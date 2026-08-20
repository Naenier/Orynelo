package dns

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	maximumDNSMessageBytes = 65535
	maximumDNSQuestions    = 4
	maximumDNSAnswers      = 64
	maximumDNSAuthorities  = 32
	maximumCNAMEHops       = 8
	detailedLookupTimeout  = 2 * time.Second
)

type dnsWireExchange func(
	context.Context,
	string,
	[]byte,
	uint16,
) ([]byte, error)

type wireDetailedResolver struct {
	servers       []string
	searchDomains []string
	source        string
	exchange      dnsWireExchange
	queryID       func() (uint16, error)
}

type wireFamilyResult struct {
	recordType string
	status     model.DNSFamilyStatus
	rcode      string
	cnames     []string
	ttl        time.Duration
	server     string
	err        error
}

type cnameLink struct {
	owner  string
	target string
}

type parsedWireResponse struct {
	rcode       dnsmessage.RCode
	hasAddress  bool
	cnames      []string
	cnameLinks  []cnameLink
	ttlSeconds  uint32
	ttlObserved bool
}

func newSystemWireDetailedResolver() (*wireDetailedResolver, error) {
	configuration, err := readResolverConfiguration(resolverConfigurationPath)
	if err != nil || len(configuration.servers) == 0 {
		if err == nil {
			err = errors.New("resolver configuration has no IP nameserver")
		}
		return nil, err
	}
	servers := make([]string, 0, len(configuration.servers))
	for _, server := range configuration.servers {
		servers = append(servers, net.JoinHostPort(server, "53"))
	}
	return &wireDetailedResolver{
		servers:       servers,
		searchDomains: append([]string(nil), configuration.searchDomains...),
		source:        "DNS wire resolver configured by " + resolverConfigurationPath,
		exchange:      exchangeDNSWire,
		queryID:       secureDNSQueryID,
	}, nil
}

func (resolver *wireDetailedResolver) LookupDetails(
	ctx context.Context,
	host string,
) (DetailedResult, error) {
	if resolver == nil || len(resolver.servers) == 0 {
		return DetailedResult{}, errors.New("DNS wire resolver has no configured server")
	}
	host, err := absoluteDNSName(host)
	if err != nil {
		return DetailedResult{}, err
	}
	lookupContext, cancel := context.WithTimeout(ctx, detailedLookupTimeout)
	defer cancel()

	type familyQuery struct {
		recordType string
		queryType  dnsmessage.Type
	}
	queries := []familyQuery{
		{recordType: "A", queryType: dnsmessage.TypeA},
		{recordType: "AAAA", queryType: dnsmessage.TypeAAAA},
	}
	results := make(chan wireFamilyResult, len(queries))
	for _, query := range queries {
		query := query
		go func() {
			results <- resolver.lookupFamily(
				lookupContext,
				host,
				query.recordType,
				query.queryType,
			)
		}()
	}

	result := DetailedResult{
		ResponseCodes:  make(map[string]string, len(queries)),
		ResolverSource: resolver.source,
		SearchDomains:  append([]string(nil), resolver.searchDomains...),
	}
	var failures []error
	var usedServers []string
	byRecordType := make(map[string]wireFamilyResult, len(queries))
	for range queries {
		family := <-results
		byRecordType[family.recordType] = family
	}
	for _, query := range queries {
		family := byRecordType[query.recordType]
		key := familyKey(family.recordType)
		if family.rcode != "" {
			result.ResponseCodes[key] = family.rcode
		}
		result.CNAMEs = append(result.CNAMEs, family.cnames...)
		result.TTL = minimumPositiveDuration(result.TTL, family.ttl)
		if family.server != "" {
			usedServers = append(usedServers, family.server)
		}
		if family.err != nil {
			failures = append(failures, fmt.Errorf("%s detail query failed: %w", family.recordType, family.err))
			continue
		}
		// Connection candidates remain authoritative from the platform
		// Resolver. Wire success is therefore metadata-only, while structured
		// negative responses may refine an otherwise ambiguous platform error.
		if family.status != model.DNSFamilyStatusSuccess {
			result.Families = append(result.Families, model.DNSFamilyResult{
				Family:     displayFamily(key),
				RecordType: family.recordType,
				Status:     family.status,
				ErrorCode:  errorCodeForFamilyStatus(family.status),
			})
		}
	}
	result.CNAMEs = normalizeCNAMEs(result.CNAMEs, 16)
	usedServers = uniqueStrings(usedServers, maximumResolverServers)
	if len(usedServers) > 0 {
		result.ResolverSource += " via " + strings.Join(usedServers, ", ")
	}
	return result, errors.Join(failures...)
}

func (resolver *wireDetailedResolver) lookupFamily(
	ctx context.Context,
	host string,
	recordType string,
	queryType dnsmessage.Type,
) wireFamilyResult {
	result := wireFamilyResult{recordType: recordType}
	current := host
	seen := make(map[string]struct{}, maximumCNAMEHops)
	for range maximumCNAMEHops {
		key := canonicalDNSName(current)
		if _, duplicate := seen[key]; duplicate {
			result.status = model.DNSFamilyStatusError
			result.err = errors.New("DNS CNAME loop detected")
			return result
		}
		seen[key] = struct{}{}

		response, server, err := resolver.query(ctx, current, queryType)
		if err != nil {
			result.err = err
			return result
		}
		result.server = server
		parsed, err := parseWireResponse(response, current, queryType)
		if err != nil {
			result.err = err
			return result
		}
		result.rcode = responseCodeName(parsed.rcode)
		result.cnames = append(result.cnames, parsed.cnames...)
		if parsed.ttlObserved {
			result.ttl = minimumPositiveDuration(
				result.ttl,
				time.Duration(parsed.ttlSeconds)*time.Second,
			)
		}
		switch parsed.rcode {
		case dnsmessage.RCodeNameError:
			result.status = model.DNSFamilyStatusNXDOMAIN
			return result
		case dnsmessage.RCodeServerFailure:
			result.status = model.DNSFamilyStatusSERVFAIL
			return result
		case dnsmessage.RCodeSuccess:
			if parsed.hasAddress {
				result.status = model.DNSFamilyStatusSuccess
				return result
			}
			next, followed, chainErr := followCNAMEChain(current, parsed.cnameLinks)
			if chainErr != nil {
				result.status = model.DNSFamilyStatusError
				result.err = chainErr
				return result
			}
			if followed {
				current = next
				continue
			}
			result.status = model.DNSFamilyStatusNoData
			return result
		default:
			result.status = model.DNSFamilyStatusError
			return result
		}
	}
	result.status = model.DNSFamilyStatusError
	result.err = fmt.Errorf("DNS CNAME chain exceeded %d hops", maximumCNAMEHops)
	return result
}

func (resolver *wireDetailedResolver) query(
	ctx context.Context,
	host string,
	queryType dnsmessage.Type,
) ([]byte, string, error) {
	queryID := resolver.queryID
	if queryID == nil {
		queryID = secureDNSQueryID
	}
	id, err := queryID()
	if err != nil {
		return nil, "", err
	}
	query, err := buildDNSQuery(id, host, queryType)
	if err != nil {
		return nil, "", err
	}
	exchange := resolver.exchange
	if exchange == nil {
		exchange = exchangeDNSWire
	}
	var failures []error
	for _, server := range resolver.servers {
		response, exchangeErr := exchange(ctx, server, query, id)
		if exchangeErr == nil {
			return response, server, nil
		}
		failures = append(failures, exchangeErr)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, "", errors.Join(failures...)
}

func buildDNSQuery(id uint16, host string, queryType dnsmessage.Type) ([]byte, error) {
	name, err := dnsmessage.NewName(host)
	if err != nil {
		return nil, err
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               id,
		RecursionDesired: true,
	})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{
		Name: name, Type: queryType, Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

func parseWireResponse(
	message []byte,
	expectedName string,
	expectedType dnsmessage.Type,
) (parsedWireResponse, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(message)
	if err != nil {
		return parsedWireResponse{}, err
	}
	if !header.Response || header.Truncated {
		return parsedWireResponse{}, errors.New("DNS response is incomplete")
	}
	result := parsedWireResponse{rcode: header.RCode}
	questionCount := 0
	for {
		question, questionErr := parser.Question()
		if errors.Is(questionErr, dnsmessage.ErrSectionDone) {
			break
		}
		if questionErr != nil {
			return parsedWireResponse{}, questionErr
		}
		questionCount++
		if questionCount > maximumDNSQuestions {
			return parsedWireResponse{}, errors.New("DNS response has too many questions")
		}
		if questionCount == 1 &&
			(canonicalDNSName(question.Name.String()) != canonicalDNSName(expectedName) ||
				question.Type != expectedType || question.Class != dnsmessage.ClassINET) {
			return parsedWireResponse{}, errors.New("DNS response question does not match the query")
		}
	}
	if questionCount != 1 {
		return parsedWireResponse{}, errors.New("DNS response did not echo exactly one question")
	}

	answerCount := 0
	for {
		resourceHeader, answerErr := parser.AnswerHeader()
		if errors.Is(answerErr, dnsmessage.ErrSectionDone) {
			break
		}
		if answerErr != nil {
			return parsedWireResponse{}, answerErr
		}
		answerCount++
		if answerCount > maximumDNSAnswers {
			return parsedWireResponse{}, errors.New("DNS response has too many answers")
		}
		switch resourceHeader.Type {
		case dnsmessage.TypeCNAME:
			resource, resourceErr := parser.CNAMEResource()
			if resourceErr != nil {
				return parsedWireResponse{}, resourceErr
			}
			owner := canonicalDNSName(resourceHeader.Name.String())
			target := canonicalDNSName(resource.CNAME.String())
			if owner != "" && target != "" {
				result.cnames = append(result.cnames, target)
				result.cnameLinks = append(result.cnameLinks, cnameLink{owner: owner, target: target})
			}
			result.observeTTL(resourceHeader.TTL)
		case dnsmessage.TypeA:
			if _, resourceErr := parser.AResource(); resourceErr != nil {
				return parsedWireResponse{}, resourceErr
			}
			if expectedType == dnsmessage.TypeA {
				result.hasAddress = true
				result.observeTTL(resourceHeader.TTL)
			}
		case dnsmessage.TypeAAAA:
			if _, resourceErr := parser.AAAAResource(); resourceErr != nil {
				return parsedWireResponse{}, resourceErr
			}
			if expectedType == dnsmessage.TypeAAAA {
				result.hasAddress = true
				result.observeTTL(resourceHeader.TTL)
			}
		default:
			if skipErr := parser.SkipAnswer(); skipErr != nil {
				return parsedWireResponse{}, skipErr
			}
		}
	}

	authorityCount := 0
	for {
		resourceHeader, authorityErr := parser.AuthorityHeader()
		if errors.Is(authorityErr, dnsmessage.ErrSectionDone) {
			break
		}
		if authorityErr != nil {
			return parsedWireResponse{}, authorityErr
		}
		authorityCount++
		if authorityCount > maximumDNSAuthorities {
			return parsedWireResponse{}, errors.New("DNS response has too many authority records")
		}
		if resourceHeader.Type != dnsmessage.TypeSOA {
			if skipErr := parser.SkipAuthority(); skipErr != nil {
				return parsedWireResponse{}, skipErr
			}
			continue
		}
		resource, resourceErr := parser.SOAResource()
		if resourceErr != nil {
			return parsedWireResponse{}, resourceErr
		}
		negativeTTL := resourceHeader.TTL
		if resource.MinTTL < negativeTTL {
			negativeTTL = resource.MinTTL
		}
		result.observeTTL(negativeTTL)
	}
	return result, nil
}

func (result *parsedWireResponse) observeTTL(value uint32) {
	if !result.ttlObserved || value < result.ttlSeconds {
		result.ttlSeconds = value
		result.ttlObserved = true
	}
}

func followCNAMEChain(current string, links []cnameLink) (string, bool, error) {
	current = canonicalDNSName(current)
	seen := make(map[string]struct{}, len(links)+1)
	seen[current] = struct{}{}
	followed := false
	for range maximumCNAMEHops {
		next := ""
		for _, link := range links {
			if link.owner == current {
				next = link.target
				break
			}
		}
		if next == "" {
			return current + ".", followed, nil
		}
		if _, duplicate := seen[next]; duplicate {
			return "", false, errors.New("DNS CNAME loop detected")
		}
		seen[next] = struct{}{}
		current = next
		followed = true
	}
	return "", false, fmt.Errorf("DNS CNAME chain exceeded %d hops", maximumCNAMEHops)
}

func exchangeDNSWire(
	ctx context.Context,
	server string,
	query []byte,
	id uint16,
) ([]byte, error) {
	response, err := exchangeDNSUDP(ctx, server, query)
	if err != nil {
		return nil, err
	}
	header, err := validateDNSResponseHeader(response, id)
	if err != nil {
		return nil, err
	}
	if !header.Truncated {
		return response, nil
	}
	response, err = exchangeDNSTCP(ctx, server, query)
	if err != nil {
		return nil, err
	}
	header, err = validateDNSResponseHeader(response, id)
	if err != nil {
		return nil, err
	}
	if header.Truncated {
		return nil, errors.New("DNS TCP response is truncated")
	}
	return response, nil
}

func exchangeDNSUDP(ctx context.Context, server string, query []byte) ([]byte, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "udp", server)
	if err != nil {
		return nil, contextualDNSError(ctx, err)
	}
	defer connection.Close()
	stop := interruptConnectionOnCancellation(ctx, connection)
	defer stop()
	if _, err = connection.Write(query); err != nil {
		return nil, contextualDNSError(ctx, err)
	}
	buffer := make([]byte, maximumDNSMessageBytes)
	count, err := connection.Read(buffer)
	if err != nil {
		return nil, contextualDNSError(ctx, err)
	}
	return append([]byte(nil), buffer[:count]...), nil
}

func exchangeDNSTCP(ctx context.Context, server string, query []byte) ([]byte, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, contextualDNSError(ctx, err)
	}
	defer connection.Close()
	stop := interruptConnectionOnCancellation(ctx, connection)
	defer stop()
	if len(query) > maximumDNSMessageBytes {
		return nil, errors.New("DNS TCP query length exceeds the wire-format bound")
	}
	framed := make([]byte, 2+len(query))
	// The explicit upper bound above proves that the DNS two-byte length field
	// can represent the query without truncation.
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query))) //nolint:gosec // guarded conversion
	copy(framed[2:], query)
	if err = writeAll(connection, framed); err != nil {
		return nil, contextualDNSError(ctx, err)
	}
	var lengthBytes [2]byte
	if _, err = io.ReadFull(connection, lengthBytes[:]); err != nil {
		return nil, contextualDNSError(ctx, err)
	}
	length := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if length < 12 || length > maximumDNSMessageBytes {
		return nil, errors.New("DNS TCP response length is invalid")
	}
	response := make([]byte, length)
	if _, err = io.ReadFull(connection, response); err != nil {
		return nil, contextualDNSError(ctx, err)
	}
	return response, nil
}

func interruptConnectionOnCancellation(
	ctx context.Context,
	connection net.Conn,
) func() bool {
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	return context.AfterFunc(ctx, func() { _ = connection.Close() })
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func validateDNSResponseHeader(message []byte, id uint16) (dnsmessage.Header, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(message)
	if err != nil {
		return dnsmessage.Header{}, err
	}
	if !header.Response || header.ID != id {
		return dnsmessage.Header{}, errors.New("DNS response identity does not match the query")
	}
	return header, nil
}

func secureDNSQueryID() (uint16, error) {
	var value [2]byte
	if _, err := cryptorand.Read(value[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(value[:]), nil
}

func absoluteDNSName(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" || containsControl(host) {
		return "", errors.New("DNS detail hostname is invalid")
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return "", errors.New("DNS detail hostname is invalid")
	}
	result := host + "."
	if _, err := dnsmessage.NewName(result); err != nil {
		return "", errors.New("DNS detail hostname is invalid")
	}
	return result, nil
}

func canonicalDNSName(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func contextualDNSError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
	}
	return err
}

func responseCodeName(code dnsmessage.RCode) string {
	switch code {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE_%d", code)
	}
}

func minimumPositiveDuration(current, candidate time.Duration) time.Duration {
	if candidate <= 0 {
		return current
	}
	if current <= 0 || candidate < current {
		return candidate
	}
	return current
}

func uniqueStrings(values []string, limit int) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
		if limit > 0 && len(result) == limit {
			break
		}
	}
	return result
}
