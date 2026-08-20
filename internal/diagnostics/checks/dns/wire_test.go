package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"golang.org/x/net/dns/dnsmessage"
)

type wireAnswer struct {
	owner  string
	target string
	ttl    uint32
}

func TestWireDetailedResolverCollectsCNAMEsTTLAndNoData(t *testing.T) {
	t.Parallel()

	var nextID atomic.Uint32
	resolver := &wireDetailedResolver{
		servers:       []string{"192.0.2.53:53"},
		searchDomains: []string{"svc.example"},
		source:        "fixture resolver",
		queryID: func() (uint16, error) {
			return uint16(nextID.Add(1)), nil
		},
		exchange: func(
			_ context.Context,
			server string,
			query []byte,
			_ uint16,
		) ([]byte, error) {
			if server != "192.0.2.53:53" {
				return nil, errors.New("unexpected resolver server")
			}
			header, question, err := parseWireQuery(query)
			if err != nil {
				return nil, err
			}
			if question.Type == dnsmessage.TypeAAAA {
				return buildWireResponse(header, question, dnsmessage.RCodeSuccess, nil, false)
			}
			return buildWireResponse(header, question, dnsmessage.RCodeSuccess, []wireAnswer{
				{owner: question.Name.String(), target: "backend.example.", ttl: 90},
				{owner: "backend.example.", target: "192.0.2.10", ttl: 45},
			}, false)
		},
	}

	result, err := resolver.LookupDetails(context.Background(), "www.example")
	if err != nil {
		t.Fatal(err)
	}
	if result.ResponseCodes["ip4"] != "NOERROR" ||
		result.ResponseCodes["ip6"] != "NOERROR" ||
		strings.Join(result.CNAMEs, ",") != "backend.example" ||
		result.TTL != 45*time.Second ||
		result.ResolverSource != "fixture resolver via 192.0.2.53:53" ||
		strings.Join(result.SearchDomains, ",") != "svc.example" {
		t.Fatalf("detailed result = %#v", result)
	}
	if len(result.Families) != 1 ||
		result.Families[0].RecordType != "AAAA" ||
		result.Families[0].Status != model.DNSFamilyStatusNoData {
		t.Fatalf("family details = %#v", result.Families)
	}
}

func TestWireDetailedResolverClassifiesNXDOMAINAndSERVFAIL(t *testing.T) {
	t.Parallel()

	resolver := &wireDetailedResolver{
		servers: []string{"192.0.2.53:53"},
		source:  "fixture resolver",
		queryID: func() (uint16, error) { return 7, nil },
		exchange: func(
			_ context.Context,
			_ string,
			query []byte,
			_ uint16,
		) ([]byte, error) {
			header, question, err := parseWireQuery(query)
			if err != nil {
				return nil, err
			}
			code := dnsmessage.RCodeNameError
			if question.Type == dnsmessage.TypeAAAA {
				code = dnsmessage.RCodeServerFailure
			}
			return buildWireResponse(header, question, code, nil, false)
		},
	}

	result, err := resolver.LookupDetails(context.Background(), "missing.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Families) != 2 ||
		result.Families[0].Status != model.DNSFamilyStatusNXDOMAIN ||
		result.Families[1].Status != model.DNSFamilyStatusSERVFAIL ||
		result.ResponseCodes["ip4"] != "NXDOMAIN" ||
		result.ResponseCodes["ip6"] != "SERVFAIL" {
		t.Fatalf("detailed result = %#v", result)
	}
}

func TestWireDetailedResolverBoundsCNAMETraversalAndDetectsLoop(t *testing.T) {
	t.Parallel()

	var queries atomic.Int32
	resolver := &wireDetailedResolver{
		servers: []string{"192.0.2.53:53"},
		source:  "fixture resolver",
		queryID: func() (uint16, error) { return 9, nil },
		exchange: func(
			_ context.Context,
			_ string,
			query []byte,
			_ uint16,
		) ([]byte, error) {
			queries.Add(1)
			header, question, err := parseWireQuery(query)
			if err != nil {
				return nil, err
			}
			target := "loop-b.example."
			if canonicalDNSName(question.Name.String()) == "loop-b.example" {
				target = "loop-a.example."
			}
			return buildWireResponse(header, question, dnsmessage.RCodeSuccess, []wireAnswer{{
				owner: question.Name.String(), target: target, ttl: 30,
			}}, false)
		},
	}

	result, err := resolver.LookupDetails(context.Background(), "loop-a.example")
	if err == nil || !strings.Contains(err.Error(), "CNAME loop") {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	if got := queries.Load(); got != 4 {
		t.Fatalf("wire queries = %d, want two bounded queries per family", got)
	}
}

func TestParseWireResponseRejectsAnswersBeyondBound(t *testing.T) {
	t.Parallel()

	query, err := buildDNSQuery(10, "bounded.example.", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	header, question, err := parseWireQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	answers := make([]wireAnswer, maximumDNSAnswers+1)
	for index := range answers {
		answers[index] = wireAnswer{
			owner: question.Name.String(), target: "192.0.2.10", ttl: 60,
		}
	}
	response, err := buildWireResponse(
		header,
		question,
		dnsmessage.RCodeSuccess,
		answers,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = parseWireResponse(response, question.Name.String(), question.Type)
	if err == nil || !strings.Contains(err.Error(), "too many answers") {
		t.Fatalf("parse error = %v", err)
	}
}

func TestExchangeDNSWireFallsBackToTCPOnlyWhenUDPIsTruncated(t *testing.T) {
	t.Parallel()

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()

	udpDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 512)
		count, client, readErr := udp.ReadFromUDP(buffer)
		if readErr != nil {
			udpDone <- readErr
			return
		}
		header, question, parseErr := parseWireQuery(buffer[:count])
		if parseErr != nil {
			udpDone <- parseErr
			return
		}
		response, buildErr := buildWireResponse(
			header,
			question,
			dnsmessage.RCodeSuccess,
			nil,
			true,
		)
		if buildErr == nil {
			_, buildErr = udp.WriteToUDP(response, client)
		}
		udpDone <- buildErr
	}()

	tcpDone := make(chan error, 1)
	go func() {
		connection, acceptErr := tcp.Accept()
		if acceptErr != nil {
			tcpDone <- acceptErr
			return
		}
		defer connection.Close()
		var size [2]byte
		if _, acceptErr = io.ReadFull(connection, size[:]); acceptErr != nil {
			tcpDone <- acceptErr
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, acceptErr = io.ReadFull(connection, query); acceptErr != nil {
			tcpDone <- acceptErr
			return
		}
		header, question, parseErr := parseWireQuery(query)
		if parseErr != nil {
			tcpDone <- parseErr
			return
		}
		response, buildErr := buildWireResponse(
			header,
			question,
			dnsmessage.RCodeSuccess,
			[]wireAnswer{{owner: question.Name.String(), target: "192.0.2.44", ttl: 60}},
			false,
		)
		if buildErr != nil {
			tcpDone <- buildErr
			return
		}
		framed := make([]byte, 2+len(response))
		binary.BigEndian.PutUint16(framed[:2], uint16(len(response)))
		copy(framed[2:], response)
		tcpDone <- writeAll(connection, framed)
	}()

	query, err := buildDNSQuery(42, "www.example.", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := exchangeDNSWire(ctx, udp.LocalAddr().String(), query, 42)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseWireResponse(response, "www.example.", dnsmessage.TypeA)
	if err != nil || !parsed.hasAddress || parsed.ttlSeconds != 60 {
		t.Fatalf("parsed response=%#v error=%v", parsed, err)
	}
	if err := <-udpDone; err != nil {
		t.Fatalf("UDP fixture: %v", err)
	}
	if err := <-tcpDone; err != nil {
		t.Fatalf("TCP fixture: %v", err)
	}
}

func TestExchangeDNSWireIsCancelledWhileWaitingForUDP(t *testing.T) {
	t.Parallel()

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	queryReceived := make(chan struct{})
	go func() {
		buffer := make([]byte, 512)
		if _, _, readErr := udp.ReadFromUDP(buffer); readErr == nil {
			close(queryReceived)
		}
	}()

	query, err := buildDNSQuery(43, "www.example.", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = exchangeDNSWire(ctx, udp.LocalAddr().String(), query, 43)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("exchange error = %v", err)
	}
	select {
	case <-queryReceived:
	case <-time.After(time.Second):
		t.Fatal("UDP fixture did not receive the query")
	}
}

func parseWireQuery(query []byte) (dnsmessage.Header, dnsmessage.Question, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return dnsmessage.Header{}, dnsmessage.Question{}, err
	}
	question, err := parser.Question()
	return header, question, err
}

func buildWireResponse(
	queryHeader dnsmessage.Header,
	question dnsmessage.Question,
	code dnsmessage.RCode,
	answers []wireAnswer,
	truncated bool,
) ([]byte, error) {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 queryHeader.ID,
		Response:           true,
		Truncated:          truncated,
		RecursionDesired:   queryHeader.RecursionDesired,
		RecursionAvailable: true,
		RCode:              code,
	})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	for _, answer := range answers {
		owner, err := dnsmessage.NewName(answer.owner)
		if err != nil {
			return nil, err
		}
		header := dnsmessage.ResourceHeader{
			Name: owner, Class: dnsmessage.ClassINET, TTL: answer.ttl,
		}
		if address := net.ParseIP(answer.target); address != nil {
			if question.Type == dnsmessage.TypeA {
				var value [4]byte
				copy(value[:], address.To4())
				if err := builder.AResource(header, dnsmessage.AResource{A: value}); err != nil {
					return nil, err
				}
			} else {
				var value [16]byte
				copy(value[:], address.To16())
				if err := builder.AAAAResource(header, dnsmessage.AAAAResource{AAAA: value}); err != nil {
					return nil, err
				}
			}
			continue
		}
		target, err := dnsmessage.NewName(answer.target)
		if err != nil {
			return nil, err
		}
		if err := builder.CNAMEResource(header, dnsmessage.CNAMEResource{CNAME: target}); err != nil {
			return nil, err
		}
	}
	return builder.Finish()
}
