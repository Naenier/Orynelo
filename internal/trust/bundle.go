// Package trust loads bounded custom certificate-authority bundles without
// retaining private key material or weakening normal certificate validation.
package trust

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const MaxBundleBytes int64 = 1 << 20

var (
	ErrBundleTooLarge  = errors.New("CA bundle exceeds the 1 MiB limit")
	ErrNotRegularFile  = errors.New("CA bundle is not a regular file")
	ErrPrivateKeyBlock = errors.New("CA bundle contains private key material")
	ErrInvalidBundle   = errors.New("CA bundle contains no valid certificates")
)

// ReadBundle reads a regular file with a hard size bound and validates that
// every PEM block is a certificate. Private-key blocks are always rejected.
func ReadBundle(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open CA bundle: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect CA bundle: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, ErrNotRegularFile
	}
	if info.Size() > MaxBundleBytes {
		return nil, ErrBundleTooLarge
	}
	content, err := io.ReadAll(io.LimitReader(file, MaxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	if int64(len(content)) > MaxBundleBytes {
		return nil, ErrBundleTooLarge
	}
	if err := ValidateBundle(content); err != nil {
		return nil, err
	}
	return content, nil
}

// ValidateBundle accepts certificate PEM only. It parses every certificate so
// malformed material cannot be mistaken for a configured trust anchor.
func ValidateBundle(content []byte) error {
	rest := content
	certificates := 0
	for len(rest) > 0 {
		block, trailing := pem.Decode(rest)
		if block == nil {
			if strings.TrimSpace(string(rest)) == "" {
				break
			}
			return ErrInvalidBundle
		}
		rest = trailing
		blockType := strings.ToUpper(strings.TrimSpace(block.Type))
		if strings.Contains(blockType, "PRIVATE KEY") {
			return ErrPrivateKeyBlock
		}
		if blockType != "CERTIFICATE" {
			return fmt.Errorf("%w: unsupported PEM block %q", ErrInvalidBundle, block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("%w: malformed certificate", ErrInvalidBundle)
		}
		certificates++
	}
	if certificates == 0 {
		return ErrInvalidBundle
	}
	return nil
}

// Pool returns the system trust store extended with the supplied certificate
// bundle. An empty bundle returns the unmodified system pool.
func Pool(content []byte) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if len(content) == 0 {
		return pool, nil
	}
	if err := ValidateBundle(content); err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(content) {
		return nil, ErrInvalidBundle
	}
	return pool, nil
}
