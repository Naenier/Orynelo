package trust

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateBundleAcceptsCertificatesAndExtendsPool(t *testing.T) {
	bundle := testCertificatePEM(t)
	if err := ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle() error = %v", err)
	}
	pool, err := Pool(bundle)
	if err != nil {
		t.Fatalf("Pool() error = %v", err)
	}
	if pool == nil {
		t.Fatal("Pool() = nil")
	}
}

func TestValidateBundleRejectsPrivateKeysWithoutEchoingContent(t *testing.T) {
	secret := "private-key-secret"
	bundle := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte(secret)})
	err := ValidateBundle(bundle)
	if !errors.Is(err, ErrPrivateKeyBlock) {
		t.Fatalf("ValidateBundle() error = %v, want private-key rejection", err)
	}
	if err != nil && contains(err.Error(), secret) {
		t.Fatalf("error exposed private-key bytes: %v", err)
	}
}

func TestReadBundleRejectsOversizedAndNonRegularInputs(t *testing.T) {
	directory := t.TempDir()
	if _, err := ReadBundle(directory); !errors.Is(err, ErrNotRegularFile) {
		t.Fatalf("ReadBundle(directory) error = %v", err)
	}
	path := filepath.Join(directory, "large.pem")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxBundleBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBundle(path); !errors.Is(err, ErrBundleTooLarge) {
		t.Fatalf("ReadBundle(large) error = %v", err)
	}
}

func testCertificatePEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Orynelo test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func contains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
