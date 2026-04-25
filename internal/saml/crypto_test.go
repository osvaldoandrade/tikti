package saml

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// writePEMKeyPair writes an RSA key and self-signed certificate as PEM files.
// The certificate's validity is controlled by notBefore/notAfter.
func writePEMKeyPair(t *testing.T, dir string, notBefore, notAfter time.Time) (keyPath, certPath string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-sp"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	keyPath = filepath.Join(dir, "sp.key")
	certPath = filepath.Join(dir, "sp.crt")

	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatalf("encode key PEM: %v", err)
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode cert PEM: %v", err)
	}

	return keyPath, certPath
}

func TestKeyHolder_LoadValid(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := writePEMKeyPair(t, dir,
		time.Now().Add(-time.Hour),
		time.Now().Add(24*time.Hour),
	)

	kh := NewKeyHolder(KeyHolderConfig{})
	if err := kh.LoadKey(keyPath, certPath); err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	if kh.Key() == nil {
		t.Fatal("Key() returned nil after successful load")
	}
	if kh.Cert() == nil {
		t.Fatal("Cert() returned nil after successful load")
	}
	if kh.Cert().Subject.CommonName != "test-sp" {
		t.Errorf("Cert().Subject.CommonName = %q, want %q", kh.Cert().Subject.CommonName, "test-sp")
	}
}

func TestKeyHolder_LoadExpired_Rejected(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := writePEMKeyPair(t, dir,
		time.Now().Add(-48*time.Hour),
		time.Now().Add(-24*time.Hour), // expired yesterday
	)

	kh := NewKeyHolder(KeyHolderConfig{})
	err := kh.LoadKey(keyPath, certPath)
	if err == nil {
		t.Fatal("LoadKey should have failed for expired certificate")
	}
	t.Logf("expected error: %v", err)

	// Ensure no key is stored.
	if kh.Key() != nil {
		t.Error("Key() should be nil after failed load")
	}
	if kh.Cert() != nil {
		t.Error("Cert() should be nil after failed load")
	}
}

func TestKeyHolder_SIGHUP_Swap(t *testing.T) {
	dir := t.TempDir()

	// Write the initial key pair.
	keyPath, certPath := writePEMKeyPair(t, dir,
		time.Now().Add(-time.Hour),
		time.Now().Add(24*time.Hour),
	)

	kh := NewKeyHolder(KeyHolderConfig{})
	if err := kh.LoadKey(keyPath, certPath); err != nil {
		t.Fatalf("initial LoadKey: %v", err)
	}

	origFingerprint := kh.Cert().SerialNumber.String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kh.Start(ctx, keyPath, certPath)

	// Write a new key pair to the same paths (different serial → different cert).
	writePEMKeyPair(t, dir,
		time.Now().Add(-time.Hour),
		time.Now().Add(48*time.Hour),
	)

	// Send SIGHUP to ourselves.
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	if err := p.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("Signal SIGHUP: %v", err)
	}

	// Wait for the reload to take effect.
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	swapped := false
	for !swapped {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for key swap after SIGHUP")
		case <-ticker.C:
			if kh.Cert().SerialNumber.String() != origFingerprint {
				swapped = true
			}
		}
	}

	// 100 concurrent readers should see a consistent (non-nil) key pair
	// and never panic under -race.
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k := kh.Key()
			c := kh.Cert()
			if k == nil || c == nil {
				t.Errorf("concurrent reader saw nil key or cert")
			}
			// Validate the key can sign something.
			digest := sha256.Sum256([]byte("test"))
			_, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
			if err != nil {
				t.Errorf("concurrent signer error: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestKeyHolder_NilBeforeLoad(t *testing.T) {
	kh := NewKeyHolder(KeyHolderConfig{})
	if kh.Key() != nil {
		t.Error("Key() should be nil before LoadKey")
	}
	if kh.Cert() != nil {
		t.Error("Cert() should be nil before LoadKey")
	}
}

func TestKeyHolder_LoadInvalidKeyPath(t *testing.T) {
	dir := t.TempDir()
	_, certPath := writePEMKeyPair(t, dir,
		time.Now().Add(-time.Hour),
		time.Now().Add(24*time.Hour),
	)

	kh := NewKeyHolder(KeyHolderConfig{})
	err := kh.LoadKey(filepath.Join(dir, "nonexistent.key"), certPath)
	if err == nil {
		t.Fatal("LoadKey should fail with non-existent key file")
	}
}

func TestKeyHolder_LoadInvalidCertPath(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writePEMKeyPair(t, dir,
		time.Now().Add(-time.Hour),
		time.Now().Add(24*time.Hour),
	)

	kh := NewKeyHolder(KeyHolderConfig{})
	err := kh.LoadKey(keyPath, filepath.Join(dir, "nonexistent.crt"))
	if err == nil {
		t.Fatal("LoadKey should fail with non-existent cert file")
	}
}
