package saml

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/beevik/etree"
	"github.com/fsnotify/fsnotify"
)

// parseXML is the centralized XML parser for all SAML payloads.
// It rejects XXE attack vectors (DOCTYPE, ENTITY declarations) before
// parsing and disables entity expansion in the etree reader.
func parseXML(raw []byte) (*etree.Document, error) {
	if containsXXE(raw) {
		return nil, fmt.Errorf("%w", ErrXXE)
	}

	doc := etree.NewDocument()
	doc.ReadSettings = etree.ReadSettings{
		// Do not map any custom entities — prevents expansion.
		Entity: nil,
		// Strict mode: reject malformed XML.
		Permissive: false,
		// Validate that the input is well-formed XML.
		ValidateInput: true,
	}

	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, fmt.Errorf("saml: xml parse: %w", err)
	}
	return doc, nil
}

// containsXXE scans raw XML bytes for DOCTYPE or ENTITY declarations
// (case-insensitive) that signal an XXE attack attempt.
func containsXXE(raw []byte) bool {
	lower := bytes.ToLower(raw)
	return bytes.Contains(lower, []byte("<!doctype")) ||
		bytes.Contains(lower, []byte("<!entity"))
}

// gracePeriod is the duration the old key pair is kept alive after a swap,
// allowing in-flight signers that grabbed the old pointer to finish.
const gracePeriod = 10 * time.Second

// keyPair bundles a parsed RSA private key and its X.509 certificate.
type keyPair struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

// KeyHolderConfig carries optional settings for the KeyHolder.
type KeyHolderConfig struct {
	WatchFile bool
}

// KeyHolder holds the current SP key pair behind an atomic pointer so that
// concurrent readers never block and key rotation is lock-free.
type KeyHolder struct {
	pair atomic.Pointer[keyPair]
	cfg  KeyHolderConfig
}

// NewKeyHolder returns a KeyHolder ready for use. Call LoadKey to populate
// the initial key pair, then Start to enable SIGHUP-based hot reload.
func NewKeyHolder(cfg KeyHolderConfig) *KeyHolder {
	return &KeyHolder{cfg: cfg}
}

// LoadKey reads a PEM-encoded RSA private key and X.509 certificate from
// disk, validates the certificate is not expired, and atomically stores the
// pair. It returns an error if the files cannot be read, parsed, or if the
// certificate has expired.
func (kh *KeyHolder) LoadKey(keyPath, certPath string) error {
	kp, err := loadKeyPair(keyPath, certPath)
	if err != nil {
		return err
	}
	kh.pair.Store(kp)
	return nil
}

// Key returns the current RSA private key or nil if none is loaded.
func (kh *KeyHolder) Key() *rsa.PrivateKey {
	p := kh.pair.Load()
	if p == nil {
		return nil
	}
	return p.key
}

// Cert returns the current X.509 certificate or nil if none is loaded.
func (kh *KeyHolder) Cert() *x509.Certificate {
	p := kh.pair.Load()
	if p == nil {
		return nil
	}
	return p.cert
}

// Start installs a SIGHUP handler that reloads the key pair from disk.
// If cfg.WatchFile is true an fsnotify watcher is also started. The
// goroutines exit when ctx is cancelled.
func (kh *KeyHolder) Start(ctx context.Context, keyPath, certPath string) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	go func() {
		defer signal.Stop(sig)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				kh.reload(keyPath, certPath)
			}
		}
	}()

	if kh.cfg.WatchFile {
		go kh.watch(ctx, keyPath, certPath)
	}
}

// reload performs the atomic swap of the key pair, keeping the old pointer
// alive for a 10-second grace period so in-flight signers can finish.
func (kh *KeyHolder) reload(keyPath, certPath string) {
	kp, err := loadKeyPair(keyPath, certPath)
	if err != nil {
		log.Printf("saml: key reload failed: %v", err)
		return
	}
	old := kh.pair.Swap(kp)
	log.Printf("saml: key pair reloaded from %s / %s", keyPath, certPath)

	// Keep old pointer reachable for 10 s so in-flight operations that
	// grabbed it before the swap can complete.
	if old != nil {
		go func(prev *keyPair) {
			time.Sleep(gracePeriod)
			runtime.KeepAlive(prev)
		}(old)
	}
}

// watch uses fsnotify to reload the key pair when the key or cert files
// change on disk.
func (kh *KeyHolder) watch(ctx context.Context, keyPath, certPath string) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("saml: fsnotify watcher failed: %v", err)
		return
	}
	defer w.Close()

	if err := w.Add(keyPath); err != nil {
		log.Printf("saml: watch %s: %v", keyPath, err)
		return
	}
	if err := w.Add(certPath); err != nil {
		log.Printf("saml: watch %s: %v", certPath, err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				kh.reload(keyPath, certPath)
			}
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			log.Printf("saml: fsnotify error: %v", err)
		}
	}
}

// loadKeyPair reads PEM files from disk and returns a validated keyPair.
func loadKeyPair(keyPath, certPath string) (*keyPair, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("saml: read key %s: %w", keyPath, err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("saml: read cert %s: %w", certPath, err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("saml: no PEM block in %s", keyPath)
	}

	privKey, err := parseRSAPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("saml: parse key %s: %w", keyPath, err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("saml: no CERTIFICATE PEM block in %s", certPath)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("saml: parse cert %s: %w", certPath, err)
	}

	now := time.Now()
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("saml: certificate %s expired at %s", certPath, cert.NotAfter)
	}
	if now.Before(cert.NotBefore) {
		return nil, fmt.Errorf("saml: certificate %s not yet valid until %s", certPath, cert.NotBefore)
	}

	return &keyPair{key: privKey, cert: cert}, nil
}

// parseRSAPrivateKey tries PKCS#8 first, then PKCS#1.
func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("PKCS#8 key is not RSA")
	}
	return x509.ParsePKCS1PrivateKey(der)
}
