package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/internal/saml"
)

// testSAMLKeyPair generates a self-signed RSA 2048 key pair for tests.
func testSAMLKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-sp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return key, cert
}

func TestBuildTestAuthnURL_Success(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	// Register an IdP for the tenant.
	idp := saml.IdPRecord{
		TenantID:     "t-test",
		EntityID:     "https://idp.example.com",
		SSOURL:       "https://idp.example.com/sso",
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
	}
	if err := store.PutIdP(ctx, idp); err != nil {
		t.Fatalf("PutIdP: %v", err)
	}

	key, cert := testSAMLKeyPair(t)
	provider := &saml.CrewjamProvider{
		EntityID: "https://auth.example.com/saml",
		ACSURL:   "https://auth.example.com/saml/acs",
		Key:      key,
		Cert:     cert,
	}

	opts := samlTestOptions{
		TID:    "t-test",
		Email:  "user@example.com",
		ACSURL: "https://auth.example.com/saml/acs",
	}

	authn, err := buildTestAuthnURL(ctx, store, provider, opts)
	if err != nil {
		t.Fatalf("buildTestAuthnURL: %v", err)
	}

	if authn.ID == "" {
		t.Error("AuthnRequest ID is empty")
	}
	if authn.RedirectURL == "" {
		t.Fatal("RedirectURL is empty")
	}

	// Verify the URL points to the IdP SSO endpoint.
	u, err := url.Parse(authn.RedirectURL)
	if err != nil {
		t.Fatalf("parse redirect URL: %v", err)
	}
	if u.Host != "idp.example.com" {
		t.Errorf("URL host = %q, want %q", u.Host, "idp.example.com")
	}
	if u.Path != "/sso" {
		t.Errorf("URL path = %q, want %q", u.Path, "/sso")
	}

	// Verify RelayState is /debug/ok.
	if got := u.Query().Get("RelayState"); got != "/debug/ok" {
		t.Errorf("RelayState = %q, want %q", got, "/debug/ok")
	}

	// Verify SAMLRequest is present.
	if u.Query().Get("SAMLRequest") == "" {
		t.Error("SAMLRequest query parameter is missing")
	}
}

func TestBuildTestAuthnURL_MissingTID(t *testing.T) {
	store := newMemStore()
	key, cert := testSAMLKeyPair(t)
	provider := &saml.CrewjamProvider{
		EntityID: "https://auth.example.com/saml",
		ACSURL:   "https://auth.example.com/saml/acs",
		Key:      key,
		Cert:     cert,
	}

	_, err := buildTestAuthnURL(context.Background(), store, provider, samlTestOptions{
		Email:  "user@example.com",
		ACSURL: "https://auth.example.com/saml/acs",
	})
	if err == nil {
		t.Fatal("expected error for missing TID")
	}
	if !strings.Contains(err.Error(), "--tid") {
		t.Errorf("error = %q, want mention of --tid", err.Error())
	}
}

func TestBuildTestAuthnURL_MissingEmail(t *testing.T) {
	store := newMemStore()
	key, cert := testSAMLKeyPair(t)
	provider := &saml.CrewjamProvider{
		EntityID: "https://auth.example.com/saml",
		ACSURL:   "https://auth.example.com/saml/acs",
		Key:      key,
		Cert:     cert,
	}

	_, err := buildTestAuthnURL(context.Background(), store, provider, samlTestOptions{
		TID:    "t-test",
		ACSURL: "https://auth.example.com/saml/acs",
	})
	if err == nil {
		t.Fatal("expected error for missing email")
	}
	if !strings.Contains(err.Error(), "--email") {
		t.Errorf("error = %q, want mention of --email", err.Error())
	}
}

func TestBuildTestAuthnURL_IdPNotFound(t *testing.T) {
	store := newMemStore()
	key, cert := testSAMLKeyPair(t)
	provider := &saml.CrewjamProvider{
		EntityID: "https://auth.example.com/saml",
		ACSURL:   "https://auth.example.com/saml/acs",
		Key:      key,
		Cert:     cert,
	}

	_, err := buildTestAuthnURL(context.Background(), store, provider, samlTestOptions{
		TID:    "nonexistent",
		Email:  "user@example.com",
		ACSURL: "https://auth.example.com/saml/acs",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent IdP")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error = %q, want mention of tenant ID", err.Error())
	}
}
