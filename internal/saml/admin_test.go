package saml

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
)

func newAdminTestStore(t *testing.T) Store {
	t.Helper()
	server := miniredis.RunT(t)
	return NewRedisStore(redis.NewClient(&redis.Options{Addr: server.Addr()}))
}

func TestAdminServicePutGetDeleteInlineMetadata(t *testing.T) {
	store := newAdminTestStore(t)
	raw, err := os.ReadFile("testdata/idp_okta.xml")
	if err != nil {
		t.Fatal(err)
	}
	service := NewAdminService(store, MetadataHTTPFetcher{}, "https://code-foundry.example", nil)

	saved, err := service.Put(context.Background(), "local-tenant", PutIdPConfiguration{
		MetadataXML: string(raw),
		AttributeMap: map[string][]string{
			"email": {"mail"},
			"name":  {},
			"roles": {},
		},
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !saved.Configured || saved.SigningCertificateCount < 1 || saved.LoginURL != "https://code-foundry.example/saml/login/local-tenant" {
		t.Fatalf("unexpected projection: %#v", saved)
	}
	if saved.MetadataURL != "" {
		t.Fatalf("inline XML must not be returned, got metadata URL %q", saved.MetadataURL)
	}

	loaded, err := service.Get(context.Background(), "local-tenant")
	if err != nil || !loaded.Configured || loaded.EntityID != saved.EntityID {
		t.Fatalf("Get: %#v, %v", loaded, err)
	}
	if err := service.Delete(context.Background(), "local-tenant"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	loaded, err = service.Get(context.Background(), "local-tenant")
	if err != nil || loaded.Configured {
		t.Fatalf("expected unconfigured projection, got %#v, %v", loaded, err)
	}
}

func TestAdminServiceRejectsInvalidInputWithoutReplacingExistingTrust(t *testing.T) {
	store := newAdminTestStore(t)
	existing := IdPRecord{TenantID: "local-tenant", EntityID: "https://existing.example", SSOURL: "https://existing.example/sso"}
	if err := store.PutIdP(context.Background(), existing); err != nil {
		t.Fatal(err)
	}
	service := NewAdminService(store, MetadataHTTPFetcher{}, "https://code-foundry.example", nil)

	_, err := service.Put(context.Background(), "local-tenant", PutIdPConfiguration{
		MetadataXML:  "<not-metadata/>",
		AttributeMap: DefaultAttributeMap(),
	})
	if !errors.Is(err, ErrAdminInvalidInput) {
		t.Fatalf("expected invalid input, got %v", err)
	}
	loaded, err := store.GetIdP(context.Background(), "local-tenant")
	if err != nil || loaded.EntityID != existing.EntityID {
		t.Fatalf("existing trust was changed: %#v, %v", loaded, err)
	}
}

func TestMetadataHTTPFetcherRejectsSSRFAndInsecureURLs(t *testing.T) {
	fetcher := MetadataHTTPFetcher{}
	for _, rawURL := range []string{
		"http://idp.example.com/metadata",
		"https://127.0.0.1/metadata",
		"https://[::1]/metadata",
		"https://user:password@idp.example.com/metadata",
	} {
		if _, err := fetcher.Fetch(context.Background(), rawURL); err == nil {
			t.Fatalf("expected %q to be rejected", rawURL)
		}
	}
}
