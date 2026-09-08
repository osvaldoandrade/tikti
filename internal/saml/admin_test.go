package saml

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
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
	firstRecord, err := store.GetIdP(context.Background(), "local-tenant")
	if err != nil || firstRecord.Generation == "" {
		t.Fatalf("first trust generation was not persisted: generation=%q err=%v", firstRecord.Generation, err)
	}
	if _, err = service.Put(context.Background(), "local-tenant", PutIdPConfiguration{
		MetadataXML:  string(raw),
		AttributeMap: map[string][]string{"email": {"mail"}},
	}); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	secondRecord, err := store.GetIdP(context.Background(), "local-tenant")
	if err != nil || secondRecord.Generation == "" || secondRecord.Generation == firstRecord.Generation {
		t.Fatalf("trust generation did not rotate: first=%q second=%q err=%v", firstRecord.Generation, secondRecord.Generation, err)
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

func TestAdminServiceKeepsTwoTenantConfigurationsIsolated(t *testing.T) {
	store := newAdminTestStore(t)
	raw, err := os.ReadFile("testdata/idp_okta.xml")
	if err != nil {
		t.Fatal(err)
	}
	service := NewAdminService(store, MetadataHTTPFetcher{}, "https://code-foundry.example", nil)
	put := func(tenantID, entityID, emailAttribute string) IdPConfiguration {
		t.Helper()
		metadata := strings.ReplaceAll(string(raw), "http://www.okta.com/exk123abc", entityID)
		configuration, putErr := service.Put(context.Background(), tenantID, PutIdPConfiguration{
			MetadataXML:  metadata,
			AttributeMap: map[string][]string{"email": {emailAttribute}},
		})
		if putErr != nil {
			t.Fatalf("Put %s: %v", tenantID, putErr)
		}
		return configuration
	}

	master := put("local-tenant", "https://master-idp.example.com/entity", "master-mail")
	bereia := put("bereia", "https://bereia-idp.example.com/entity", "bereia-mail")
	if master.EntityID == bereia.EntityID ||
		master.LoginURL != "https://code-foundry.example/saml/login/local-tenant" ||
		bereia.LoginURL != "https://code-foundry.example/saml/login/bereia" {
		t.Fatalf("tenant-specific save projections crossed: MASTER=%#v Bereia=%#v", master, bereia)
	}

	loadedMaster, err := service.Get(context.Background(), "local-tenant")
	if err != nil || loadedMaster.EntityID != master.EntityID || loadedMaster.AttributeMap["email"][0] != "master-mail" {
		t.Fatalf("Get MASTER: %#v, %v", loadedMaster, err)
	}
	loadedBereia, err := service.Get(context.Background(), "bereia")
	if err != nil || loadedBereia.EntityID != bereia.EntityID || loadedBereia.AttributeMap["email"][0] != "bereia-mail" {
		t.Fatalf("Get Bereia: %#v, %v", loadedBereia, err)
	}

	if err := service.Delete(context.Background(), "local-tenant"); err != nil {
		t.Fatalf("Delete MASTER: %v", err)
	}
	loadedMaster, err = service.Get(context.Background(), "local-tenant")
	if err != nil || loadedMaster.Configured {
		t.Fatalf("deleted MASTER remains configured: %#v, %v", loadedMaster, err)
	}
	loadedBereia, err = service.Get(context.Background(), "bereia")
	if err != nil || !loadedBereia.Configured || loadedBereia.EntityID != bereia.EntityID {
		t.Fatalf("deleting MASTER changed Bereia: %#v, %v", loadedBereia, err)
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

func TestAdminServiceRejectsRetiredDefaultTenant(t *testing.T) {
	service := NewAdminService(newAdminTestStore(t), MetadataHTTPFetcher{}, "https://code-foundry.example", nil)
	if _, err := service.Get(context.Background(), "default"); !errors.Is(err, ErrAdminInvalidInput) {
		t.Fatalf("Get default = %v", err)
	}
	if _, err := service.Put(context.Background(), "default", PutIdPConfiguration{}); !errors.Is(err, ErrAdminInvalidInput) {
		t.Fatalf("Put default = %v", err)
	}
	if err := service.Delete(context.Background(), "default"); !errors.Is(err, ErrAdminInvalidInput) {
		t.Fatalf("Delete default = %v", err)
	}
}

func TestMetadataHTTPFetcherRejectsSSRFAndInsecureURLs(t *testing.T) {
	fetcher := MetadataHTTPFetcher{}
	for _, rawURL := range []string{
		"http://idp.example.com/metadata",
		"https://127.0.0.1/metadata",
		"https://[::1]/metadata",
		"https://100.64.0.1/metadata",
		"https://198.18.0.1/metadata",
		"https://198.51.100.1/metadata",
		"https://240.0.0.1/metadata",
		"https://[64:ff9b::a00:1]/metadata",
		"https://[2001:db8::1]/metadata",
		"https://[2002:0a00:0001::1]/metadata",
		"https://user:password@idp.example.com/metadata",
		"https://idp.example.com/metadata?token=must-not-leak",
	} {
		if _, err := fetcher.Fetch(context.Background(), rawURL); err == nil {
			t.Fatalf("expected %q to be rejected", rawURL)
		} else if strings.Contains(err.Error(), "must-not-leak") {
			t.Fatalf("metadata error leaked URL query: %v", err)
		}
	}
}

func TestMetadataHTTPFetcherRejectsSpecialPurposeDNSAnswers(t *testing.T) {
	for _, answer := range []string{"100.64.0.10", "198.18.0.10", "192.0.2.10", "64:ff9b::a00:1", "2001:db8::10"} {
		answer := answer
		t.Run(answer, func(t *testing.T) {
			fetcher := MetadataHTTPFetcher{LookupIP: func(context.Context, string, string) ([]net.IP, error) {
				return []net.IP{net.ParseIP(answer)}, nil
			}}
			if _, err := fetcher.Fetch(context.Background(), "https://idp.example.com/metadata"); err == nil || !strings.Contains(err.Error(), "non-public") {
				t.Fatalf("special-purpose DNS answer %s was accepted: %v", answer, err)
			}
		})
	}
}

func TestPublicMetadataIPAllowlist(t *testing.T) {
	for address, want := range map[string]bool{
		"1.1.1.1": true, "8.8.8.8": true, "2606:4700:4700::1111": true,
		"10.0.0.1": false, "100.64.0.1": false, "198.18.0.1": false,
		"203.0.113.1": false, "64:ff9b::a00:1": false, "2001:db8::1": false,
	} {
		if got := isPublicMetadataIP(net.ParseIP(address)); got != want {
			t.Fatalf("isPublicMetadataIP(%s) = %v, want %v", address, got, want)
		}
	}
}
