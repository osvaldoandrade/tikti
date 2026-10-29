package nativeauth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/internal/nativepolicy"
)

func storeFixture(t *testing.T) (*Store, *miniredis.Miniredis, *time.Time) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr(), MaxRetries: -1, DialTimeout: 100 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	return NewStore(client, func() time.Time { return now }), server, &now
}

func requestFixture() Request {
	challenge, _ := nativepolicy.S256Challenge(strings.Repeat("v", 43))
	return Request{ClientID: "code-forge-desktop-native", ClientFingerprint: strings.Repeat("a", 64),
		RedirectURI: "http://127.0.0.1:49152/oauth/callback", State: strings.Repeat("s", 43), Challenge: challenge}
}

func grantFixture(now time.Time) Grant {
	request := requestFixture()
	return Grant{ClientID: request.ClientID, ClientFingerprint: request.ClientFingerprint,
		RedirectURI: request.RedirectURI, Challenge: request.Challenge, Subject: "user-1", IdentityTenantID: "local-tenant",
		IdentityFingerprint: strings.Repeat("b", 64), TokenVersion: 3, ApprovedScopes: []string{"code-forge:access"},
		SessionExpiresAt: now.Add(time.Hour).Unix()}
}

func TestRequestCanBeConsumedOnlyOnceAcrossConcurrentRequests(t *testing.T) {
	store, _, _ := storeFixture(t)
	ctx := context.Background()
	id, err := store.CreateRequest(ctx, requestFixture())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Request(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			consumed, err := store.ConsumeRequest(ctx, id, snapshot)
			if err != nil {
				t.Error(err)
			}
			if consumed {
				accepted.Add(1)
			}
		}()
	}
	wait.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("authorization request was accepted %d times", accepted.Load())
	}
}

func TestCodeCanBeRedeemedOnlyOnceAndDoesNotPersistBearerSecrets(t *testing.T) {
	store, server, now := storeFixture(t)
	ctx := context.Background()
	code, err := store.CreateCode(ctx, grantFixture(*now))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range server.Keys() {
		raw, err := server.Get(key)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(key, code) || strings.Contains(raw, code) || strings.Contains(raw, strings.Repeat("v", 43)) {
			t.Fatal("plaintext code or verifier was persisted")
		}
		if strings.Contains(raw, "accessToken") || strings.Contains(raw, "idToken") || strings.Contains(raw, "password") {
			t.Fatal("credential field entered the code record")
		}
	}
	snapshot, err := store.Code(ctx, code)
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			consumed, err := store.ConsumeCode(ctx, code, snapshot)
			if err != nil {
				t.Error(err)
			}
			if consumed {
				accepted.Add(1)
			}
		}()
	}
	wait.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("authorization code was accepted %d times", accepted.Load())
	}
}

func TestExpiredRequestsAndCodesCannotBeReadOrConsumed(t *testing.T) {
	store, server, now := storeFixture(t)
	ctx := context.Background()
	id, err := store.CreateRequest(ctx, requestFixture())
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.CreateCode(ctx, grantFixture(*now))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Code(ctx, code)
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(RequestTTL + time.Second)
	server.FastForward(RequestTTL + time.Second)
	if _, err := store.Request(ctx, id); !errors.Is(err, ErrInvalidGrant) {
		t.Error("expired authorization request was accepted")
	}
	if _, err := store.Code(ctx, code); !errors.Is(err, ErrInvalidGrant) {
		t.Error("expired authorization code was accepted")
	}
	if ok, err := store.ConsumeCode(ctx, code, snapshot); ok || !errors.Is(err, ErrInvalidGrant) {
		t.Error("expired authorization snapshot was accepted")
	}
}

func TestCodeExpiryCannotOutliveItsSourceSAMLSession(t *testing.T) {
	store, _, now := storeFixture(t)
	grant := grantFixture(*now)
	grant.SessionExpiresAt = now.Add(10 * time.Second).Unix()
	code, err := store.CreateCode(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Code(context.Background(), code)
	if err != nil || snapshot.Value.ExpiresAt != grant.SessionExpiresAt {
		t.Fatal("authorization code exceeded the source session lifetime")
	}
}

func TestCorruptedOrReplacedCodeStateFailsClosed(t *testing.T) {
	store, server, now := storeFixture(t)
	ctx := context.Background()
	code, err := store.CreateCode(ctx, grantFixture(*now))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Code(ctx, code)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"", "{}", strings.Repeat("x", maximumRecord+1),
		strings.Replace(snapshot.raw, `{"clientId":`, `{"clientId":"other","clientId":`, 1),
		strings.TrimSuffix(snapshot.raw, "}") + `,"unexpected":true}`,
	} {
		server.Set(stateKey("code", code), raw)
		if _, err := store.Code(ctx, code); !errors.Is(err, ErrUnavailable) {
			t.Errorf("corrupt code record accepted: %v", err)
		}
		if consumed, err := store.ConsumeCode(ctx, code, snapshot); consumed || err != nil {
			t.Errorf("replaced record consumed: %v, %v", consumed, err)
		}
	}
	server.Set(stateKey("code", code), snapshot.raw)
	snapshot.Value.ApprovedScopes = []string{"unapproved:scope"}
	if consumed, err := store.ConsumeCode(ctx, code, snapshot); consumed || !errors.Is(err, ErrInvalidGrant) {
		t.Fatal("modified grant snapshot was accepted")
	}
}

func TestNativeStoreOutageNeverFallsBackToAnInMemoryGrant(t *testing.T) {
	store, server, now := storeFixture(t)
	server.Close()
	if _, err := store.CreateCode(context.Background(), grantFixture(*now)); !errors.Is(err, ErrUnavailable) {
		t.Error("storage outage did not fail closed")
	}
	var absent *Store
	if _, err := absent.CreateRequest(context.Background(), requestFixture()); !errors.Is(err, ErrUnavailable) {
		t.Error("absent storage did not fail closed")
	}
}
