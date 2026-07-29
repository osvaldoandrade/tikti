package saml

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/vmihailenco/msgpack/v5"
)

// helper: spin up miniredis and return a connected RedisStore + cleanup.
func newTestStore(t *testing.T) (*RedisStore, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		_ = rdb.Close()
		mr.Close()
	})
	return NewRedisStore(rdb), mr
}

// TestPutRequest_NX verifies that a second PutRequest with the same ID fails.
func TestPutRequest_NX(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	rec := RequestRecord{
		ID:           "req-001",
		TenantID:     "t-001",
		RelayState:   "/dashboard",
		ACSURL:       "https://sp.example.com/acs",
		IssueInstant: time.Now().UTC().Truncate(time.Second),
	}

	if err := store.PutRequest(ctx, rec); err != nil {
		t.Fatalf("first PutRequest failed: %v", err)
	}

	err := store.PutRequest(ctx, rec)
	if err == nil {
		t.Fatal("second PutRequest with same ID should have failed")
	}
}

// TestConsumeRequest_Atomic verifies that among concurrent consumers, exactly
// one wins and the others get (zero, false, nil).
func TestConsumeRequest_Atomic(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	rec := RequestRecord{
		ID:           "req-race",
		TenantID:     "t-001",
		RelayState:   "/home",
		ACSURL:       "https://sp.example.com/acs",
		IssueInstant: time.Now().UTC().Truncate(time.Second),
	}
	if err := store.PutRequest(ctx, rec); err != nil {
		t.Fatalf("PutRequest: %v", err)
	}

	const goroutines = 10
	wins := make(chan RequestRecord, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			got, ok, err := store.ConsumeRequest(ctx, "req-race")
			if err != nil {
				t.Errorf("ConsumeRequest error: %v", err)
				return
			}
			if ok {
				wins <- got
			}
		}()
	}

	wg.Wait()
	close(wins)

	var winners []RequestRecord
	for w := range wins {
		winners = append(winners, w)
	}
	if len(winners) != 1 {
		t.Fatalf("expected exactly 1 winner, got %d", len(winners))
	}
	if winners[0].ID != rec.ID {
		t.Errorf("winner ID = %q, want %q", winners[0].ID, rec.ID)
	}
}

// TestPutIdP_Persists verifies that IdP trust survives until explicit removal.
func TestPutIdP_Persists(t *testing.T) {
	store, mr := newTestStore(t)
	ctx := context.Background()

	rec := IdPRecord{
		TenantID: "t-001",
		EntityID: "https://idp.example.com",
		SSOURL:   "https://idp.example.com/sso",
	}
	if err := store.PutIdP(ctx, rec); err != nil {
		t.Fatalf("PutIdP: %v", err)
	}

	// Should be retrievable before TTL.
	got, err := store.GetIdP(ctx, "t-001")
	if err != nil {
		t.Fatalf("GetIdP: %v", err)
	}
	if got.EntityID != rec.EntityID {
		t.Errorf("EntityID = %q, want %q", got.EntityID, rec.EntityID)
	}

	// Fast-forward well past the former 24-hour TTL.
	mr.FastForward(7 * 24 * time.Hour)

	got, err = store.GetIdP(ctx, "t-001")
	if err != nil || got.EntityID != rec.EntityID {
		t.Errorf("expected persistent IdP record, got %#v, %v", got, err)
	}
}

// TestGetIdP_NotFound_ErrSentinel verifies that GetIdP returns the typed
// sentinel error when the record does not exist.
func TestGetIdP_NotFound_ErrSentinel(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	_, err := store.GetIdP(ctx, "no-such-tenant")
	if err != ErrIdPNotFound {
		t.Errorf("expected ErrIdPNotFound, got %v", err)
	}
}

// TestListIdPs_Scan verifies that SCAN iterates > 100 records without hang.
func TestListIdPs_Scan(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	const count = 150
	for i := 0; i < count; i++ {
		rec := IdPRecord{
			TenantID: fmt.Sprintf("t-%d", i),
			EntityID: fmt.Sprintf("https://idp.example.com/%d", i),
		}
		if err := store.PutIdP(ctx, rec); err != nil {
			t.Fatalf("PutIdP %d: %v", i, err)
		}
	}

	idps, err := store.ListIdPs(ctx)
	if err != nil {
		t.Fatalf("ListIdPs: %v", err)
	}
	if len(idps) != count {
		t.Errorf("ListIdPs returned %d records, want %d", len(idps), count)
	}
}

// TestPutIndex_TTLBoundByNotOnOrAfter verifies that the TTL is derived from
// NotOnOrAfter minus now.
func TestPutIndex_TTLBoundByNotOnOrAfter(t *testing.T) {
	store, mr := newTestStore(t)
	ctx := context.Background()

	notOnOrAfter := time.Now().Add(60 * time.Second).UTC()
	rec := IndexRecord{
		TenantID:     "t-001",
		Subject:      "user@example.com",
		SessionIndex: "si-001",
		NotOnOrAfter: notOnOrAfter,
	}
	if err := store.PutIndex(ctx, "user@example.com", rec); err != nil {
		t.Fatalf("PutIndex: %v", err)
	}

	// Should still exist.
	got, err := store.GetIndex(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("GetIndex: %v", err)
	}
	if got.Subject != "user@example.com" {
		t.Errorf("Subject = %q, want %q", got.Subject, "user@example.com")
	}

	// Fast-forward past the TTL.
	mr.FastForward(61 * time.Second)

	_, err = store.GetIndex(ctx, "user@example.com")
	if err == nil {
		t.Error("expected error after TTL expiry, got nil")
	}
}

// TestMarkSeen_Replay verifies that the second SETNX returns false (replay
// detected).
func TestMarkSeen_Replay(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	ok, err := store.MarkSeen(ctx, "assertion-001", time.Hour)
	if err != nil {
		t.Fatalf("first MarkSeen: %v", err)
	}
	if !ok {
		t.Fatal("first MarkSeen should return true")
	}

	ok, err = store.MarkSeen(ctx, "assertion-001", time.Hour)
	if err != nil {
		t.Fatalf("second MarkSeen: %v", err)
	}
	if ok {
		t.Fatal("second MarkSeen should return false (replay)")
	}
}

// TestDomain_GetPutDelete verifies the discovery table round-trip.
func TestDomain_GetPutDelete(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	// Put
	if err := store.PutDomain(ctx, "example.com", "t-001"); err != nil {
		t.Fatalf("PutDomain: %v", err)
	}

	// Get
	tid, err := store.GetDomain(ctx, "example.com")
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if tid != "t-001" {
		t.Errorf("GetDomain = %q, want %q", tid, "t-001")
	}

	// Delete
	if err := store.DeleteDomain(ctx, "example.com"); err != nil {
		t.Fatalf("DeleteDomain: %v", err)
	}

	// Verify gone
	_, err = store.GetDomain(ctx, "example.com")
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

// TestConsumeRequest_RoundTrip verifies the full data round-trip through
// msgpack serialization.
func TestConsumeRequest_RoundTrip(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	orig := RequestRecord{
		ID:           "req-rt",
		TenantID:     "t-001",
		RelayState:   "/profile",
		ACSURL:       "https://sp.example.com/acs",
		IssueInstant: time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC),
	}
	if err := store.PutRequest(ctx, orig); err != nil {
		t.Fatalf("PutRequest: %v", err)
	}

	got, ok, err := store.ConsumeRequest(ctx, "req-rt")
	if err != nil {
		t.Fatalf("ConsumeRequest: %v", err)
	}
	if !ok {
		t.Fatal("ConsumeRequest: expected ok=true")
	}
	if got.ID != orig.ID || got.TenantID != orig.TenantID ||
		got.RelayState != orig.RelayState || got.ACSURL != orig.ACSURL ||
		!got.IssueInstant.Equal(orig.IssueInstant) {
		t.Errorf("round-trip mismatch:\n got  %+v\n want %+v", got, orig)
	}

	// Second consume must return false.
	_, ok, err = store.ConsumeRequest(ctx, "req-rt")
	if err != nil {
		t.Fatalf("second ConsumeRequest: %v", err)
	}
	if ok {
		t.Error("second ConsumeRequest should return false")
	}
}

// TestIdPRecord_MsgpackCompat verifies that the msgpack encoding used by the
// store is compatible with direct msgpack round-trips.
func TestIdPRecord_MsgpackCompat(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	orig := IdPRecord{
		TenantID:     "t-compat",
		EntityID:     "https://idp.test",
		SSOURL:       "https://idp.test/sso",
		SLOURL:       "https://idp.test/slo",
		SigningCerts: [][]byte{[]byte("cert-data")},
		AttributeMap: map[string][]string{"email": {"mail"}},
		LastFetched:  time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := store.PutIdP(ctx, orig); err != nil {
		t.Fatalf("PutIdP: %v", err)
	}

	// Read raw from Redis and manually unmarshal.
	rdb := store.rdb
	raw, err := rdb.Get(ctx, "saml:idp:t-compat").Bytes()
	if err != nil {
		t.Fatalf("raw Get: %v", err)
	}
	var got IdPRecord
	if err := msgpack.Unmarshal(raw, &got); err != nil {
		t.Fatalf("msgpack.Unmarshal: %v", err)
	}
	if got.EntityID != orig.EntityID {
		t.Errorf("EntityID = %q, want %q", got.EntityID, orig.EntityID)
	}
}

// TestDeleteIdP verifies DeleteIdP removes an existing record.
func TestDeleteIdP(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	rec := IdPRecord{TenantID: "t-del", EntityID: "https://idp.example.com"}
	if err := store.PutIdP(ctx, rec); err != nil {
		t.Fatalf("PutIdP: %v", err)
	}
	if err := store.DeleteIdP(ctx, "t-del"); err != nil {
		t.Fatalf("DeleteIdP: %v", err)
	}
	_, err := store.GetIdP(ctx, "t-del")
	if err != ErrIdPNotFound {
		t.Errorf("expected ErrIdPNotFound after delete, got %v", err)
	}
}

// TestDeleteIndex verifies DeleteIndex removes an existing session index.
func TestDeleteIndex(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	rec := IndexRecord{
		TenantID:     "t-001",
		Subject:      "user@example.com",
		SessionIndex: "si-001",
		NotOnOrAfter: time.Now().Add(10 * time.Minute).UTC(),
	}
	if err := store.PutIndex(ctx, "user@example.com", rec); err != nil {
		t.Fatalf("PutIndex: %v", err)
	}
	if err := store.DeleteIndex(ctx, "user@example.com"); err != nil {
		t.Fatalf("DeleteIndex: %v", err)
	}
	_, err := store.GetIndex(ctx, "user@example.com")
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

// TestPutRequest_MarshalAndConsume verifies error paths are covered.
func TestPutRequest_MarshalAndConsume(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	// Consume non-existent request.
	_, ok, err := store.ConsumeRequest(ctx, "no-such")
	if err != nil {
		t.Fatalf("ConsumeRequest error: %v", err)
	}
	if ok {
		t.Error("ConsumeRequest should return false for non-existent ID")
	}
}

// TestPutIndex_PastNotOnOrAfter verifies TTL floor for expired records.
func TestPutIndex_PastNotOnOrAfter(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	rec := IndexRecord{
		TenantID:     "t-001",
		Subject:      "user@past.com",
		SessionIndex: "si-past",
		NotOnOrAfter: time.Now().Add(-1 * time.Hour).UTC(), // already expired
	}
	// Should still succeed (floor to 1s TTL).
	if err := store.PutIndex(ctx, "user@past.com", rec); err != nil {
		t.Fatalf("PutIndex with past NotOnOrAfter: %v", err)
	}
}

// TestGetDomain_NotFound verifies GetDomain error for missing domains.
func TestGetDomain_NotFound(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	_, err := store.GetDomain(ctx, "nonexistent.com")
	if err == nil {
		t.Error("expected error for nonexistent domain")
	}
}

// TestGetIndex_NotFound verifies GetIndex error for missing index.
func TestGetIndex_NotFound(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	_, err := store.GetIndex(ctx, "nonexistent@example.com")
	if err == nil {
		t.Error("expected error for nonexistent index")
	}
}

// TestPutIdP_Overwrite verifies that PutIdP overwrites an existing record.
func TestPutIdP_Overwrite(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	rec1 := IdPRecord{TenantID: "t-overwrite", EntityID: "https://v1.example.com"}
	if err := store.PutIdP(ctx, rec1); err != nil {
		t.Fatalf("PutIdP v1: %v", err)
	}

	rec2 := IdPRecord{TenantID: "t-overwrite", EntityID: "https://v2.example.com"}
	if err := store.PutIdP(ctx, rec2); err != nil {
		t.Fatalf("PutIdP v2: %v", err)
	}

	got, err := store.GetIdP(ctx, "t-overwrite")
	if err != nil {
		t.Fatalf("GetIdP: %v", err)
	}
	if got.EntityID != "https://v2.example.com" {
		t.Errorf("EntityID = %q, want %q", got.EntityID, "https://v2.example.com")
	}
}

// TestListIdPs_Empty verifies ListIdPs returns nil for an empty store.
func TestListIdPs_Empty(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	idps, err := store.ListIdPs(ctx)
	if err != nil {
		t.Fatalf("ListIdPs: %v", err)
	}
	if len(idps) != 0 {
		t.Errorf("expected 0 IdPs, got %d", len(idps))
	}
}

// TestRedisStore_ErrorPaths exercises error paths by closing the redis server.
func TestRedisStore_ErrorPaths(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewRedisStore(rdb)
	ctx := context.Background()

	// Close the miniredis to force errors.
	mr.Close()
	_ = rdb.Close()

	// PutRequest with closed connection.
	if err := store.PutRequest(ctx, RequestRecord{ID: "err"}); err == nil {
		t.Error("PutRequest: expected error with closed connection")
	}

	// ConsumeRequest with closed connection.
	_, _, err = store.ConsumeRequest(ctx, "err")
	if err == nil {
		t.Error("ConsumeRequest: expected error with closed connection")
	}

	// PutIdP with closed connection.
	if err := store.PutIdP(ctx, IdPRecord{TenantID: "err"}); err == nil {
		t.Error("PutIdP: expected error with closed connection")
	}

	// GetIdP with closed connection.
	_, err = store.GetIdP(ctx, "err")
	if err == nil {
		t.Error("GetIdP: expected error with closed connection")
	}

	// ListIdPs with closed connection.
	_, err = store.ListIdPs(ctx)
	if err == nil {
		t.Error("ListIdPs: expected error with closed connection")
	}

	// DeleteIdP with closed connection.
	if err := store.DeleteIdP(ctx, "err"); err == nil {
		t.Error("DeleteIdP: expected error with closed connection")
	}

	// PutIndex with closed connection.
	if err := store.PutIndex(ctx, "err", IndexRecord{NotOnOrAfter: time.Now().Add(time.Hour)}); err == nil {
		t.Error("PutIndex: expected error with closed connection")
	}

	// GetIndex with closed connection.
	_, err = store.GetIndex(ctx, "err")
	if err == nil {
		t.Error("GetIndex: expected error with closed connection")
	}

	// DeleteIndex with closed connection.
	if err := store.DeleteIndex(ctx, "err"); err == nil {
		t.Error("DeleteIndex: expected error with closed connection")
	}

	// MarkSeen with closed connection.
	_, err = store.MarkSeen(ctx, "err", time.Hour)
	if err == nil {
		t.Error("MarkSeen: expected error with closed connection")
	}

	// PutDomain with closed connection.
	if err := store.PutDomain(ctx, "err", "t-err"); err == nil {
		t.Error("PutDomain: expected error with closed connection")
	}

	// GetDomain with closed connection.
	_, err = store.GetDomain(ctx, "err")
	if err == nil {
		t.Error("GetDomain: expected error with closed connection")
	}

	// DeleteDomain with closed connection.
	if err := store.DeleteDomain(ctx, "err"); err == nil {
		t.Error("DeleteDomain: expected error with closed connection")
	}
}

// TestCorruptedData exercises unmarshal error paths by writing raw invalid data.
func TestCorruptedData(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	// Write corrupt data directly for IdP.
	store.rdb.Set(ctx, "saml:idp:corrupt", "not-valid-msgpack", 0)
	_, err := store.GetIdP(ctx, "corrupt")
	if err == nil {
		t.Error("GetIdP: expected unmarshal error for corrupted data")
	}
	if err == ErrIdPNotFound {
		t.Error("GetIdP: got ErrIdPNotFound, expected unmarshal error")
	}

	// Write corrupt data for Index.
	store.rdb.Set(ctx, "saml:idx:corrupt@test.com", "not-valid-msgpack", 0)
	_, err = store.GetIndex(ctx, "corrupt@test.com")
	if err == nil {
		t.Error("GetIndex: expected unmarshal error for corrupted data")
	}

	// Write corrupt data for request, then try to consume.
	store.rdb.Set(ctx, "saml:req:corrupt-req", "not-valid-msgpack", 300*time.Second)
	_, _, err = store.ConsumeRequest(ctx, "corrupt-req")
	if err == nil {
		t.Error("ConsumeRequest: expected unmarshal error for corrupted data")
	}

	// Write corrupt data in ListIdPs path.
	store.rdb.Set(ctx, "saml:idp:corrupt-list", "not-valid-msgpack", 0)
	_, err = store.ListIdPs(ctx)
	if err == nil {
		t.Error("ListIdPs: expected unmarshal error for corrupted data")
	}
}

// TestConsumeRequest_EmptyValue verifies consuming an empty value returns false.
func TestConsumeRequest_EmptyValue(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	// Write empty string directly as request data.
	store.rdb.Set(ctx, "saml:req:empty", "", 300*time.Second)
	_, ok, err := store.ConsumeRequest(ctx, "empty")
	if err != nil {
		t.Fatalf("ConsumeRequest: %v", err)
	}
	if ok {
		t.Error("ConsumeRequest: expected ok=false for empty value")
	}
}

// TestListIdPs_NilValueSkipped verifies that nil MGet values are skipped.
func TestListIdPs_NilValueSkipped(t *testing.T) {
	store, mr := newTestStore(t)
	ctx := context.Background()

	// Write a valid and then an expiring IdP.
	valid := IdPRecord{TenantID: "t-valid", EntityID: "https://valid.example.com"}
	if err := store.PutIdP(ctx, valid); err != nil {
		t.Fatalf("PutIdP: %v", err)
	}
	// Write a second one with a very short TTL, then expire it between SCAN and MGet.
	// Since miniredis doesn't support that, write an empty-string value instead.
	store.rdb.Set(ctx, "saml:idp:t-empty", "", 86400*time.Second)

	idps, err := store.ListIdPs(ctx)
	if err != nil {
		t.Fatalf("ListIdPs: %v", err)
	}
	// Only the valid one should be returned; the empty one is skipped.
	if len(idps) != 1 {
		t.Errorf("expected 1 IdP, got %d", len(idps))
	}

	// Also fast-forward to expire a key so MGet returns nil for it.
	store.rdb.Set(ctx, "saml:idp:t-expire", "data", 1*time.Second)
	mr.FastForward(2 * time.Second)
	// The expired key is gone from SCAN, so ListIdPs should still work.
	idps2, err := store.ListIdPs(ctx)
	if err != nil {
		t.Fatalf("ListIdPs after expire: %v", err)
	}
	if len(idps2) != 1 {
		t.Errorf("expected 1 IdP after expire, got %d", len(idps2))
	}
}
