package saml

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// ─── Test helpers ─────────────────────────────────────────────────────────────

// tickCountingStore counts how many times ListIdPs is called.
type tickCountingStore struct {
	stubStore
	count atomic.Int32
}

func (s *tickCountingStore) ListIdPs(_ context.Context) ([]IdPRecord, error) {
	s.count.Add(1)
	return nil, nil
}

// refreshMemStore is a simple in-memory Store for refresh tests.
type refreshMemStore struct {
	stubStore
	records map[string]IdPRecord
}

func newRefreshMemStore(recs ...IdPRecord) *refreshMemStore {
	s := &refreshMemStore{records: make(map[string]IdPRecord)}
	for _, r := range recs {
		s.records[r.TenantID] = r
	}
	return s
}

func (s *refreshMemStore) PutIdP(_ context.Context, rec IdPRecord) error {
	s.records[rec.TenantID] = rec
	return nil
}

func (s *refreshMemStore) GetIdP(_ context.Context, tid string) (IdPRecord, error) {
	r, ok := s.records[tid]
	if !ok {
		return IdPRecord{}, ErrIdPNotFound
	}
	return r, nil
}

func (s *refreshMemStore) ListIdPs(_ context.Context) ([]IdPRecord, error) {
	out := make([]IdPRecord, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	return out, nil
}

// gaugeVecValue reads the current value of a GaugeVec for the given label set.
func gaugeVecValue(t *testing.T, gv *prometheus.GaugeVec, labels ...string) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := gv.WithLabelValues(labels...).Write(m); err != nil {
		t.Fatalf("GaugeVec.Write: %v", err)
	}
	return m.GetGauge().GetValue()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

// TestRefresh_TickerFires verifies that the refresher fires at least one tick
// (i.e. calls ListIdPs) within 5 seconds when a short interval is used.
func TestRefresh_TickerFires(t *testing.T) {
	store := &tickCountingStore{}
	r := NewRefresher(RefresherConfig{
		Store:     store,
		Interval:  50 * time.Millisecond,
		MaxJitter: 0, // no jitter in tests
		Fetcher:   func(_ string) ([]byte, error) { return nil, errors.New("stub") },
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)

	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("timeout: ListIdPs never called after 5 s (count=%d)", store.count.Load())
		default:
			if store.count.Load() >= 1 {
				return // success
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// TestRefresh_FetchFail_KeepsOld verifies that a failing metadata fetch does
// not overwrite the existing IdP record in the store.
func TestRefresh_FetchFail_KeepsOld(t *testing.T) {
	original := IdPRecord{
		TenantID:    "t-fail",
		EntityID:    "https://idp.example.com",
		MetadataURL: "https://idp.example.com/meta",
		SSOURL:      "https://idp.example.com/sso",
	}
	store := newRefreshMemStore(original)

	r := NewRefresher(RefresherConfig{
		Store:     store,
		Interval:  1 * time.Hour,
		MaxJitter: 0,
		Fetcher:   func(_ string) ([]byte, error) { return nil, errors.New("network error") },
	})

	r.tick(context.Background())

	got, err := store.GetIdP(context.Background(), "t-fail")
	if err != nil {
		t.Fatalf("GetIdP: %v", err)
	}
	if got.EntityID != original.EntityID {
		t.Errorf("EntityID changed: got %q, want %q", got.EntityID, original.EntityID)
	}
	if got.SSOURL != original.SSOURL {
		t.Errorf("SSOURL changed: got %q, want %q", got.SSOURL, original.SSOURL)
	}
}

// TestRefresh_TwoFailures_GaugeBumped verifies that two consecutive fetch
// failures drive the consecutive-failures gauge to 2.
func TestRefresh_TwoFailures_GaugeBumped(t *testing.T) {
	idp := IdPRecord{
		TenantID:    "t-gauge",
		EntityID:    "https://idp.example.com",
		MetadataURL: "https://idp.example.com/meta",
	}
	store := newRefreshMemStore(idp)

	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	r := NewRefresher(RefresherConfig{
		Store:     store,
		Metrics:   m,
		Interval:  1 * time.Hour,
		MaxJitter: 0,
		Fetcher:   func(_ string) ([]byte, error) { return nil, errors.New("fetch error") },
	})

	ctx := context.Background()
	r.tick(ctx)
	r.tick(ctx)

	v := gaugeVecValue(t, m.RefreshConsecFailures, "t-gauge")
	if v != 2 {
		t.Errorf("consecutive failures gauge = %v, want 2", v)
	}
}
