package saml

import (
	"context"
	"errors"
	"os"
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

// TestRefresh_IdPRoundtrip_Observed verifies that the IdP metadata fetch
// roundtrip duration histogram is observed after a fetch attempt.
func TestRefresh_IdPRoundtrip_Observed(t *testing.T) {
	idp := IdPRecord{
		TenantID:    "t-rt",
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
		Fetcher: func(_ string) ([]byte, error) {
			time.Sleep(1 * time.Millisecond) // ensure non-zero duration
			return nil, errors.New("fail")
		},
	})

	r.tick(context.Background())

	// Verify the histogram was observed.
	hm := &dto.Metric{}
	if err := m.IdPRoundtrip.WithLabelValues("t-rt").(prometheus.Histogram).Write(hm); err != nil {
		t.Fatalf("write histogram: %v", err)
	}
	if hm.GetHistogram().GetSampleCount() != 1 {
		t.Errorf("IdPRoundtrip sample count = %d, want 1", hm.GetHistogram().GetSampleCount())
	}
}

// TestRefresh_IdPCertExpiry_Set verifies that the IdP cert expiry gauge is
// set after a successful metadata refresh.
func TestRefresh_IdPCertExpiry_Set(t *testing.T) {
	metaXML, err := os.ReadFile("testdata/idp_okta.xml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	existing := IdPRecord{
		TenantID:    "t-cert",
		MetadataURL: "https://idp.example.com/meta",
	}
	store := newRefreshMemStore(existing)

	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	r := NewRefresher(RefresherConfig{
		Store:     store,
		Metrics:   m,
		Interval:  1 * time.Hour,
		MaxJitter: 0,
		Fetcher:   func(_ string) ([]byte, error) { return metaXML, nil },
	})

	r.tick(context.Background())

	// Verify that at least one IdPCertExpiry gauge was set.
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() == "tikti_saml_idp_cert_expiry_seconds" {
			if len(mf.GetMetric()) > 0 {
				found = true
			}
		}
	}
	if !found {
		t.Error("IdPCertExpiry gauge not set after successful metadata refresh")
	}
}

// TestRefresh_SPCertExpiry_Set verifies that the SP cert expiry gauge is
// set when SPCertPEM is provided.
func TestRefresh_SPCertExpiry_Set(t *testing.T) {
	spCert, err := os.ReadFile("testdata/sp_signing.crt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	store := newRefreshMemStore() // no IdPs

	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	r := NewRefresher(RefresherConfig{
		Store:     store,
		Metrics:   m,
		Interval:  1 * time.Hour,
		MaxJitter: 0,
		Fetcher:   func(_ string) ([]byte, error) { return nil, errors.New("stub") },
		SPCertPEM: spCert,
	})

	r.tick(context.Background())

	// Verify SPCertExpiry gauge was set.
	gm := &dto.Metric{}
	if err := m.SPCertExpiry.Write(gm); err != nil {
		t.Fatalf("write gauge: %v", err)
	}
	val := gm.GetGauge().GetValue()
	if val <= 0 {
		t.Errorf("SPCertExpiry = %v, want > 0 (cert expires 2035)", val)
	}
}
