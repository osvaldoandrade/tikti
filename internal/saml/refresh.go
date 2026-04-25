package saml

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"time"
)

// DefaultJitter is the production upper bound on the random pre-first-tick
// delay. Pass this to RefresherConfig.MaxJitter in production; use 0 in tests.
const DefaultJitter = jitterMax

// jitterMax is the upper bound on the random first-tick delay for production use.
const jitterMax = 5 * time.Minute

// MetadataFetcher downloads raw IdP metadata XML from the given URL.
type MetadataFetcher func(url string) ([]byte, error)

// RefresherConfig carries all parameters for the background IdP metadata refresher.
type RefresherConfig struct {
	Store     Store           // required
	Metrics   *Metrics        // may be nil; metrics are skipped when nil
	Interval  time.Duration   // ticker period
	MaxJitter time.Duration   // upper bound of random pre-first-tick delay; 0 = no jitter (useful in tests)
	Fetcher   MetadataFetcher // nil → httpFetch
	SPCertPEM []byte          // optional PEM-encoded SP signing cert; when set, SPCertExpiry gauge is updated each tick
}

// Refresher runs the background IdP metadata refresh loop.
// One goroutine is started per call to Start; it exits when ctx is cancelled.
type Refresher struct {
	store       Store
	metrics     *Metrics
	interval    time.Duration
	maxJitter   time.Duration
	fetcher     MetadataFetcher
	spCertPEM   []byte
	consecFails map[string]int
}

// NewRefresher creates a Refresher from cfg. If cfg.Fetcher is nil the default
// HTTP fetcher is used. Set cfg.MaxJitter to 0 to disable jitter (e.g. in tests).
func NewRefresher(cfg RefresherConfig) *Refresher {
	f := cfg.Fetcher
	if f == nil {
		f = httpFetch
	}
	return &Refresher{
		store:       cfg.Store,
		metrics:     cfg.Metrics,
		interval:    cfg.Interval,
		maxJitter:   cfg.MaxJitter,
		fetcher:     f,
		spCertPEM:   cfg.SPCertPEM,
		consecFails: make(map[string]int),
	}
}

// Start launches the background refresh goroutine. The goroutine exits when
// ctx is cancelled, enabling graceful shutdown.
func (r *Refresher) Start(ctx context.Context) {
	go r.run(ctx)
}

// run is the goroutine body: it applies an optional jitter delay, then fires
// the ticker at r.interval.
func (r *Refresher) run(ctx context.Context) {
	if r.maxJitter > 0 {
		//nolint:gosec // non-crypto jitter is intentional
		jitter := time.Duration(rand.Int63n(int64(r.maxJitter)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter):
		}
	}

	// Fire once immediately after the optional jitter, then on every tick.
	r.tick(ctx)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tick(ctx)
		}
	}
}

// tick performs one full refresh cycle: list all IdPs and refresh each one.
func (r *Refresher) tick(ctx context.Context) {
	r.updateSPCertExpiry()

	idps, err := r.store.ListIdPs(ctx)
	if err != nil {
		log.Printf("saml: metadata refresher: list IdPs: %v", err)
		return
	}
	for _, idp := range idps {
		r.refreshOne(ctx, idp)
	}
}

// refreshOne fetches fresh metadata for a single IdP and overwrites the stored
// record on success. On failure the existing record is kept intact.
func (r *Refresher) refreshOne(ctx context.Context, existing IdPRecord) {
	tid := existing.TenantID
	if existing.MetadataURL == "" {
		return
	}

	t0 := time.Now()
	raw, err := r.fetcher(existing.MetadataURL)
	dur := time.Since(t0)
	if r.metrics != nil {
		r.metrics.IdPRoundtrip.WithLabelValues(tid).Observe(dur.Seconds())
	}
	if err != nil {
		r.handleFailure(tid, err)
		return
	}

	rec, err := ParseIdPMetadata(raw)
	if err != nil {
		r.handleFailure(tid, fmt.Errorf("parse: %w", err))
		return
	}

	// Carry over tenant-specific fields that metadata does not supply.
	rec.TenantID = tid
	rec.MetadataURL = existing.MetadataURL
	rec.LastFetched = time.Now()
	if rec.AttributeMap == nil && existing.AttributeMap != nil {
		rec.AttributeMap = existing.AttributeMap
	}

	if err := r.store.PutIdP(ctx, *rec); err != nil {
		r.handleFailure(tid, fmt.Errorf("store: %w", err))
		return
	}

	// Success: reset consecutive failure tracking.
	r.consecFails[tid] = 0
	if r.metrics != nil {
		r.metrics.MetadataRefresh.WithLabelValues(tid, "success").Inc()
		r.metrics.RefreshConsecFailures.WithLabelValues(tid).Set(0)
	}

	// Update IdP cert expiry gauge for each signing cert.
	r.updateIdPCertExpiry(tid, rec.SigningCerts)
}

// handleFailure logs the error, bumps the failure counter/gauge, and emits an
// ERROR-level log when two consecutive failures have occurred.
func (r *Refresher) handleFailure(tid string, err error) {
	log.Printf("saml: metadata refresh failed for tid=%s: %v", tid, err)

	r.consecFails[tid]++
	if r.metrics != nil {
		r.metrics.MetadataRefresh.WithLabelValues(tid, "failure").Inc()
		r.metrics.RefreshConsecFailures.WithLabelValues(tid).Set(float64(r.consecFails[tid]))
	}

	if r.consecFails[tid] >= 2 {
		log.Printf("ERROR saml: metadata refresh for tid=%s has failed %d consecutive times",
			tid, r.consecFails[tid])
	}
}

// updateIdPCertExpiry parses DER-encoded signing certs and sets the
// IdPCertExpiry gauge for each cert. Seconds until expiry may be negative
// if the cert is already expired.
func (r *Refresher) updateIdPCertExpiry(tid string, derCerts [][]byte) {
	if r.metrics == nil {
		return
	}
	now := time.Now()
	for _, der := range derCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		subject := cert.Subject.CommonName
		if subject == "" {
			subject = cert.Subject.String()
		}
		r.metrics.IdPCertExpiry.WithLabelValues(tid, subject).Set(cert.NotAfter.Sub(now).Seconds())
	}
}

// updateSPCertExpiry parses the optional SP signing cert PEM and sets the
// SPCertExpiry gauge. Called once per tick.
func (r *Refresher) updateSPCertExpiry() {
	if r.metrics == nil || len(r.spCertPEM) == 0 {
		return
	}
	block, _ := pem.Decode(r.spCertPEM)
	if block == nil {
		log.Printf("saml: SPCertPEM provided but contains no valid PEM block")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("saml: failed to parse SP signing cert: %v", err)
		return
	}
	r.metrics.SPCertExpiry.Set(cert.NotAfter.Sub(time.Now()).Seconds())
}

// httpClient is the default HTTP client used by httpFetch, with a 30-second
// timeout to prevent the refresh goroutine from hanging indefinitely.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// httpFetch is the default MetadataFetcher. It performs an HTTP GET with a
// timeout and validates that the response status is 2xx.
func httpFetch(url string) ([]byte, error) {
	//nolint:gosec // URL originates from admin-supplied IdP records
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status %d fetching %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}
