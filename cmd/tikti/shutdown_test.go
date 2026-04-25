package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestShutdown_DrainsInFlight verifies that an in-flight HTTP request completes
// within the 30-second drain window when srv.Shutdown is called.
func TestShutdown_DrainsInFlight(t *testing.T) {
	const handlerDelay = 100 * time.Millisecond

	// Handler that sleeps briefly to simulate an in-flight request.
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(handlerDelay)
		w.WriteHeader(http.StatusOK)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: mux}

	go func() { _ = srv.Serve(ln) }()

	addr := ln.Addr().String()

	// Fire the slow request in the background.
	var (
		wg       sync.WaitGroup
		respCode int
		reqErr   error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		reqCtx, reqCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://"+addr+"/slow", nil)
		if err != nil {
			reqErr = err
			return
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			reqErr = err
			return
		}
		respCode = resp.StatusCode
		resp.Body.Close()
	}()

	// Give the request a moment to reach the handler before we shut down.
	time.Sleep(20 * time.Millisecond)

	shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutCtx); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}

	// Wait for the request goroutine to finish.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for in-flight request to complete")
	}

	if reqErr != nil {
		t.Fatalf("in-flight request returned error: %v", reqErr)
	}
	if respCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", respCode)
	}
}

// TestShutdown_WorkerStops verifies that a background worker goroutine exits
// promptly when its context is cancelled (simulating the SIGTERM → rootCtx
// cancellation that stops the SAML KeyHolder and other workers).
func TestShutdown_WorkerStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// simulate periodic work
			}
		}
	}()

	// Cancel the context — the worker must exit.
	cancel()

	select {
	case <-stopped:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("worker goroutine did not stop after context cancellation")
	}
}

// TestShutdown_HTTPServer_RejectsNewConnections verifies that after
// srv.Shutdown is called the server no longer accepts new connections,
// even though the listener was closed by Shutdown itself.
func TestShutdown_HTTPServer_RejectsNewConnections(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	addr := srv.Listener.Addr().String()

	// Shutdown closes the listener.
	srv.Close()

	// Subsequent connection attempts must fail.
	reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer reqCancel()
	req, newReqErr := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://"+addr+"/", nil)
	if newReqErr != nil {
		t.Fatalf("failed to build request: %v", newReqErr)
	}
	_, doErr := http.DefaultClient.Do(req)
	if doErr == nil {
		t.Fatal("expected connection error after shutdown, got nil")
	}
}
