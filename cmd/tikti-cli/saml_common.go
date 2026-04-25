package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/go-redis/redis/v8"
	"github.com/spf13/cobra"

	"github.com/osvaldoandrade/tikti/internal/saml"
)

// samlWriter wraps an io.Writer and output format for SAML subcommands.
type samlWriter struct {
	w      io.Writer
	isJSON bool
}

// writeJSON marshals v as indented JSON to the writer.
func (sw *samlWriter) writeJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(sw.w, string(b))
	return err
}

// writeText writes a plain-text line to the writer.
func (sw *samlWriter) writeText(msg string) error {
	_, err := fmt.Fprintln(sw.w, msg)
	return err
}

// write outputs v as JSON when --output json is active, otherwise plain text.
func (sw *samlWriter) write(v any) error {
	if sw.isJSON {
		return sw.writeJSON(v)
	}
	switch t := v.(type) {
	case map[string]any:
		return sw.writeJSON(t)
	default:
		_, err := fmt.Fprintf(sw.w, "%v\n", v)
		return err
	}
}

// newSAMLWriter returns a writer bound to stdout and the current output mode.
func newSAMLWriter(jsonOut *bool) *samlWriter {
	return &samlWriter{w: os.Stdout, isJSON: *jsonOut}
}

// stubRunE returns a RunE that prints a "not yet implemented" message. It is
// used for leaf commands that are scaffolded but not yet wired to the backend.
func stubRunE(name string, jsonOut *bool) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		w := newSAMLWriter(jsonOut)
		return w.write(map[string]any{
			"command": name,
			"status":  "not yet implemented",
		})
	}
}

// newRedisStore creates a Redis-backed SAML store. It resolves the address
// from the flag, REDIS_ADDR env, or falls back to localhost:6379. The
// returned cleanup function closes the Redis client.
func newRedisStore(addr string) (saml.Store, func(), error) {
	if addr == "" {
		addr = os.Getenv("REDIS_ADDR")
	}
	if addr == "" {
		addr = "localhost:6379"
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	store := saml.NewRedisStore(rdb)
	cleanup := func() { rdb.Close() }
	return store, cleanup, nil
}

// defaultHTTPGetter wraps http.DefaultClient to satisfy the httpGetter
// interface used by fetchMetadata.
type defaultHTTPGetter struct{}

func (defaultHTTPGetter) Get(url string) (*http.Response, error) {
	return http.Get(url) //nolint:gosec // URL is admin-supplied
}
