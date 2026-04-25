package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
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
