package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/go-redis/redis/v8"
	"github.com/spf13/cobra"

	"github.com/osvaldoandrade/tikti/internal/saml"
)

// httpGetter abstracts HTTP GET for testability.
type httpGetter interface {
	Get(url string) (*http.Response, error)
}

// registerIdPOptions holds the parameters for IdP registration.
type registerIdPOptions struct {
	TID          string
	MetadataURL  string
	MetadataFile string
	AttrMapFile  string
	HTTPClient   httpGetter
}

// registerIdP is the testable core of the "saml idp register" command.
// It fetches or reads metadata, parses and validates it, checks for
// duplicate tenant IDs, applies an optional attribute map, and persists
// the record via the provided store.
func registerIdP(ctx context.Context, store saml.Store, opts registerIdPOptions) (*saml.IdPRecord, error) {
	if opts.TID == "" {
		return nil, errors.New("--tid is required")
	}
	if opts.MetadataURL == "" && opts.MetadataFile == "" {
		return nil, errors.New("--metadata-url or --metadata-file is required")
	}

	// Reject duplicate tenant ID.
	_, err := store.GetIdP(ctx, opts.TID)
	if err == nil {
		return nil, fmt.Errorf("IdP already registered for tenant %q", opts.TID)
	}
	if !errors.Is(err, saml.ErrIdPNotFound) {
		return nil, fmt.Errorf("checking existing IdP: %w", err)
	}

	// Obtain raw metadata bytes.
	var raw []byte
	if opts.MetadataFile != "" {
		raw, err = os.ReadFile(opts.MetadataFile)
	} else {
		raw, err = fetchMetadata(opts.HTTPClient, opts.MetadataURL)
	}
	if err != nil {
		return nil, err
	}

	// Parse and validate.
	rec, err := saml.ParseIdPMetadata(raw)
	if err != nil {
		return nil, err
	}
	rec.TenantID = opts.TID

	// Apply optional attribute map.
	if opts.AttrMapFile != "" {
		mapData, err := os.ReadFile(opts.AttrMapFile)
		if err != nil {
			return nil, fmt.Errorf("reading attribute map: %w", err)
		}
		var attrMap map[string][]string
		if err := json.Unmarshal(mapData, &attrMap); err != nil {
			return nil, fmt.Errorf("parsing attribute map: %w", err)
		}
		rec.AttributeMap = attrMap
	}

	// Persist.
	if err := store.PutIdP(ctx, *rec); err != nil {
		return nil, err
	}

	return rec, nil
}

// fetchMetadata downloads IdP metadata from the given URL.
func fetchMetadata(client httpGetter, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching metadata: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// samlCmd returns the top-level "saml" command with its sub-tree.
func samlCmd(profileName *string, outputJSON *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "saml", Short: "SAML operations"}

	idpCmd := &cobra.Command{Use: "idp", Short: "IdP operations"}

	var tid, metadataURL, metadataFile, attrMapFile, redisAddr string

	register := &cobra.Command{
		Use:   "register",
		Short: "Register an IdP for a tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			if redisAddr == "" {
				redisAddr = os.Getenv("REDIS_ADDR")
			}
			if redisAddr == "" {
				redisAddr = "localhost:6379"
			}

			rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
			defer rdb.Close()
			store := saml.NewRedisStore(rdb)

			opts := registerIdPOptions{
				TID:          tid,
				MetadataURL:  metadataURL,
				MetadataFile: metadataFile,
				AttrMapFile:  attrMapFile,
				HTTPClient:   http.DefaultClient,
			}

			rec, err := registerIdP(context.Background(), store, opts)
			if err != nil {
				return err
			}

			report := map[string]any{
				"tenant_id":   rec.TenantID,
				"entity_id":   rec.EntityID,
				"sso_url":     rec.SSOURL,
				"slo_url":     rec.SLOURL,
				"name_id_fmt": rec.NameIDFormat,
				"num_signing_certs":    len(rec.SigningCerts),
				"num_encryption_certs": len(rec.EncryptionCerts),
				"attribute_map":        rec.AttributeMap,
				"last_fetched":         rec.LastFetched,
			}
			return printResult(*outputJSON, report)
		},
	}

	register.Flags().StringVar(&tid, "tid", "", "Tenant ID (required)")
	register.Flags().StringVar(&metadataURL, "metadata-url", "", "IdP metadata URL")
	register.Flags().StringVar(&metadataFile, "metadata-file", "", "IdP metadata file path")
	register.Flags().StringVar(&attrMapFile, "attr-map", "", "Attribute map JSON file")
	register.Flags().StringVar(&redisAddr, "redis", "", "Redis address (default: REDIS_ADDR env or localhost:6379)")

	idpCmd.AddCommand(register)
	cmd.AddCommand(idpCmd)
	return cmd
}
