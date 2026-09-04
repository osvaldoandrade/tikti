package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/spf13/cobra"
)

// certOverlapDuration is the window during which both old and new IdP
// signing certificates are accepted after an update. HLD §Q9.
const certOverlapDuration = 24 * time.Hour

func samlIdpUpdateCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var (
		tid          string
		metadataURL  string
		metadataFile string
		attrMapFile  string
	)

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Refresh an existing IdP record with new metadata",
		Long: `Re-fetch metadata from the original URL or accept a new metadata file.
Old signing certificates are preserved for a 24-hour overlap window.
If the new metadata fails to parse the existing record is left untouched.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tid == "" {
				return &cliError{msg: "tenant id required (--tid)", exit: 1}
			}
			if metadataURL == "" && metadataFile == "" {
				return &cliError{msg: "one of --metadata-url or --metadata-file is required", exit: 1}
			}
			if metadataURL != "" && metadataFile != "" {
				return &cliError{msg: "only one of --metadata-url or --metadata-file may be specified", exit: 1}
			}

			prof, err := loadProfile(*profileName)
			if err != nil {
				return err
			}
			token, err := tenantAdministrationAccessToken(prof)
			if err != nil {
				return err
			}

			// ── Step 1: Fetch the existing IdP record ──
			existingResp, err := doJSONWithAPIKey(
				http.MethodGet,
				prof.BaseURL+"/v1/admin/tenants/"+tid+"/saml/idp",
				token,
				prof.ApiKey,
				nil,
			)
			if err != nil {
				return fmt.Errorf("fetch existing IdP record: %w", err)
			}

			// ── Step 2: Read new metadata ──
			raw, err := readMetadata(metadataURL, metadataFile)
			if err != nil {
				return fmt.Errorf("read metadata: %w", err)
			}

			// ── Step 3: Parse — rollback on failure (existing record untouched) ──
			newRec, err := saml.ParseIdPMetadata(raw)
			if err != nil {
				return fmt.Errorf("metadata parse failed, existing record unchanged: %w", err)
			}

			// ── Step 4: Merge old signing certs for 24-hour overlap (HLD §Q9) ──
			oldCerts := extractOldCerts(existingResp)
			merged := mergeCerts(oldCerts, newRec.SigningCerts)
			newRec.SigningCerts = merged
			newRec.TenantID = tid

			// ── Step 5: Optional attribute map ──
			var attrMap map[string][]string
			if attrMapFile != "" {
				attrMap, err = loadAttrMap(attrMapFile)
				if err != nil {
					return fmt.Errorf("load attribute map: %w", err)
				}
				newRec.AttributeMap = attrMap
			} else if existingResp["attributeMap"] != nil {
				// Preserve existing attribute map when not overridden.
				if m, ok := existingResp["attributeMap"].(map[string]any); ok {
					preserved := make(map[string][]string, len(m))
					for k, v := range m {
						if arr, ok := v.([]any); ok {
							strs := make([]string, 0, len(arr))
							for _, elem := range arr {
								if s, ok := elem.(string); ok {
									strs = append(strs, s)
								}
							}
							preserved[k] = strs
						}
					}
					newRec.AttributeMap = preserved
				}
			}

			// ── Step 6: Build payload and PUT ──
			sigB64 := make([]string, len(newRec.SigningCerts))
			for i, c := range newRec.SigningCerts {
				sigB64[i] = base64.StdEncoding.EncodeToString(c)
			}
			encB64 := make([]string, len(newRec.EncryptionCerts))
			for i, c := range newRec.EncryptionCerts {
				encB64[i] = base64.StdEncoding.EncodeToString(c)
			}

			body := map[string]any{
				"tenantId":         tid,
				"entityId":         newRec.EntityID,
				"ssoUrl":           newRec.SSOURL,
				"sloUrl":           newRec.SLOURL,
				"signingCerts":     sigB64,
				"encryptionCerts":  encB64,
				"nameIdFormat":     newRec.NameIDFormat,
				"attributeMap":     newRec.AttributeMap,
				"lastFetched":      newRec.LastFetched.Format(time.RFC3339),
				"certOverlapUntil": time.Now().Add(certOverlapDuration).Format(time.RFC3339),
			}

			resp, err := doJSONWithAPIKey(
				http.MethodPut,
				prof.BaseURL+"/v1/admin/tenants/"+tid+"/saml/idp",
				token,
				prof.ApiKey,
				body,
			)
			if err != nil {
				return fmt.Errorf("update IdP record: %w", err)
			}

			return printResult(*outputJSON, resp)
		},
	}

	cmd.Flags().StringVar(&tid, "tid", "", "Tenant ID (required)")
	cmd.Flags().StringVar(&metadataURL, "metadata-url", "", "URL to fetch IdP metadata XML from")
	cmd.Flags().StringVar(&metadataFile, "metadata-file", "", "Path to local IdP metadata XML file")
	cmd.Flags().StringVar(&attrMapFile, "attr-map", "", "Path to attribute-map JSON file")
	return cmd
}

// readMetadata fetches metadata from a URL or reads it from a file.
func readMetadata(url, file string) ([]byte, error) {
	if file != "" {
		return os.ReadFile(file)
	}
	resp, err := http.Get(url) //nolint:gosec // URL is admin-supplied
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}

// extractOldCerts pulls base64-encoded signing certs from the existing API
// response and decodes them back to DER bytes.
func extractOldCerts(resp map[string]any) [][]byte {
	raw, ok := resp["signingCerts"]
	if !ok {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	var out [][]byte
	for _, v := range arr {
		s, ok := v.(string)
		if !ok {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			continue
		}
		out = append(out, der)
	}
	return out
}

// mergeCerts returns the union of old and new certificate lists (by DER
// bytes). Duplicates are removed so an IdP that re-publishes the same cert
// does not cause bloat.
func mergeCerts(old, new [][]byte) [][]byte {
	seen := make(map[string]struct{}, len(old)+len(new))
	var merged [][]byte

	// New certs first so they appear first in the list.
	for _, c := range new {
		key := string(c)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, c)
	}
	for _, c := range old {
		key := string(c)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, c)
	}
	return merged
}

// loadAttrMap reads a JSON attribute-map file.
func loadAttrMap(path string) (map[string][]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	var m map[string][]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse attribute map: %w", err)
	}
	return m, nil
}
