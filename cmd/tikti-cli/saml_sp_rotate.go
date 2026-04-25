package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/spf13/cobra"
	"github.com/vmihailenco/msgpack/v5"

	rkeys "github.com/osvaldoandrade/tikti/internal/redis"
	"github.com/osvaldoandrade/tikti/internal/saml"
)

// rotationState is persisted in Redis at saml:sp:rotation during a 2-step
// SP key rotation. It records the old certificate so that --commit can drop
// it from the published metadata.
type rotationState struct {
	OldCertPEM []byte    `msgpack:"old_cert_pem"`
	NewCertPEM []byte    `msgpack:"new_cert_pem"`
	PreparedAt time.Time `msgpack:"prepared_at"`
}

// samlCmd is the top-level `saml` command group.
func samlCmd(outputJSON *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "saml",
		Short: "SAML administration commands",
	}
	cmd.AddCommand(spCmd(outputJSON))
	return cmd
}

// spCmd is the `saml sp` command group.
func spCmd(outputJSON *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sp",
		Short: "SP key and metadata operations",
	}
	cmd.AddCommand(spRotateCmd(outputJSON))
	return cmd
}

// spRotateCmd builds the `saml sp rotate` CLI sub-command tree.
// It requires --redis-addr, --signing-key, --signing-cert, and the SP
// metadata parameters (--entity-id, --acs-url, --slo-url).
func spRotateCmd(outputJSON *bool) *cobra.Command {
	var (
		redisAddr  string
		keyPath    string
		certPath   string
		entityID   string
		acsURL     string
		sloURL     string
		outFile    string
		keyBits    int
		prepare    bool
		commit     bool
	)

	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "2-step SP signing key rotation (--prepare then --commit)",
		Long: `Performs a 2-step SP signing key rotation per HLD §13.

Step 1 — tikti saml sp rotate --prepare
  Generates a new signing key/cert, publishes SP metadata with both the
  old and new certificates, and stores the rotation state in Redis.

Step 2 — tikti saml sp rotate --commit
  Publishes SP metadata with only the new certificate and removes the
  rotation state from Redis.

See docs/saml/key-rotation.md for the full procedure.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if prepare == commit {
				return &cliError{msg: "exactly one of --prepare or --commit is required", exit: 1}
			}

			rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
			defer rdb.Close()

			ctx := context.Background()

			if prepare {
				return rotatePrepare(ctx, rdb, keyPath, certPath, entityID, acsURL, sloURL, outFile, keyBits, *outputJSON)
			}
			return rotateCommit(ctx, rdb, keyPath, certPath, entityID, acsURL, sloURL, outFile, *outputJSON)
		},
	}

	cmd.Flags().StringVar(&redisAddr, "redis-addr", "localhost:6379", "Redis address")
	cmd.Flags().StringVar(&keyPath, "signing-key", "sp.key", "Path to SP signing private key PEM")
	cmd.Flags().StringVar(&certPath, "signing-cert", "sp.crt", "Path to SP signing certificate PEM")
	cmd.Flags().StringVar(&entityID, "entity-id", "", "SP entity ID")
	cmd.Flags().StringVar(&acsURL, "acs-url", "", "Assertion Consumer Service URL")
	cmd.Flags().StringVar(&sloURL, "slo-url", "", "Single Logout Service URL")
	cmd.Flags().StringVar(&outFile, "out", "", "Write metadata XML to file (default: stdout)")
	cmd.Flags().IntVar(&keyBits, "key-bits", 2048, "RSA key size for new key (2048 or 3072)")
	cmd.Flags().BoolVar(&prepare, "prepare", false, "Step 1: publish metadata with old + new certs")
	cmd.Flags().BoolVar(&commit, "commit", false, "Step 2: publish metadata with new cert only")

	return cmd
}

// rotatePrepare generates a new RSA key pair, writes it to disk alongside the
// current files (suffixed .new), publishes SP metadata containing both certs,
// and stores rotation state in Redis.
func rotatePrepare(
	ctx context.Context,
	rdb *redis.Client,
	keyPath, certPath, entityID, acsURL, sloURL, outFile string,
	keyBits int,
	jsonOut bool,
) error {
	// Read old certificate.
	oldCertPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read old cert: %w", err)
	}

	// Generate new key pair.
	newKeyPEM, newCertPEM, err := generateSelfSignedKeyPair(keyBits)
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}

	// Write new key/cert to .new files so the admin can inspect and later
	// move them into place.
	if err := os.WriteFile(keyPath+".new", newKeyPEM, 0o600); err != nil {
		return fmt.Errorf("write new key: %w", err)
	}
	if err := os.WriteFile(certPath+".new", newCertPEM, 0o600); err != nil {
		return fmt.Errorf("write new cert: %w", err)
	}

	// Build metadata with both certs (old + new).
	cfg := saml.SPMetadataConfig{
		EntityID:             entityID,
		ACSURL:               acsURL,
		SLOURL:               sloURL,
		SigningCertPEM:        oldCertPEM,
		EncryptCertPEM:       oldCertPEM, // encryption uses old cert in prepare phase; updated in commit
		ExtraSigningCertPEMs: [][]byte{newCertPEM},
		ValidUntil:           time.Now().AddDate(1, 0, 0),
	}
	metaXML, err := saml.SPMetadataFromConfig(cfg)
	if err != nil {
		return fmt.Errorf("build metadata: %w", err)
	}

	// Persist rotation state in Redis.
	state := rotationState{
		OldCertPEM: oldCertPEM,
		NewCertPEM: newCertPEM,
		PreparedAt: time.Now().UTC(),
	}
	data, err := msgpack.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	if err := rdb.Set(ctx, rkeys.SAMLSPRotationKey, data, 0).Err(); err != nil {
		return fmt.Errorf("store rotation state: %w", err)
	}

	// Output metadata.
	if err := writeOutput(outFile, metaXML); err != nil {
		return err
	}

	return printResult(jsonOut, map[string]any{
		"status":    "prepared",
		"newKey":    keyPath + ".new",
		"newCert":   certPath + ".new",
		"certs":     2,
		"message":   "Metadata published with 2 signing certs. Wait for IdPs to refresh, then run --commit.",
	})
}

// rotateCommit reads the rotation state from Redis, publishes SP metadata
// with only the new certificate, and cleans up the Redis key.
func rotateCommit(
	ctx context.Context,
	rdb *redis.Client,
	keyPath, certPath, entityID, acsURL, sloURL, outFile string,
	jsonOut bool,
) error {
	// Load rotation state from Redis.
	raw, err := rdb.Get(ctx, rkeys.SAMLSPRotationKey).Bytes()
	if errors.Is(err, redis.Nil) {
		return &cliError{
			msg:  "no pending rotation found — run --prepare first",
			exit: 1,
		}
	}
	if err != nil {
		return fmt.Errorf("read rotation state: %w", err)
	}

	var state rotationState
	if err := msgpack.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("unmarshal rotation state: %w", err)
	}

	// Build metadata with only the new cert.
	cfg := saml.SPMetadataConfig{
		EntityID:       entityID,
		ACSURL:         acsURL,
		SLOURL:         sloURL,
		SigningCertPEM: state.NewCertPEM,
		EncryptCertPEM: state.NewCertPEM,
		ValidUntil:     time.Now().AddDate(1, 0, 0),
	}
	metaXML, err := saml.SPMetadataFromConfig(cfg)
	if err != nil {
		return fmt.Errorf("build metadata: %w", err)
	}

	// Remove rotation state from Redis.
	if err := rdb.Del(ctx, rkeys.SAMLSPRotationKey).Err(); err != nil {
		return fmt.Errorf("delete rotation state: %w", err)
	}

	// Output metadata.
	if err := writeOutput(outFile, metaXML); err != nil {
		return err
	}

	return printResult(jsonOut, map[string]any{
		"status":     "committed",
		"certs":      1,
		"preparedAt": state.PreparedAt.Format(time.RFC3339),
		"message":    "Rotation complete. Metadata now contains only the new certificate.",
	})
}

// writeOutput writes data to a file or stdout.
func writeOutput(path string, data []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// generateSelfSignedKeyPair generates a new RSA key pair and self-signed
// X.509 certificate valid for 1 year with CN=tikti-sp.
func generateSelfSignedKeyPair(bits int) (keyPEM, certPEM []byte, err error) {
	if bits < 2048 {
		return nil, nil, fmt.Errorf("RSA key size must be at least 2048 bits, got %d", bits)
	}

	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("generate RSA key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tikti-sp"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return keyPEM, certPEM, nil
}
