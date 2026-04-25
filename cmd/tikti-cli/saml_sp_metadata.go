package main

import (
	"fmt"
	"os"
	"time"

	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/spf13/cobra"
)

func samlCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "saml",
		Short: "SAML commands",
	}
	sp := &cobra.Command{
		Use:   "sp",
		Short: "Service Provider commands",
	}
	sp.AddCommand(samlSPMetadataCmd())
	cmd.AddCommand(sp)
	return cmd
}

func samlSPMetadataCmd() *cobra.Command {
	var (
		entityID       string
		acsURL         string
		sloURL         string
		signingCert    string
		encryptionCert string
		validUntil     string
		outFile        string
	)

	cmd := &cobra.Command{
		Use:   "metadata",
		Short: "Emit SP metadata XML",
		RunE: func(cmd *cobra.Command, args []string) error {
			sigCertPEM, err := os.ReadFile(signingCert)
			if err != nil {
				return &cliError{msg: fmt.Sprintf("read signing cert: %v", err), exit: 1}
			}

			encCertPath := encryptionCert
			if encCertPath == "" {
				encCertPath = signingCert
			}
			encCertPEM, err := os.ReadFile(encCertPath)
			if err != nil {
				return &cliError{msg: fmt.Sprintf("read encryption cert: %v", err), exit: 1}
			}

			vu := time.Now().AddDate(1, 0, 0).UTC().Truncate(24 * time.Hour)
			if validUntil != "" {
				vu, err = time.Parse("2006-01-02", validUntil)
				if err != nil {
					return &cliError{msg: fmt.Sprintf("invalid valid-until: %v", err), exit: 1}
				}
			}

			cfg := saml.SPMetadataConfig{
				EntityID:       entityID,
				ACSURL:         acsURL,
				SLOURL:         sloURL,
				SigningCertPEM: sigCertPEM,
				EncryptCertPEM: encCertPEM,
				ValidUntil:     vu,
			}

			meta, err := saml.SPMetadataFromConfig(cfg)
			if err != nil {
				return &cliError{msg: fmt.Sprintf("generate metadata: %v", err), exit: 1}
			}

			if outFile != "" {
				if err := os.WriteFile(outFile, meta, 0o644); err != nil {
					return &cliError{msg: fmt.Sprintf("write file: %v", err), exit: 1}
				}
				return nil
			}

			if _, err := cmd.OutOrStdout().Write(meta); err != nil {
				return &cliError{msg: fmt.Sprintf("write stdout: %v", err), exit: 1}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&entityID, "entity-id", "", "SP entity ID")
	cmd.Flags().StringVar(&acsURL, "acs-url", "", "Assertion Consumer Service URL")
	cmd.Flags().StringVar(&sloURL, "slo-url", "", "Single Logout URL")
	cmd.Flags().StringVar(&signingCert, "signing-cert", "", "Path to signing certificate PEM")
	cmd.Flags().StringVar(&encryptionCert, "encryption-cert", "", "Path to encryption certificate PEM")
	cmd.Flags().StringVar(&validUntil, "valid-until", "", "Metadata valid-until date (YYYY-MM-DD)")
	cmd.Flags().StringVar(&outFile, "out", "", "Output file path (default: stdout)")
	_ = cmd.MarkFlagRequired("entity-id")
	_ = cmd.MarkFlagRequired("acs-url")
	_ = cmd.MarkFlagRequired("signing-cert")

	return cmd
}
