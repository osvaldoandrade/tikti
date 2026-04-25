package main

import (
	"fmt"
	"os"
	"time"

	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/spf13/cobra"
)

// samlCmd returns the "tikti saml" root command with all subcommand groups
// and leaf operations defined in HLD §17.
func samlCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var (
		configFile string
		redisAddr  string
	)

	cmd := &cobra.Command{
		Use:   "saml",
		Short: "SAML 2.0 federation management",
		Long:  "Manage SAML 2.0 Service-Provider metadata, Identity-Provider registrations, email-domain discovery mappings, and diagnostic helpers.",
	}

	cmd.PersistentFlags().StringVar(&configFile, "config", "", "Path to configuration file")
	cmd.PersistentFlags().StringVar(&redisAddr, "redis-addr", "", "Redis server address (host:port)")

	cmd.AddCommand(samlSPCmd(profileName, outputJSON))
	cmd.AddCommand(samlIdPCmd(profileName, outputJSON))
	cmd.AddCommand(samlTestCmd(profileName, outputJSON))
	cmd.AddCommand(samlDomainCmd(profileName, outputJSON))
	return cmd
}

// --- sp subgroup ---

func samlSPCmd(profileName *string, outputJSON *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sp",
		Short: "Service-Provider operations",
	}
	cmd.AddCommand(samlSPMetadataCmd(profileName, outputJSON))
	cmd.AddCommand(samlSPRotateCmd(profileName, outputJSON))
	return cmd
}

func samlSPMetadataCmd(profileName *string, outputJSON *bool) *cobra.Command {
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

func samlSPRotateCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var (
		prepare bool
		commit  bool
	)
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Two-step SP signing-key rotation",
		RunE:  stubRunE("saml sp rotate", outputJSON),
	}
	cmd.Flags().BoolVar(&prepare, "prepare", false, "Prepare new key (publish both old and new in metadata)")
	cmd.Flags().BoolVar(&commit, "commit", false, "Commit rotation (remove old key)")
	return cmd
}

// --- idp subgroup ---

func samlIdPCmd(profileName *string, outputJSON *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "idp",
		Short: "Identity-Provider registration and inspection",
	}
	cmd.AddCommand(samlIdPRegisterCmd(profileName, outputJSON))
	cmd.AddCommand(samlIdPUpdateCmd(profileName, outputJSON))
	cmd.AddCommand(samlIdPRemoveCmd(profileName, outputJSON))
	cmd.AddCommand(samlIdPListCmd(profileName, outputJSON))
	cmd.AddCommand(samlIdPShowCmd(profileName, outputJSON))
	cmd.AddCommand(samlIdPFetchCmd(profileName, outputJSON))
	return cmd
}

func samlIdPRegisterCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var (
		tid         string
		metadataURL string
		attrMapFile string
	)
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register an IdP for a tenant",
		RunE:  stubRunE("saml idp register", outputJSON),
	}
	cmd.Flags().StringVar(&tid, "tid", "", "Tenant ID")
	cmd.Flags().StringVar(&metadataURL, "metadata-url", "", "IdP metadata URL")
	cmd.Flags().StringVar(&attrMapFile, "attr-map", "", "Path to attribute-mapping file")
	_ = cmd.MarkFlagRequired("tid")
	_ = cmd.MarkFlagRequired("metadata-url")
	return cmd
}

func samlIdPUpdateCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var (
		tid         string
		metadataURL string
		attrMapFile string
	)
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update an existing IdP registration",
		RunE:  stubRunE("saml idp update", outputJSON),
	}
	cmd.Flags().StringVar(&tid, "tid", "", "Tenant ID")
	cmd.Flags().StringVar(&metadataURL, "metadata-url", "", "IdP metadata URL")
	cmd.Flags().StringVar(&attrMapFile, "attr-map", "", "Path to attribute-mapping file")
	_ = cmd.MarkFlagRequired("tid")
	return cmd
}

func samlIdPRemoveCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var tid string
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove an IdP registration",
		RunE:  stubRunE("saml idp remove", outputJSON),
	}
	cmd.Flags().StringVar(&tid, "tid", "", "Tenant ID")
	_ = cmd.MarkFlagRequired("tid")
	return cmd
}

func samlIdPListCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var tid string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registered IdPs",
		RunE:  stubRunE("saml idp list", outputJSON),
	}
	cmd.Flags().StringVar(&tid, "tid", "", "Tenant ID (optional, lists all if omitted)")
	return cmd
}

func samlIdPShowCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var tid string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show details of a single IdP",
		RunE:  stubRunE("saml idp show", outputJSON),
	}
	cmd.Flags().StringVar(&tid, "tid", "", "Tenant ID")
	_ = cmd.MarkFlagRequired("tid")
	return cmd
}

func samlIdPFetchCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var tid string
	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Force metadata refresh for an IdP",
		RunE:  stubRunE("saml idp fetch", outputJSON),
	}
	cmd.Flags().StringVar(&tid, "tid", "", "Tenant ID")
	_ = cmd.MarkFlagRequired("tid")
	return cmd
}

// --- test command ---

func samlTestCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var (
		tid   string
		email string
	)
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Emit an AuthnRequest URL for manual validation",
		RunE:  stubRunE("saml test", outputJSON),
	}
	cmd.Flags().StringVar(&tid, "tid", "", "Tenant ID")
	cmd.Flags().StringVar(&email, "email", "", "User email")
	_ = cmd.MarkFlagRequired("tid")
	_ = cmd.MarkFlagRequired("email")
	return cmd
}

// --- domain subgroup ---

func samlDomainCmd(profileName *string, outputJSON *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain",
		Short: "Email-domain discovery mappings",
	}
	cmd.AddCommand(samlDomainAddCmd(profileName, outputJSON))
	cmd.AddCommand(samlDomainRemoveCmd(profileName, outputJSON))
	return cmd
}

func samlDomainAddCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var (
		tid    string
		domain string
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Map an email domain to a tenant for SAML discovery",
		RunE:  stubRunE("saml domain add", outputJSON),
	}
	cmd.Flags().StringVar(&tid, "tid", "", "Tenant ID")
	cmd.Flags().StringVar(&domain, "domain", "", "Email domain (e.g. example.com)")
	_ = cmd.MarkFlagRequired("tid")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}

func samlDomainRemoveCmd(profileName *string, outputJSON *bool) *cobra.Command {
	var domain string
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove an email-domain mapping",
		RunE:  stubRunE("saml domain remove", outputJSON),
	}
	cmd.Flags().StringVar(&domain, "domain", "", "Email domain (e.g. example.com)")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}
