package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func newTestRoot() *cobra.Command {
	root := &cobra.Command{Use: "tikti"}
	root.AddCommand(samlCmd())
	return root
}

func TestCLI_SPMetadata_Stdout(t *testing.T) {
	golden, err := os.ReadFile("../../internal/saml/testdata/sp_metadata.xml")
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}

	buf := new(bytes.Buffer)
	root := newTestRoot()
	root.SetOut(buf)
	root.SetArgs([]string{
		"saml", "sp", "metadata",
		"--entity-id", "https://auth.example.com/saml",
		"--acs-url", "https://auth.example.com/saml/acs",
		"--slo-url", "https://auth.example.com/saml/slo",
		"--signing-cert", "../../internal/saml/testdata/sp_signing.crt",
		"--encryption-cert", "../../internal/saml/testdata/sp_encryption.crt",
		"--valid-until", "2027-04-24",
	})

	if err := root.Execute(); err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if !bytes.Equal(buf.Bytes(), golden) {
		t.Fatalf("output differs from golden.\ngot:\n%s\nwant:\n%s", buf.String(), string(golden))
	}
}

func TestCLI_SPMetadata_OutFlag(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "metadata.xml")

	root := newTestRoot()
	root.SetArgs([]string{
		"saml", "sp", "metadata",
		"--entity-id", "https://auth.example.com/saml",
		"--acs-url", "https://auth.example.com/saml/acs",
		"--slo-url", "https://auth.example.com/saml/slo",
		"--signing-cert", "../../internal/saml/testdata/sp_signing.crt",
		"--encryption-cert", "../../internal/saml/testdata/sp_encryption.crt",
		"--valid-until", "2027-04-24",
		"--out", outPath,
	})

	if err := root.Execute(); err != nil {
		t.Fatalf("command failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}

	golden, err := os.ReadFile("../../internal/saml/testdata/sp_metadata.xml")
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}

	if !bytes.Equal(data, golden) {
		t.Fatalf("output file differs from golden.\ngot:\n%s\nwant:\n%s", string(data), string(golden))
	}
}
