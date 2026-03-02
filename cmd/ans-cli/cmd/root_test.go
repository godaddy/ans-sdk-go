package cmd

import (
	"testing"
)

func TestBuildRootCmd(t *testing.T) {
	cmd := buildRootCmd()

	if cmd == nil {
		t.Fatal("buildRootCmd() returned nil")
	}

	if cmd.Use != "ans-cli" {
		t.Errorf("Use = %q, want %q", cmd.Use, "ans-cli")
	}

	// Verify all subcommands are registered
	expectedSubcommands := []string{
		"badge",
		"csr-status",
		"events",
		"generate-csr",
		"get-identity-certs",
		"get-server-certs",
		"register",
		"resolve",
		"revoke",
		"search",
		"status",
		"submit-identity-csr",
		"submit-server-csr",
		"verify-acme",
		"verify-dns",
	}

	subCmds := cmd.Commands()
	subCmdNames := make(map[string]bool)
	for _, sub := range subCmds {
		subCmdNames[sub.Name()] = true
	}

	for _, expected := range expectedSubcommands {
		if !subCmdNames[expected] {
			t.Errorf("missing subcommand %q", expected)
		}
	}

	// Verify persistent flags exist
	persistentFlags := []string{"api-key", "base-url", "verbose", "json"}
	for _, flagName := range persistentFlags {
		if cmd.PersistentFlags().Lookup(flagName) == nil {
			t.Errorf("missing persistent flag %q", flagName)
		}
	}
}

func TestInitConfig(_ *testing.T) {
	// initConfig should not panic
	initConfig()
}
