package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/godaddy/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/spf13/cobra"
)

func buildVerifyDNSCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify-dns <agentId>",
		Short: "Verify DNS records are configured",
		Long: `Verifies that all required DNS records (HTTPS, TLSA, _ans, _ans-badge) have been
configured correctly. This is the final step for external domain registration.`,
		Args: cobra.ExactArgs(1),
		RunE: runVerifyDNS,
	}
}

func runVerifyDNS(_ *cobra.Command, args []string) error {
	agentID := args[0]

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.APIKey == "" {
		return errors.New("API key is required. Set --api-key flag or ANS_API_KEY environment variable")
	}

	// Create client and verify DNS
	c, err := createClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx := context.Background()
	result, err := c.VerifyDNS(ctx, agentID)
	if err != nil {
		return fmt.Errorf("DNS verification failed: %w", err)
	}

	// Output result
	if cfg.JSON {
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(os.Stdout, string(jsonData))
	} else {
		fmt.Fprintln(os.Stdout, "\n✓ DNS records verified successfully")
		if result.Status != "" {
			fmt.Fprintf(os.Stdout, "Status: %s\n", result.Status)
		}
		if result.Phase != "" {
			fmt.Fprintf(os.Stdout, "Phase: %s\n", result.Phase)
		}

		if len(result.CompletedSteps) > 0 {
			fmt.Fprintln(os.Stdout, "\nCompleted steps:")
			for _, step := range result.CompletedSteps {
				fmt.Fprintf(os.Stdout, "  ✓ %s\n", step)
			}
		}

		fmt.Fprintln(os.Stdout, "\nAgent registration is now active!")
		fmt.Fprintln(os.Stdout, "Use 'ans-cli status "+agentID+"' to view full details.")
		fmt.Fprintln(os.Stdout)
	}

	return nil
}
