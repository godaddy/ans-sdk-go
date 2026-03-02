package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/godaddy/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/godaddy/ans-sdk-go/models"
	"github.com/spf13/cobra"
)

func buildSearchCmd() *cobra.Command {
	var (
		searchName    string
		searchHost    string
		searchVersion string
		searchLimit   int
		searchOffset  int
	)

	cmd := &cobra.Command{
		Use:   "search",
		Short: "Search for registered agents",
		Long: `Search the Agent Name Service registry using flexible criteria such as
agent name, host domain, and version ranges.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runSearchWithParams(searchName, searchHost, searchVersion, searchLimit, searchOffset)
		},
	}

	cmd.Flags().StringVar(&searchName, "name", "", "Agent display name (partial matching supported)")
	cmd.Flags().StringVar(&searchHost, "host", "", "Agent host domain (partial matching supported)")
	cmd.Flags().StringVar(&searchVersion, "version", "", "Agent version (flexible matching supported)")
	cmd.Flags().IntVar(&searchLimit, "limit", DefaultSearchLimit, "Maximum number of results (default: 20, max: 100)")
	cmd.Flags().IntVar(&searchOffset, "offset", 0, "Number of results to skip for pagination")

	return cmd
}

func runSearchWithParams(searchName, searchHost, searchVersion string, searchLimit, searchOffset int) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.APIKey == "" {
		return errors.New("API key is required. Set --api-key flag or ANS_API_KEY environment variable")
	}

	// Validate search criteria
	if searchName == "" && searchHost == "" && searchVersion == "" {
		return errors.New("at least one search criteria is required (--name, --host, or --version)")
	}

	// Create client and search
	c, err := createClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx := context.Background()
	result, err := c.SearchAgents(ctx, searchName, searchHost, searchVersion, searchLimit, searchOffset)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	// Output result
	if cfg.JSON {
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(os.Stdout, string(jsonData))
	} else {
		printSearchResults(result)
	}

	return nil
}

func printSearchResults(result *models.AgentSearchResponse) {
	printSearchHeader(result)

	if len(result.Agents) == 0 {
		fmt.Fprintln(os.Stdout, "No agents found matching the search criteria.")
		return
	}

	for i, agent := range result.Agents {
		printAgentSummary(i+1, &agent)
		if i < len(result.Agents)-1 {
			fmt.Fprintln(os.Stdout)
		}
	}

	printPaginationHint(result)
	fmt.Fprintln(os.Stdout)
}

func printSearchHeader(result *models.AgentSearchResponse) {
	fmt.Fprintln(os.Stdout, "\nSearch Results")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthWide))
	fmt.Fprintf(os.Stdout, "Total matches: %d | Showing: %d | Limit: %d | Offset: %d | More: %v\n\n",
		result.TotalCount, result.ReturnedCount, result.Limit, result.Offset, result.HasMore)
}

func printAgentSummary(num int, agent *models.AgentSearchResult) {
	fmt.Fprintf(os.Stdout, "%d. %s\n", num, agent.AgentDisplayName)
	fmt.Fprintf(os.Stdout, "   ANS Name: %s\n", agent.ANSName)
	fmt.Fprintf(os.Stdout, "   Host:     %s\n", agent.AgentHost)
	fmt.Fprintf(os.Stdout, "   Version:  %s\n", agent.Version)

	if agent.AgentDescription != "" {
		fmt.Fprintf(os.Stdout, "   Description: %s\n", agent.AgentDescription)
	}

	if len(agent.Endpoints) > 0 {
		protocols := make([]string, len(agent.Endpoints))
		for j, endpoint := range agent.Endpoints {
			protocols[j] = endpoint.Protocol
		}
		fmt.Fprintf(os.Stdout, "   Endpoints: %d (%s)\n", len(agent.Endpoints), strings.Join(protocols, ", "))
	}

	if !agent.RegistrationTimestamp.IsZero() {
		fmt.Fprintf(os.Stdout, "   Registered: %s\n", agent.RegistrationTimestamp.Format("2006-01-02 15:04:05"))
	}

	for _, link := range agent.Links {
		if link.Rel == "agent-details" || link.Rel == "self" {
			fmt.Fprintf(os.Stdout, "   Details: %s\n", link.Href)
			break
		}
	}
}

func printPaginationHint(result *models.AgentSearchResponse) {
	if result.HasMore {
		nextOffset := result.Offset + result.ReturnedCount
		fmt.Fprintf(os.Stdout, "\nMore results available. Use --offset %d to see the next page.\n", nextOffset)
	}
}
