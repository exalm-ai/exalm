package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	exalmstore "github.com/exalm-ai/exalm/internal/store"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// globalDB is set by initStore() and shared across commands for usage tracking
// and the `exalm usage` report. Nil when the DB could not be opened.
var globalDB *sql.DB

// usageTrackingLLM wraps any plugin.LLMClient and records token counts for
// every Complete() call to the llm_usage SQLite table.
type usageTrackingLLM struct {
	inner      plugin.LLMClient
	db         *sql.DB
	pluginName string
	subName    string
}

func (u *usageTrackingLLM) Name() string { return u.inner.Name() }

// Complete delegates to the underlying client and records token usage on success.
func (u *usageTrackingLLM) Complete(ctx context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	resp, err := u.inner.Complete(ctx, req)
	if err == nil && u.db != nil && (resp.InputTokens > 0 || resp.OutputTokens > 0) {
		_ = exalmstore.RecordUsage(u.db, exalmstore.UsageRecord{
			RecordedAt:   time.Now().UTC(),
			Provider:     u.inner.Name(),
			Plugin:       u.pluginName,
			Subcommand:   u.subName,
			InputTokens:  resp.InputTokens,
			OutputTokens: resp.OutputTokens,
		})
	}
	return resp, err
}

// wrapWithUsageTracking wraps llmClient with usage tracking when globalDB is set.
// Returns llmClient unchanged if globalDB is nil (DB unavailable).
func wrapWithUsageTracking(llmClient plugin.LLMClient, pluginName, subName string) plugin.LLMClient {
	if globalDB == nil {
		return llmClient
	}
	return &usageTrackingLLM{
		inner:      llmClient,
		db:         globalDB,
		pluginName: pluginName,
		subName:    subName,
	}
}

// newUsageCmd returns the `exalm usage` command subtree.
//
//	exalm usage report [--days N]
func newUsageCmd() *cobra.Command {
	usageRoot := &cobra.Command{
		Use:   "usage",
		Short: "Show LLM token usage for analyses run with exalm",
	}

	var days int
	report := &cobra.Command{
		Use:   "report",
		Short: "Print a token usage summary grouped by provider/plugin/subcommand",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runUsageReport(days)
		},
	}
	report.Flags().IntVar(&days, "days", 30, "reporting window in days")
	usageRoot.AddCommand(report)

	return usageRoot
}

// runUsageReport fetches and formats the usage table from SQLite.
func runUsageReport(days int) error {
	if globalDB == nil {
		fmt.Println("No usage data: SQLite database is unavailable.")
		return nil
	}

	summaries, err := exalmstore.QueryUsageSummary(globalDB, days)
	if err != nil {
		return fmt.Errorf("usage report: %w", err)
	}
	inpTotal, outTotal, grandTotal, err := exalmstore.QueryUsageTotals(globalDB, days)
	if err != nil {
		return fmt.Errorf("usage totals: %w", err)
	}

	fmt.Printf("LLM Token Usage — last %d days\n", days)
	fmt.Println(strings.Repeat("─", 72))

	if len(summaries) == 0 {
		fmt.Println("No usage recorded in this window.")
		return nil
	}

	// Column widths.
	const (
		wProv = 12
		wPlug = 14
		wSub  = 14
		wCall = 6
		wTok  = 10
	)
	header := fmt.Sprintf("%-*s %-*s %-*s %*s %*s %*s %*s",
		wProv, "Provider",
		wPlug, "Plugin",
		wSub, "Subcommand",
		wCall, "Calls",
		wTok, "Input",
		wTok, "Output",
		wTok, "Total",
	)
	fmt.Println(header)
	fmt.Println(strings.Repeat("─", len(header)))

	for _, s := range summaries {
		fmt.Printf("%-*s %-*s %-*s %*d %*s %*s %*s\n",
			wProv, s.Provider,
			wPlug, s.Plugin,
			wSub, s.Subcommand,
			wCall, s.Calls,
			wTok, formatTokens(s.InputTokens),
			wTok, formatTokens(s.OutputTokens),
			wTok, formatTokens(s.TotalTokens),
		)
	}

	fmt.Println(strings.Repeat("─", len(header)))
	fmt.Printf("%-*s %-*s %-*s %*s %*s %*s %*s\n",
		wProv, "TOTAL",
		wPlug, "",
		wSub, "",
		wCall, "",
		wTok, formatTokens(inpTotal),
		wTok, formatTokens(outTotal),
		wTok, formatTokens(grandTotal),
	)
	return nil
}

// formatTokens formats an integer token count with thousands separators.
func formatTokens(n int) string {
	if n == 0 {
		return "0"
	}
	s := fmt.Sprintf("%d", n)
	// Insert commas every 3 digits from the right.
	out := make([]byte, 0, len(s)+len(s)/3)
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c)) //nolint:gosec // G115: c is always an ASCII digit '0'-'9', safe to truncate
	}
	return string(out)
}
