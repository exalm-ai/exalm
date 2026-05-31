package store

import (
	"database/sql"
	"fmt"
	"math/rand"
	"time"
)

// UsageRecord holds the token counts for a single LLM completion call.
type UsageRecord struct {
	// ID is auto-generated if empty.
	ID           string
	RecordedAt   time.Time
	Provider     string // "claude", "openai", "ollama", "openrouter"
	Model        string // e.g. "claude-sonnet-4-6"
	Plugin       string // e.g. "k8s", "logs"
	Subcommand   string // e.g. "analyze", "summarize"
	InputTokens  int
	OutputTokens int
}

// UsageSummary aggregates usage across calls with the same provider/plugin/subcommand.
type UsageSummary struct {
	Provider     string
	Plugin       string
	Subcommand   string
	Calls        int
	InputTokens  int
	OutputTokens int
	TotalTokens  int
}

// RecordUsage inserts a token-usage row into the llm_usage table.
// If r.ID is empty a random ID is generated. If r.RecordedAt is zero the
// current UTC time is used. Non-fatal errors (e.g. DB unavailable) are
// returned so the caller can log a warning without aborting the analysis.
func RecordUsage(db *sql.DB, r UsageRecord) error {
	if db == nil {
		return nil
	}
	if r.ID == "" {
		r.ID = fmt.Sprintf("usage-%s-%06d",
			time.Now().UTC().Format("20060102-150405"),
			rand.Intn(1_000_000), //nolint:gosec // G404: non-cryptographic ID generation, security irrelevant here
		)
	}
	if r.RecordedAt.IsZero() {
		r.RecordedAt = time.Now().UTC()
	}
	_, err := db.Exec(
		`INSERT INTO llm_usage(id,recorded_at,provider,model,plugin,subcommand,input_tokens,output_tokens)
		 VALUES(?,?,?,?,?,?,?,?)`,
		r.ID,
		r.RecordedAt.UTC().Format(time.RFC3339Nano),
		r.Provider, r.Model, r.Plugin, r.Subcommand,
		r.InputTokens, r.OutputTokens,
	)
	if err != nil {
		return fmt.Errorf("store: record usage: %w", err)
	}
	return nil
}

// QueryUsageSummary returns aggregated token usage grouped by provider, plugin,
// and subcommand for the last n days. The result is ordered by total token
// consumption descending. An empty slice is returned if there is no usage data.
func QueryUsageSummary(db *sql.DB, days int) ([]UsageSummary, error) {
	if db == nil {
		return nil, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339Nano)
	rows, err := db.Query(`
		SELECT
			provider,
			plugin,
			subcommand,
			COUNT(*)             AS calls,
			SUM(input_tokens)    AS inp,
			SUM(output_tokens)   AS out,
			SUM(input_tokens + output_tokens) AS total
		FROM llm_usage
		WHERE recorded_at >= ?
		GROUP BY provider, plugin, subcommand
		ORDER BY total DESC
	`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("store: query usage: %w", err)
	}
	defer rows.Close()

	var summaries []UsageSummary
	for rows.Next() {
		var s UsageSummary
		if err := rows.Scan(&s.Provider, &s.Plugin, &s.Subcommand,
			&s.Calls, &s.InputTokens, &s.OutputTokens, &s.TotalTokens); err != nil {
			return nil, fmt.Errorf("store: scan usage: %w", err)
		}
		summaries = append(summaries, s)
	}
	return summaries, rows.Err()
}

// QueryUsageTotals returns the grand-total input, output, and total token
// counts for the last n days across all providers, plugins, and subcommands.
func QueryUsageTotals(db *sql.DB, days int) (input, output, total int, err error) {
	if db == nil {
		return 0, 0, 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339Nano)
	row := db.QueryRow(`
		SELECT
			COALESCE(SUM(input_tokens), 0),
			COALESCE(SUM(output_tokens), 0),
			COALESCE(SUM(input_tokens + output_tokens), 0)
		FROM llm_usage
		WHERE recorded_at >= ?
	`, cutoff)
	err = row.Scan(&input, &output, &total)
	return
}
