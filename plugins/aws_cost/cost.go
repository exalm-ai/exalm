package aws_cost

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// MaxInputBytes caps the Cost Explorer payload sent to the LLM.
const MaxInputBytes = 200 * 1024

// CostReport is the structure returned by `aws ce get-cost-and-usage`.
type CostReport struct {
	ResultsByTime []PeriodResult `json:"ResultsByTime"`
}

// PeriodResult holds cost data for a single billing period.
type PeriodResult struct {
	TimePeriod TimePeriod        `json:"TimePeriod"`
	Total      map[string]Amount `json:"Total"`
	Groups     []Group           `json:"Groups"`
	Estimated  bool              `json:"Estimated"`
}

// TimePeriod is a start/end date pair (YYYY-MM-DD).
type TimePeriod struct {
	Start string `json:"Start"`
	End   string `json:"End"`
}

// Group is one service's cost within a period.
type Group struct {
	Keys    []string          `json:"Keys"`
	Metrics map[string]Amount `json:"Metrics"`
}

// Amount is a cost value with currency unit.
type Amount struct {
	Amount string `json:"Amount"`
	Unit   string `json:"Unit"`
}

// ServiceCost holds parsed cost data for a single service per period.
type ServiceCost struct {
	Service string
	Amount  float64
	Unit    string
}

// PeriodSummary is the parsed, sorted summary for one billing period.
type PeriodSummary struct {
	Start     string
	End       string
	Total     float64
	Unit      string
	Estimated bool
	Services  []ServiceCost
}

// CostAnomaly is a detected spike or new service.
type CostAnomaly struct {
	Service    string
	PrevAmount float64
	CurrAmount float64
	PctChange  float64
	IsNew      bool
}

// parseCostReport decodes the Cost Explorer JSON.
func parseCostReport(data []byte) (CostReport, error) {
	var report CostReport
	if err := json.Unmarshal(data, &report); err != nil {
		return CostReport{}, fmt.Errorf("parse cost report: %w", err)
	}
	return report, nil
}

// summarise converts a CostReport into sorted PeriodSummaries.
func summarise(report CostReport) []PeriodSummary {
	summaries := make([]PeriodSummary, 0, len(report.ResultsByTime))
	for _, p := range report.ResultsByTime {
		var ps PeriodSummary
		ps.Start = p.TimePeriod.Start
		ps.End = p.TimePeriod.End
		ps.Estimated = p.Estimated

		// Parse total.
		for metric, amt := range p.Total {
			if strings.Contains(strings.ToLower(metric), "cost") {
				ps.Total, _ = strconv.ParseFloat(amt.Amount, 64)
				ps.Unit = amt.Unit
				break
			}
		}

		// Parse service groups.
		for _, g := range p.Groups {
			if len(g.Keys) == 0 {
				continue
			}
			svcName := g.Keys[0]
			// Strip provider prefixes like "SERVICE$"
			if idx := strings.Index(svcName, "$"); idx >= 0 {
				svcName = svcName[idx+1:]
			}
			for metric, amt := range g.Metrics {
				if strings.Contains(strings.ToLower(metric), "cost") {
					v, _ := strconv.ParseFloat(amt.Amount, 64)
					ps.Services = append(ps.Services, ServiceCost{
						Service: svcName,
						Amount:  v,
						Unit:    amt.Unit,
					})
					_ = metric
					break
				}
			}
		}

		// Sort services by cost descending.
		sort.Slice(ps.Services, func(i, j int) bool {
			return ps.Services[i].Amount > ps.Services[j].Amount
		})
		summaries = append(summaries, ps)
	}
	return summaries
}

// detectAnomalies compares the last two periods and returns anomalies.
// Thresholds: >20% increase → MEDIUM, >50% → HIGH, >100% → CRITICAL; new services → LOW.
func detectAnomalies(summaries []PeriodSummary) []CostAnomaly {
	if len(summaries) < 2 {
		return nil
	}
	prev := summaries[len(summaries)-2]
	curr := summaries[len(summaries)-1]

	prevMap := make(map[string]float64, len(prev.Services))
	for _, s := range prev.Services {
		prevMap[s.Service] = s.Amount
	}

	var anomalies []CostAnomaly
	for _, s := range curr.Services {
		if s.Amount < 0.50 {
			continue // ignore sub-dollar noise
		}
		p, existed := prevMap[s.Service]
		if !existed {
			if s.Amount >= 5.0 { // only flag new services above $5
				anomalies = append(anomalies, CostAnomaly{
					Service:    s.Service,
					CurrAmount: s.Amount,
					IsNew:      true,
				})
			}
			continue
		}
		if p < 0.50 {
			continue
		}
		pct := (s.Amount - p) / p * 100
		if pct > 20 {
			anomalies = append(anomalies, CostAnomaly{
				Service:    s.Service,
				PrevAmount: p,
				CurrAmount: s.Amount,
				PctChange:  pct,
			})
		}
	}

	// Sort by pct change descending (new services go to the end).
	sort.Slice(anomalies, func(i, j int) bool {
		return anomalies[i].PctChange > anomalies[j].PctChange
	})
	return anomalies
}

// formatReport converts parsed summaries into a compact LLM-ready text block.
func formatReport(summaries []PeriodSummary, anomalies []CostAnomaly) string {
	if len(summaries) == 0 {
		return "No cost data found.\n"
	}

	var sb strings.Builder
	first := summaries[0]
	last := summaries[len(summaries)-1]
	unit := last.Unit
	if unit == "" {
		unit = "USD"
	}

	fmt.Fprintf(&sb, "AWS Cost Report | %s → %s | %d period(s)\n\n", first.Start, last.End, len(summaries))

	for i, ps := range summaries {
		label := periodLabel(ps.Start)
		suffix := ""
		if i == len(summaries)-1 && ps.Estimated {
			suffix = " (estimated)"
		}

		var momLine string
		if i > 0 {
			prev := summaries[i-1]
			if prev.Total > 0 {
				pct := (ps.Total - prev.Total) / prev.Total * 100
				sign := "+"
				if pct < 0 {
					sign = ""
				}
				momLine = fmt.Sprintf(" (%s%.1f%% MoM)", sign, pct)
			}
		}
		fmt.Fprintf(&sb, "## %s%s\n", label, suffix)
		fmt.Fprintf(&sb, "Total: %s %.2f%s\n", unit, ps.Total, momLine)

		top := ps.Services
		if len(top) > 10 {
			top = top[:10]
		}
		for rank, s := range top {
			pct := 0.0
			if ps.Total > 0 {
				pct = s.Amount / ps.Total * 100
			}
			fmt.Fprintf(&sb, "  %2d. %-40s %s %8.2f (%.1f%%)\n",
				rank+1, s.Service, unit, s.Amount, pct)
		}
		sb.WriteString("\n")
	}

	if len(anomalies) > 0 {
		sb.WriteString("## ANOMALIES\n")
		for _, a := range anomalies {
			if a.IsNew {
				fmt.Fprintf(&sb, "- [NEW] %s: %.2f %s (not present last period)\n", a.Service, a.CurrAmount, unit)
			} else {
				fmt.Fprintf(&sb, "- [%.0f%% increase] %s: %.2f → %.2f %s\n",
					a.PctChange, a.Service, a.PrevAmount, a.CurrAmount, unit)
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// BuildFindings converts anomalies into structured plugin.Finding entries.
func BuildFindings(summaries []PeriodSummary, anomalies []CostAnomaly) []plugin.Finding {
	if len(summaries) == 0 {
		return nil
	}
	last := summaries[len(summaries)-1]
	unit := last.Unit
	if unit == "" {
		unit = "USD"
	}
	var findings []plugin.Finding

	// Total spend spike between periods.
	if len(summaries) >= 2 {
		prev := summaries[len(summaries)-2]
		if prev.Total > 0 {
			pct := (last.Total - prev.Total) / prev.Total * 100
			if pct >= 50 {
				sev := plugin.SeverityHigh
				if pct >= 100 {
					sev = plugin.SeverityCritical
				}
				findings = append(findings, plugin.Finding{
					Severity:   sev,
					Title:      fmt.Sprintf("Total cost spike: +%.0f%% vs previous period", pct),
					Detail:     fmt.Sprintf("%s %.2f → %.2f %s (%s → %s)", unit, prev.Total, last.Total, unit, prev.Start, last.Start),
					Suggestion: "Drill into the top services to identify the driver. Check for untagged or idle resources.",
				})
			}
		}
	}

	for _, a := range anomalies {
		if a.IsNew {
			findings = append(findings, plugin.Finding{
				Severity:   plugin.SeverityLow,
				Title:      fmt.Sprintf("New service: %s (%.2f %s)", a.Service, a.CurrAmount, unit),
				Detail:     fmt.Sprintf("%s was not present in the previous period.", a.Service),
				Suggestion: "Confirm this service was intentionally enabled and is expected in the budget.",
			})
			continue
		}
		sev := plugin.SeverityMedium
		if a.PctChange >= 100 {
			sev = plugin.SeverityCritical
		} else if a.PctChange >= 50 {
			sev = plugin.SeverityHigh
		}
		findings = append(findings, plugin.Finding{
			Severity: sev,
			Title:    fmt.Sprintf("%s: +%.0f%% cost increase", a.Service, a.PctChange),
			Detail: fmt.Sprintf("%.2f → %.2f %s (%.0f%% increase). Period: %s.",
				a.PrevAmount, a.CurrAmount, unit, a.PctChange, last.Start),
			Suggestion: fmt.Sprintf("Investigate %s usage: check for new instances, data transfer spikes, or misconfigured auto-scaling.", a.Service),
		})
	}

	return findings
}

// periodLabel converts a YYYY-MM-DD date to a human-readable month label.
func periodLabel(dateStr string) string {
	t, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return dateStr
	}
	return t.Format("January 2006")
}

// roundFloat rounds to two decimal places (used in tests).
func roundFloat(v float64) float64 {
	return math.Round(v*100) / 100
}

var _ = roundFloat // exported for tests
