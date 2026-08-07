// Package service is the named service layer the platform review called
// for: interfaces that CLI, web, and MCP all call instead of each
// re-deriving the same views over plugin.Report. Deliberately narrow —
// only FindingsService and RemediationService are defined here, because
// those are the two concrete dependencies Phase 4 (wiring MCP to real
// services) needs today. internal/report and internal/timeline already
// expose the reusable core for a future ReportService/TimelineService;
// wrapping them in an interface with a single caller and no swap need
// would be exactly the over-engineering the platform review warned
// against — add those when a second caller actually shows up.
package service

import (
	"strings"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// FindingsFilter narrows List's results. Zero values mean "no filter" —
// mirrors internal/mcp's list_findings tool arguments exactly, since that
// is the extraction this type backs.
type FindingsFilter struct {
	Severity  string
	Category  string
	Namespace string
}

// ReportSummary is the wire shape report_summary returns.
type ReportSummary struct {
	Title   string
	Summary string
	Counts  map[string]int
	Total   int
}

// FindingsService answers read-only queries over the current findings —
// filtering, single-finding lookup, summary counts, and the remediable
// subset. Previously this exact logic (filter/lookup/count loops) lived
// inline in internal/mcp/tools.go's four read-tool handlers; this is the
// one implementation, so a future CLI or REST surface gets it for free.
type FindingsService interface {
	List(filter FindingsFilter) []plugin.Finding
	Get(title string) (plugin.Finding, bool)
	Summary() ReportSummary
	Remediable() []plugin.Finding
}

// reportFindingsService is the default FindingsService: a thin facade over
// a live plugin.Report snapshot. getReport is a getter (not a static
// Report) so callers backed by a live watch loop always see the current
// state without the service needing to know how the report refreshes.
type reportFindingsService struct {
	getReport func() plugin.Report
}

// NewFindingsService builds a FindingsService over getReport, called fresh
// on every method — never cached, so it reflects the latest snapshot.
func NewFindingsService(getReport func() plugin.Report) FindingsService {
	return &reportFindingsService{getReport: getReport}
}

func (s *reportFindingsService) List(filter FindingsFilter) []plugin.Finding {
	r := s.getReport()
	out := make([]plugin.Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if filter.Severity != "" && string(f.Severity) != filter.Severity {
			continue
		}
		if filter.Category != "" && f.Category != filter.Category {
			continue
		}
		if filter.Namespace != "" && !strings.Contains(f.Title, filter.Namespace+"/") {
			continue
		}
		out = append(out, f)
	}
	return out
}

func (s *reportFindingsService) Get(title string) (plugin.Finding, bool) {
	for _, f := range s.getReport().Findings {
		if f.Title == title {
			return f, true
		}
	}
	return plugin.Finding{}, false
}

func (s *reportFindingsService) Summary() ReportSummary {
	r := s.getReport()
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range r.Findings {
		if _, ok := counts[string(f.Severity)]; ok {
			counts[string(f.Severity)]++
		}
	}
	return ReportSummary{Title: r.Title, Summary: r.Summary, Counts: counts, Total: len(r.Findings)}
}

func (s *reportFindingsService) Remediable() []plugin.Finding {
	out := make([]plugin.Finding, 0)
	for _, f := range s.getReport().Findings {
		if f.Remediation != nil {
			out = append(out, f)
		}
	}
	return out
}
