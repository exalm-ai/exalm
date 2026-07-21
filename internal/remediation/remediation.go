// Package remediation holds the batch-apply policy for remediable findings:
// which findings are fixable, what order is safe to apply them in, and how
// to run a batch and collect per-item results. Transport-independent — takes
// a plugin.Report and an apply function, returns plain results.
//
// Extracted from internal/web/server.go's handleFixAll as part of the
// platform service-layer consolidation: this is the reusable core a future
// RemediationService (CLI/REST/MCP) wraps, not a web-specific handler detail.
package remediation

import (
	"context"
	"sort"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// FixableItem is one finding with an applicable remediation action.
type FixableItem struct {
	Title  string
	Action plugin.RemediationAction
}

// Result is one outcome of a batch apply — the wire shape of the
// /api/fix-all response, unchanged from its original web-only definition.
type Result struct {
	Title string `json:"title"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// kindOrder is the safe batch-apply order: restarts before deletes, so a
// rollout-restart or cronjob-resume gets a chance to self-heal before a
// more destructive delete-pod runs. Kinds not listed sort last, in their
// original relative order (stable sort).
var kindOrder = map[string]int{"rollout-restart": 0, "resume-cronjob": 1, "delete-pod": 2}

func orderOf(kind string) int {
	if v, ok := kindOrder[kind]; ok {
		return v
	}
	return 99
}

// FixableFromReport collects every finding in r that carries a remediation
// action, in report order.
func FixableFromReport(r plugin.Report) []FixableItem {
	var items []FixableItem
	for _, f := range r.Findings {
		if f.Remediation != nil {
			items = append(items, FixableItem{Title: f.Title, Action: *f.Remediation})
		}
	}
	return items
}

// OrderForBatch returns a NEW slice ordered for safe batch application
// (see kindOrder) — it never mutates items.
func OrderForBatch(items []FixableItem) []FixableItem {
	ordered := make([]FixableItem, len(items))
	copy(ordered, items)
	sort.SliceStable(ordered, func(i, j int) bool {
		return orderOf(ordered[i].Action.Kind) < orderOf(ordered[j].Action.Kind)
	})
	return ordered
}

// ApplyAll applies every item via applyFn, in the given order, and returns
// one Result per item (never an error return — a failed item is recorded in
// its own Result so the batch always completes and reports every outcome).
func ApplyAll(ctx context.Context, items []FixableItem, applyFn func(context.Context, plugin.RemediationAction) error) []Result {
	results := make([]Result, 0, len(items))
	for _, item := range items {
		res := Result{Title: item.Title}
		if err := applyFn(ctx, item.Action); err != nil {
			res.Error = err.Error()
		} else {
			res.OK = true
		}
		results = append(results, res)
	}
	return results
}
