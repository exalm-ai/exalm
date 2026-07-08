package k8s

// confidence.go is the KUBERNETES confidence-rule table for the framework's
// evidence-quality scoring (investigate.ScoreConfidence): an explicit
// terminal state beats a log pattern, which beats a weak correlation. The
// scan, corroboration bonus, modeled-metrics deduction, cap, and tier
// mapping are framework-owned.

import (
	"regexp"
	"strings"

	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

var (
	probeEvRe   = regexp.MustCompile(`(?i)unhealthy|probe`)
	endpointRe  = regexp.MustCompile(`(?i)no ready endpoints|selector mismatch|0 ready`)
	logErrRe    = regexp.MustCompile(`(?i)error|panic|fatal|exception|oom`)
	nodePressRe = regexp.MustCompile(`(?i)pressure`)
	recentChgRe = regexp.MustCompile(`(?i)\d+m ago|just now|[0-2]?\dm ago`)
	anyChangeRe = regexp.MustCompile(`(?i)ago`)
	noChangeRe  = regexp.MustCompile(`(?i)no changes recorded`)
	anyMetricRe = regexp.MustCompile(`.`)
)

var terminalRsns = []string{"oomkilled", "oom", "evicted"}

// confidenceRules is ordered highest first for readability; the framework
// scans all rows and keeps the max.
var confidenceRules = []investigate.ConfidenceRule{
	{
		Score: 95, Reason: "the container's own status reports an explicit terminal state (e.g. OOMKilled) — direct, unambiguous evidence",
		Match: func(_ []plugin.EvidenceItem, _ []plugin.InvestigationStep, f investigate.Facts) bool {
			pod := unwrap(f).pod
			if pod == nil {
				return false
			}
			lower := strings.ToLower(pod.Reason)
			for _, r := range terminalRsns {
				if strings.Contains(lower, r) {
					return true
				}
			}
			return false
		},
	},
	{
		Score: 90, Reason: "probe failures with matching Unhealthy events — two independent sources agree",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "event", probeEvRe) && investigate.EvidenceMatching(ev, "config", probeEvRe)
		},
	},
	{
		Score: 85, Reason: "a recorded change landed shortly before the first failure — strong temporal correlation",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "change", recentChgRe)
		},
	},
	{
		Score: 75, Reason: "a recorded change precedes the symptom within the last day — plausible trigger",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "change", anyChangeRe) && !investigate.EvidenceMatching(ev, "change", noChangeRe)
		},
	},
	{
		Score: 70, Reason: "an endpoint/selector mismatch is confirmed by live endpoint state",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "", endpointRe)
		},
	},
	{
		Score: 60, Reason: "the conclusion rests on log patterns only — consistent but not state-confirmed",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "log", logErrRe)
		},
	},
	{
		Score: 55, Reason: "node pressure signals present — environmental cause plausible",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "", nodePressRe)
		},
	},
	{
		Score: 45, Reason: "only metrics signals support the conclusion",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "metric", anyMetricRe)
		},
	},
	{
		Score: 30, Reason: "only weak, indirect correlation available",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return len(ev) > 0
		},
	},
}
