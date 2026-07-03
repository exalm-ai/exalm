package k8s

// confidence.go scores the copilot's confidence numerically (0–100) from
// evidence QUALITY, not just quantity: an explicit terminal state beats a
// log pattern, which beats a weak correlation. The score, its rationale, and
// the mapped tier are all surfaced so the user can see WHY the number is
// what it is.

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// confidenceRule is one row of the scoring table. The highest-scoring
// matching rule wins; corroboration then adds a small bonus.
type confidenceRule struct {
	Score  int
	Reason string
	Match  func(ev []plugin.EvidenceItem, steps []plugin.InvestigationStep, pod *PodSummary) bool
}

var (
	probeEvRe    = regexp.MustCompile(`(?i)unhealthy|probe`)
	endpointRe   = regexp.MustCompile(`(?i)no ready endpoints|selector mismatch|0 ready`)
	logErrRe     = regexp.MustCompile(`(?i)error|panic|fatal|exception|oom`)
	nodePressRe  = regexp.MustCompile(`(?i)pressure`)
	modeledRe    = regexp.MustCompile(`(?i)modeled`)
	recentChgRe  = regexp.MustCompile(`(?i)\d+m ago|just now|[0-2]?\dm ago`)
	anyChangeRe  = regexp.MustCompile(`(?i)ago`)
	noChangeRe   = regexp.MustCompile(`(?i)no changes recorded`)
	terminalRsns = []string{"oomkilled", "oom", "evicted"}
)

func evidenceMatching(ev []plugin.EvidenceItem, kind string, re *regexp.Regexp) bool {
	for _, e := range ev {
		if kind != "" && e.Kind != kind {
			continue
		}
		if re.MatchString(e.Source + " " + e.Excerpt) {
			return true
		}
	}
	return false
}

// confidenceRules is ordered highest first for readability; scoring scans all
// rows and keeps the max.
var confidenceRules = []confidenceRule{
	{
		Score: 95, Reason: "the container's own status reports an explicit terminal state (e.g. OOMKilled) — direct, unambiguous evidence",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, pod *PodSummary) bool {
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
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ *PodSummary) bool {
			return evidenceMatching(ev, "event", probeEvRe) && evidenceMatching(ev, "config", probeEvRe)
		},
	},
	{
		Score: 85, Reason: "a recorded change landed shortly before the first failure — strong temporal correlation",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ *PodSummary) bool {
			return evidenceMatching(ev, "change", recentChgRe)
		},
	},
	{
		Score: 75, Reason: "a recorded change precedes the symptom within the last day — plausible trigger",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ *PodSummary) bool {
			return evidenceMatching(ev, "change", anyChangeRe) && !evidenceMatching(ev, "change", noChangeRe)
		},
	},
	{
		Score: 70, Reason: "an endpoint/selector mismatch is confirmed by live endpoint state",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ *PodSummary) bool {
			return evidenceMatching(ev, "", endpointRe)
		},
	},
	{
		Score: 60, Reason: "the conclusion rests on log patterns only — consistent but not state-confirmed",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ *PodSummary) bool {
			return evidenceMatching(ev, "log", logErrRe)
		},
	},
	{
		Score: 55, Reason: "node pressure signals present — environmental cause plausible",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ *PodSummary) bool {
			return evidenceMatching(ev, "", nodePressRe)
		},
	},
	{
		Score: 45, Reason: "only metrics signals support the conclusion",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ *PodSummary) bool {
			return evidenceMatching(ev, "metric", regexp.MustCompile(`.`))
		},
	},
	{
		Score: 30, Reason: "only weak, indirect correlation available",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ *PodSummary) bool {
			return len(ev) > 0
		},
	},
}

// scoreConfidence returns the numeric confidence and a one-sentence
// rationale. Rules: highest matching row wins; +2 per independent evidence
// kind beyond the first (corroboration), capped at 98; modeled metrics
// subtract 15 when metrics are the strongest signal; floor 10 when nothing
// was gathered.
func scoreConfidence(ev []plugin.EvidenceItem, steps []plugin.InvestigationStep, pod *PodSummary) (int, string) {
	best := 0
	reason := "no evidence could be gathered this turn"
	for _, r := range confidenceRules {
		if r.Score > best && r.Match(ev, steps, pod) {
			best = r.Score
			reason = r.Reason
		}
	}
	if best == 0 {
		return 10, reason
	}

	// Modeled metrics are honest approximations, not measurements.
	if best == 45 && evidenceMatching(ev, "metric", modeledRe) {
		best -= 15
		reason += " (modeled metrics — reduced accordingly)"
	}

	kinds := map[string]bool{}
	for _, e := range ev {
		kinds[e.Kind] = true
	}
	if extra := len(kinds) - 1; extra > 0 {
		best += 2 * extra
		reason += "; corroborated across " + strconv.Itoa(len(kinds)) + " evidence kinds"
	}
	if best > 98 {
		best = 98
	}
	return best, reason
}

// tierFor maps the numeric score onto the legacy low/medium/high tiers so
// ConversationMessage.Confidence stays populated for older UI paths.
func tierFor(score int) string {
	switch {
	case score >= 75:
		return "high"
	case score >= 45:
		return "medium"
	default:
		return "low"
	}
}
