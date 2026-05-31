package tf

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// MaxInputBytes caps the Terraform plan payload sent to the LLM.
const MaxInputBytes = 200 * 1024

// TFPlan is the top-level structure of `terraform show -json` output.
type TFPlan struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version"`
	ResourceChanges  []ResourceChange `json:"resource_changes"`
}

// ResourceChange is one entry in resource_changes[].
type ResourceChange struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Change  Change `json:"change"`
}

// Change holds actions and before/after state.
type Change struct {
	Actions []string        `json:"actions"`
	Before  json.RawMessage `json:"before"`
	After   json.RawMessage `json:"after"`
}

// Action returns the canonical action string for a change.
func (rc ResourceChange) Action() string {
	switch len(rc.Change.Actions) {
	case 0:
		return "no-op"
	case 2:
		// ["delete","create"] or ["create","delete"] = replacement
		return "replace"
	default:
		return rc.Change.Actions[0]
	}
}

// RiskLevel ranks how dangerous a change is.
type RiskLevel int

const (
	RiskNone     RiskLevel = 0
	RiskLow      RiskLevel = 1
	RiskMedium   RiskLevel = 2
	RiskHigh     RiskLevel = 3
	RiskCritical RiskLevel = 4
)

func (r RiskLevel) String() string {
	switch r {
	case RiskCritical:
		return "CRITICAL"
	case RiskHigh:
		return "HIGH"
	case RiskMedium:
		return "MEDIUM"
	case RiskLow:
		return "LOW"
	default:
		return "NONE"
	}
}

func (r RiskLevel) Severity() plugin.Severity {
	switch r {
	case RiskCritical:
		return plugin.SeverityCritical
	case RiskHigh:
		return plugin.SeverityHigh
	case RiskMedium:
		return plugin.SeverityMedium
	case RiskLow:
		return plugin.SeverityLow
	default:
		return plugin.SeverityInfo
	}
}

// resourceTier classifies a resource type by its blast radius.
type resourceTier int

const (
	tierCritical resourceTier = iota
	tierHigh
	tierMedium
	tierLow
)

// criticalTypeKeywords match resource types with the highest blast radius.
var criticalTypeKeywords = []string{
	"db_instance", "db_cluster", "rds_cluster", "rds_instance",
	"dynamodb_table", "elasticache_cluster", "elasticache_replication_group",
	"redshift_cluster", "neptune_cluster", "docdb_cluster",
	"aurora_cluster", "aurora_instance",
}

// highRiskTypeKeywords match resource types with significant blast radius.
var highRiskTypeKeywords = []string{
	"iam_role", "iam_policy", "iam_user", "iam_group",
	"iam_role_policy", "iam_user_policy", "iam_group_policy",
	"iam_role_policy_attachment", "iam_user_policy_attachment",
	"security_group", "network_acl",
	"s3_bucket",
	"kms_key", "kms_alias",
	"vpc", "subnet", "internet_gateway", "nat_gateway", "route_table",
}

// mediumRiskTypeKeywords match resource types that affect traffic routing or scaling.
var mediumRiskTypeKeywords = []string{
	"_alb", "_lb_", "_load_balancer", "alb_listener", "lb_listener",
	"autoscaling_group", "autoscaling_policy",
	"ecs_service", "ecs_task_definition",
	"eks_cluster", "eks_node_group",
	"route53", "cloudfront",
	"waf", "wafv2",
	"elasticloadbalancing",
}

func classifyResourceType(resourceType string) resourceTier {
	t := strings.ToLower(resourceType)
	for _, kw := range criticalTypeKeywords {
		if strings.Contains(t, kw) {
			return tierCritical
		}
	}
	for _, kw := range highRiskTypeKeywords {
		if strings.Contains(t, kw) {
			return tierHigh
		}
	}
	for _, kw := range mediumRiskTypeKeywords {
		if strings.Contains(t, kw) {
			return tierMedium
		}
	}
	return tierLow
}

// AssessRisk computes the risk level of a single resource change.
func AssessRisk(rc ResourceChange) RiskLevel {
	action := rc.Action()
	if action == "no-op" {
		return RiskNone
	}
	tier := classifyResourceType(rc.Type)
	switch action {
	case "delete":
		switch tier {
		case tierCritical:
			return RiskCritical
		case tierHigh:
			return RiskHigh
		case tierMedium:
			return RiskMedium
		default:
			return RiskLow
		}
	case "replace":
		// Replacement on critical/high resources is always at least HIGH.
		switch tier {
		case tierCritical:
			return RiskCritical
		case tierHigh:
			return RiskHigh
		default:
			return RiskMedium // replace forces downtime even on low-tier resources
		}
	case "update":
		switch tier {
		case tierCritical:
			return RiskMedium
		case tierHigh:
			return RiskHigh
		case tierMedium:
			return RiskMedium
		default:
			return RiskLow
		}
	case "create":
		// New IAM or network resources deserve attention.
		if tier == tierHigh || tier == tierCritical {
			return RiskMedium
		}
		return RiskLow
	default:
		return RiskLow
	}
}

// parsePlan decodes terraform show -json output.
func parsePlan(data []byte) (TFPlan, error) {
	var plan TFPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return TFPlan{}, fmt.Errorf("parse terraform plan JSON: %w", err)
	}
	return plan, nil
}

// formatPlan converts a TFPlan into a compact LLM-ready text block.
func formatPlan(plan TFPlan) string {
	type riskGroup struct {
		level   RiskLevel
		changes []ResourceChange
	}
	groups := []riskGroup{
		{level: RiskCritical},
		{level: RiskHigh},
		{level: RiskMedium},
		{level: RiskLow},
	}
	counts := map[string]int{}

	for _, rc := range plan.ResourceChanges {
		action := rc.Action()
		if action == "no-op" {
			continue
		}
		counts[action]++
		risk := AssessRisk(rc)
		switch risk {
		case RiskCritical:
			groups[0].changes = append(groups[0].changes, rc)
		case RiskHigh:
			groups[1].changes = append(groups[1].changes, rc)
		case RiskMedium:
			groups[2].changes = append(groups[2].changes, rc)
		default:
			groups[3].changes = append(groups[3].changes, rc)
		}
	}

	total := counts["create"] + counts["update"] + counts["delete"] + counts["replace"]
	var sb strings.Builder
	tfVer := plan.TerraformVersion
	if tfVer == "" {
		tfVer = "unknown"
	}
	fmt.Fprintf(&sb, "Terraform Plan | terraform=%s | format=%s\n", tfVer, plan.FormatVersion)
	fmt.Fprintf(&sb, "Changes: %d total | create=%d update=%d delete=%d replace=%d\n\n",
		total, counts["create"], counts["update"], counts["delete"], counts["replace"])

	for _, g := range groups {
		if len(g.changes) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "=== %s RISK (%d) ===\n", g.level, len(g.changes))
		for _, rc := range g.changes {
			fmt.Fprintf(&sb, "[%s] %s (type: %s)\n", strings.ToUpper(rc.Action()), rc.Address, rc.Type)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// BuildFindings converts a TFPlan into structured plugin.Finding entries.
func BuildFindings(plan TFPlan) []plugin.Finding {
	var findings []plugin.Finding
	for _, rc := range plan.ResourceChanges {
		risk := AssessRisk(rc)
		if risk == RiskNone || risk == RiskLow {
			continue
		}
		action := rc.Action()
		title := fmt.Sprintf("[%s] %s", strings.ToUpper(action), rc.Address)
		detail := fmt.Sprintf("Resource type: %s. Action: %s.", rc.Type, action)
		suggestion := riskSuggestion(rc.Type, action)
		findings = append(findings, plugin.Finding{
			Severity:   risk.Severity(),
			Title:      title,
			Detail:     detail,
			Suggestion: suggestion,
		})
	}
	return findings
}

// riskSuggestion returns a concise, actionable suggestion for the given resource type and action.
func riskSuggestion(resourceType, action string) string {
	t := strings.ToLower(resourceType)
	switch {
	case containsAny(t, "db_instance", "db_cluster", "rds", "dynamodb", "elasticache"):
		if action == "delete" || action == "replace" {
			return "Verify backup exists and all consumers are updated before applying. Data loss is permanent."
		}
		return "Validate that DB parameter changes are backward-compatible and have been tested in staging."
	case containsAny(t, "iam_role", "iam_policy", "iam_user"):
		if action == "delete" || action == "replace" {
			return "Audit all principals using this IAM resource before deleting — check for attached policies and trust relationships."
		}
		return "Review the IAM policy diff carefully for privilege escalation paths or overly broad permissions."
	case containsAny(t, "security_group", "network_acl"):
		return "Check that no ingress/egress rules were widened to 0.0.0.0/0 unintentionally."
	case containsAny(t, "s3_bucket"):
		if action == "delete" {
			return "Ensure the bucket is empty and all data has been migrated before applying."
		}
		return "Verify bucket policy, ACL, and versioning settings are intentional."
	case containsAny(t, "kms_key"):
		if action == "delete" || action == "replace" {
			return "Deleting KMS keys is irreversible and will render all encrypted data permanently unreadable."
		}
		return "Verify key policy changes do not revoke access for existing services."
	case containsAny(t, "vpc", "subnet", "internet_gateway"):
		return "Network topology changes can cause connectivity loss. Test in a non-production environment first."
	default:
		if action == "delete" {
			return "Verify no downstream resources depend on this before applying."
		}
		return "Review the change diff carefully before applying."
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
