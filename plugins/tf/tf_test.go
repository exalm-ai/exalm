package tf

import (
	"context"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// fakeLLM returns a canned response for testing.
type fakeLLM struct{ captured string }

func (f *fakeLLM) Name() string { return "fake" }
func (f *fakeLLM) Complete(_ context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	f.captured = req.Messages[0].Content
	return plugin.CompleteResponse{Content: "## VERDICT\nTest."}, nil
}

// fakeRedactor passes through input unchanged.
type fakeRedactor struct{}

func (fakeRedactor) Redact(s string) string { return s }

func plan(actions []string, resourceType, address string) ResourceChange {
	return ResourceChange{
		Address: address,
		Type:    resourceType,
		Name:    address,
		Change:  Change{Actions: actions},
	}
}

// --- AssessRisk ---

func TestAssessRisk_NoOp(t *testing.T) {
	rc := plan([]string{"no-op"}, "aws_instance", "aws_instance.web")
	if got := AssessRisk(rc); got != RiskNone {
		t.Errorf("expected RiskNone, got %v", got)
	}
}

func TestAssessRisk_DeleteDatabase(t *testing.T) {
	rc := plan([]string{"delete"}, "aws_db_instance", "aws_db_instance.production")
	if got := AssessRisk(rc); got != RiskCritical {
		t.Errorf("expected RiskCritical, got %v", got)
	}
}

func TestAssessRisk_ReplaceDatabase(t *testing.T) {
	rc := plan([]string{"delete", "create"}, "aws_rds_cluster", "aws_rds_cluster.main")
	if got := AssessRisk(rc); got != RiskCritical {
		t.Errorf("expected RiskCritical, got %v", got)
	}
}

func TestAssessRisk_DeleteSecurityGroup(t *testing.T) {
	rc := plan([]string{"delete"}, "aws_security_group", "aws_security_group.web")
	if got := AssessRisk(rc); got != RiskHigh {
		t.Errorf("expected RiskHigh, got %v", got)
	}
}

func TestAssessRisk_UpdateIAMPolicy(t *testing.T) {
	rc := plan([]string{"update"}, "aws_iam_role_policy", "aws_iam_role_policy.app")
	if got := AssessRisk(rc); got != RiskHigh {
		t.Errorf("expected RiskHigh, got %v", got)
	}
}

func TestAssessRisk_ReplaceInstance(t *testing.T) {
	rc := plan([]string{"create", "delete"}, "aws_instance", "aws_instance.web")
	if got := AssessRisk(rc); got != RiskMedium {
		t.Errorf("expected RiskMedium for replacing low-tier resource, got %v", got)
	}
}

func TestAssessRisk_CreateLambda(t *testing.T) {
	rc := plan([]string{"create"}, "aws_lambda_function", "aws_lambda_function.handler")
	if got := AssessRisk(rc); got != RiskLow {
		t.Errorf("expected RiskLow, got %v", got)
	}
}

func TestAssessRisk_CreateIAMRole(t *testing.T) {
	rc := plan([]string{"create"}, "aws_iam_role", "aws_iam_role.new_service")
	if got := AssessRisk(rc); got != RiskMedium {
		t.Errorf("expected RiskMedium for new IAM role, got %v", got)
	}
}

// --- parsePlan ---

func TestParsePlan_Valid(t *testing.T) {
	data := `{
		"format_version": "1.2",
		"terraform_version": "1.6.0",
		"resource_changes": [
			{
				"address": "aws_s3_bucket.logs",
				"type": "aws_s3_bucket",
				"name": "logs",
				"change": {"actions": ["create"]}
			}
		]
	}`
	plan, err := parsePlan([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.ResourceChanges) != 1 {
		t.Errorf("expected 1 change, got %d", len(plan.ResourceChanges))
	}
}

func TestParsePlan_Invalid(t *testing.T) {
	_, err := parsePlan([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// --- BuildFindings ---

func TestBuildFindings_FilterNoOp(t *testing.T) {
	p := TFPlan{ResourceChanges: []ResourceChange{
		plan([]string{"no-op"}, "aws_instance", "aws_instance.web"),
		plan([]string{"create"}, "aws_cloudwatch_log_group", "aws_cloudwatch_log_group.api"),
	}}
	findings := BuildFindings(p)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (low/none filtered), got %d", len(findings))
	}
}

func TestBuildFindings_CriticalDelete(t *testing.T) {
	p := TFPlan{ResourceChanges: []ResourceChange{
		plan([]string{"delete"}, "aws_db_instance", "aws_db_instance.prod"),
	}}
	findings := BuildFindings(p)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != plugin.SeverityCritical {
		t.Errorf("expected critical, got %v", findings[0].Severity)
	}
}

// --- formatPlan ---

func TestFormatPlan_IncludesRiskSections(t *testing.T) {
	p := TFPlan{
		TerraformVersion: "1.6.0",
		FormatVersion:    "1.2",
		ResourceChanges: []ResourceChange{
			plan([]string{"delete"}, "aws_db_instance", "aws_db_instance.prod"),
			plan([]string{"create"}, "aws_s3_bucket", "aws_s3_bucket.logs"),
		},
	}
	out := formatPlan(p)
	if !strings.Contains(out, "CRITICAL") {
		t.Error("expected CRITICAL section in output")
	}
	if !strings.Contains(out, "aws_db_instance.prod") {
		t.Error("expected db instance address in output")
	}
}

// --- Plugin integration ---

func TestPlugin_Metadata(t *testing.T) {
	p := New()
	if p.Name() != "tf" {
		t.Errorf("expected name 'tf', got %q", p.Name())
	}
	if p.Mutates() {
		t.Error("tf plugin should not mutate")
	}
	if len(p.Subcommands()) == 0 {
		t.Error("expected at least one subcommand")
	}
}

func TestPlugin_ReviewFromStdin(t *testing.T) {
	llm := &fakeLLM{}
	p := New()
	planJSON := `{
		"format_version": "1.2",
		"terraform_version": "1.6.0",
		"resource_changes": [
			{
				"address": "aws_db_instance.prod",
				"type": "aws_db_instance",
				"name": "prod",
				"change": {"actions": ["delete"]}
			}
		]
	}`

	report, err := p.review(context.Background(), plugin.RunArgs{
		Stdin:    strings.NewReader(planJSON),
		LLM:      llm,
		Redactor: fakeRedactor{},
		Flags:    map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) == 0 {
		t.Error("expected findings for db deletion")
	}
	if !strings.Contains(llm.captured, "aws_db_instance.prod") {
		t.Error("expected plan content in LLM payload")
	}
}
