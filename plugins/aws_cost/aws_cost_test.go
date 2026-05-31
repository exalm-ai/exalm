package aws_cost

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

type fakeRedactor struct{}

func (fakeRedactor) Redact(s string) string { return s }

const twoMonthJSON = `{
	"ResultsByTime": [
		{
			"TimePeriod": {"Start": "2024-03-01", "End": "2024-04-01"},
			"Total": {"BlendedCost": {"Amount": "1000.00", "Unit": "USD"}},
			"Groups": [
				{"Keys": ["Amazon EC2"], "Metrics": {"BlendedCost": {"Amount": "600.00", "Unit": "USD"}}},
				{"Keys": ["Amazon S3"], "Metrics": {"BlendedCost": {"Amount": "200.00", "Unit": "USD"}}},
				{"Keys": ["Amazon RDS"], "Metrics": {"BlendedCost": {"Amount": "200.00", "Unit": "USD"}}}
			]
		},
		{
			"TimePeriod": {"Start": "2024-04-01", "End": "2024-05-01"},
			"Total": {"BlendedCost": {"Amount": "2200.00", "Unit": "USD"}},
			"Groups": [
				{"Keys": ["Amazon EC2"], "Metrics": {"BlendedCost": {"Amount": "1500.00", "Unit": "USD"}}},
				{"Keys": ["Amazon S3"], "Metrics": {"BlendedCost": {"Amount": "210.00", "Unit": "USD"}}},
				{"Keys": ["Amazon RDS"], "Metrics": {"BlendedCost": {"Amount": "195.00", "Unit": "USD"}}},
				{"Keys": ["Amazon EKS"], "Metrics": {"BlendedCost": {"Amount": "295.00", "Unit": "USD"}}}
			]
		}
	]
}`

func TestParseCostReport_Valid(t *testing.T) {
	r, err := parseCostReport([]byte(twoMonthJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.ResultsByTime) != 2 {
		t.Errorf("expected 2 periods, got %d", len(r.ResultsByTime))
	}
}

func TestParseCostReport_Invalid(t *testing.T) {
	_, err := parseCostReport([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestSummarise_TotalParsed(t *testing.T) {
	r, _ := parseCostReport([]byte(twoMonthJSON))
	sums := summarise(r)
	if len(sums) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(sums))
	}
	if sums[0].Total != 1000.0 {
		t.Errorf("expected 1000.00, got %f", sums[0].Total)
	}
	if sums[1].Total != 2200.0 {
		t.Errorf("expected 2200.00, got %f", sums[1].Total)
	}
}

func TestSummarise_ServicesDescending(t *testing.T) {
	r, _ := parseCostReport([]byte(twoMonthJSON))
	sums := summarise(r)
	svcs := sums[1].Services
	for i := 1; i < len(svcs); i++ {
		if svcs[i].Amount > svcs[i-1].Amount {
			t.Errorf("services not sorted descending at index %d", i)
		}
	}
}

func TestDetectAnomalies_EC2Spike(t *testing.T) {
	r, _ := parseCostReport([]byte(twoMonthJSON))
	sums := summarise(r)
	anomalies := detectAnomalies(sums)

	var ec2 *CostAnomaly
	for i := range anomalies {
		if anomalies[i].Service == "Amazon EC2" {
			ec2 = &anomalies[i]
		}
	}
	if ec2 == nil {
		t.Fatal("expected Amazon EC2 anomaly")
	}
	// 600 → 1500 = 150% increase
	if ec2.PctChange < 140 || ec2.PctChange > 160 {
		t.Errorf("expected ~150%% change, got %.1f%%", ec2.PctChange)
	}
}

func TestDetectAnomalies_NewService(t *testing.T) {
	r, _ := parseCostReport([]byte(twoMonthJSON))
	sums := summarise(r)
	anomalies := detectAnomalies(sums)

	var eks *CostAnomaly
	for i := range anomalies {
		if anomalies[i].Service == "Amazon EKS" {
			eks = &anomalies[i]
		}
	}
	if eks == nil {
		t.Fatal("expected Amazon EKS as new-service anomaly")
	}
	if !eks.IsNew {
		t.Error("expected IsNew=true for EKS")
	}
}

func TestDetectAnomalies_StableServiceNotFlagged(t *testing.T) {
	r, _ := parseCostReport([]byte(twoMonthJSON))
	sums := summarise(r)
	anomalies := detectAnomalies(sums)

	for _, a := range anomalies {
		if a.Service == "Amazon RDS" {
			t.Errorf("RDS decreased slightly, should not be flagged: %+v", a)
		}
	}
}

func TestDetectAnomalies_SinglePeriodNoAnomalies(t *testing.T) {
	r, _ := parseCostReport([]byte(`{
		"ResultsByTime": [
			{
				"TimePeriod": {"Start": "2024-04-01", "End": "2024-05-01"},
				"Total": {"BlendedCost": {"Amount": "1000.00", "Unit": "USD"}},
				"Groups": [
					{"Keys": ["Amazon EC2"], "Metrics": {"BlendedCost": {"Amount": "1000.00", "Unit": "USD"}}}
				]
			}
		]
	}`))
	sums := summarise(r)
	anomalies := detectAnomalies(sums)
	if len(anomalies) != 0 {
		t.Errorf("expected 0 anomalies for single period, got %d", len(anomalies))
	}
}

func TestBuildFindings_TotalSpike(t *testing.T) {
	r, _ := parseCostReport([]byte(twoMonthJSON))
	sums := summarise(r)
	anomalies := detectAnomalies(sums)
	findings := BuildFindings(sums, anomalies)

	// Total went from 1000 → 2200 = 120% → should be critical
	var hasTotal bool
	for _, f := range findings {
		if strings.Contains(f.Title, "Total cost spike") {
			hasTotal = true
			if f.Severity != plugin.SeverityCritical {
				t.Errorf("expected critical for 120%% total spike, got %v", f.Severity)
			}
		}
	}
	if !hasTotal {
		t.Error("expected a total cost spike finding")
	}
}

func TestFormatReport_ContainsAnomalySection(t *testing.T) {
	r, _ := parseCostReport([]byte(twoMonthJSON))
	sums := summarise(r)
	anomalies := detectAnomalies(sums)
	out := formatReport(sums, anomalies)

	if !strings.Contains(out, "ANOMALIES") {
		t.Error("expected ANOMALIES section in formatted output")
	}
	if !strings.Contains(out, "Amazon EC2") {
		t.Error("expected EC2 in formatted output")
	}
}

func TestPlugin_Metadata(t *testing.T) {
	p := New()
	if p.Name() != "aws" {
		t.Errorf("expected name 'aws', got %q", p.Name())
	}
	if p.Mutates() {
		t.Error("aws plugin should not mutate")
	}
	if len(p.Subcommands()) == 0 {
		t.Error("expected at least one subcommand")
	}
}

func TestPlugin_AnalyzeFromStdin(t *testing.T) {
	llm := &fakeLLM{}
	p := New()

	report, err := p.analyze(context.Background(), plugin.RunArgs{
		Stdin:    strings.NewReader(twoMonthJSON),
		LLM:      llm,
		Redactor: fakeRedactor{},
		Flags:    map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(llm.captured, "Amazon EC2") {
		t.Error("expected EC2 in LLM payload")
	}
	if len(report.Findings) == 0 {
		t.Error("expected findings for a cost spike")
	}
}
