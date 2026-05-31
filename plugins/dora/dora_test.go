package dora

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
	incidentpkg "github.com/exalm-ai/exalm/plugins/incident"
)

// ─── fake LLM ─────────────────────────────────────────────────────────────────

type fakeLLM struct{ response string }

func (f *fakeLLM) Name() string { return "fake" }
func (f *fakeLLM) Complete(_ context.Context, _ plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	return plugin.CompleteResponse{Content: f.response}, nil
}

type fakeRedactor struct{}

func (r *fakeRedactor) Redact(s string) string { return s }

// ─── helpers ──────────────────────────────────────────────────────────────────

func makeRunArgs(flags map[string]string) plugin.RunArgs {
	return plugin.RunArgs{
		Flags:    flags,
		LLM:      &fakeLLM{response: "test LLM response"},
		Redactor: &fakeRedactor{},
	}
}

// ─── calculateDORA tests ──────────────────────────────────────────────────────

func TestCalculateDORA_NoData(t *testing.T) {
	m := calculateDORA(30*24*time.Hour, nil, nil)
	if m.TotalDeployments != 0 {
		t.Errorf("expected 0 deployments, got %d", m.TotalDeployments)
	}
	if m.DeploymentFrequencyRating != BandNA {
		t.Errorf("expected N/A band with no data, got %s", m.DeploymentFrequencyRating)
	}
	if m.ChangeFailureRateRating != BandNA {
		t.Errorf("expected CFR N/A with no deployments, got %s", m.ChangeFailureRateRating)
	}
}

func TestCalculateDORA_EliteFrequency(t *testing.T) {
	now := time.Now().UTC()
	var deps []DeploymentEvent
	// 30 successful deployments over 30 days → 1/day → Elite
	for i := 0; i < 30; i++ {
		deps = append(deps, DeploymentEvent{
			ID:         fmt.Sprintf("DEP-%d", i),
			Service:    "test-svc",
			DeployedAt: now.Add(-time.Duration(i) * 24 * time.Hour),
			Success:    true,
		})
	}
	m := calculateDORA(30*24*time.Hour, deps, nil)
	if m.DeploymentFrequencyRating != BandElite {
		t.Errorf("expected Elite band for 1/day, got %s", m.DeploymentFrequencyRating)
	}
	if m.SuccessfulDeployments != 30 {
		t.Errorf("expected 30 successful deployments, got %d", m.SuccessfulDeployments)
	}
}

func TestCalculateDORA_HighCFR(t *testing.T) {
	now := time.Now().UTC()
	// 10 deployments, 3 critical incidents → CFR = 30% → Low
	deps := []DeploymentEvent{
		{ID: "D1", Service: "svc", DeployedAt: now.Add(-5 * time.Hour), Success: true},
		{ID: "D2", Service: "svc", DeployedAt: now.Add(-10 * time.Hour), Success: true},
		{ID: "D3", Service: "svc", DeployedAt: now.Add(-15 * time.Hour), Success: true},
		{ID: "D4", Service: "svc", DeployedAt: now.Add(-20 * time.Hour), Success: false},
	}
	closedAt := now.Add(-1 * time.Hour)
	incidents := []incidentpkg.Incident{
		{ID: "INC-1", Severity: plugin.SeverityCritical, OpenedAt: now.Add(-3 * time.Hour), ClosedAt: &closedAt},
		{ID: "INC-2", Severity: plugin.SeverityHigh, OpenedAt: now.Add(-6 * time.Hour), ClosedAt: &closedAt},
	}
	m := calculateDORA(30*24*time.Hour, deps, incidents)
	if m.CriticalHighIncidents != 2 {
		t.Errorf("expected 2 critical/high incidents, got %d", m.CriticalHighIncidents)
	}
	// CFR = (1 failed dep + 2 critical incidents) / 4 total = 75% → Low
	if m.ChangeFailureRateRating != BandLow {
		t.Errorf("expected Low CFR band, got %s", m.ChangeFailureRateRating)
	}
}

func TestCalculateDORA_MTTRElite(t *testing.T) {
	now := time.Now().UTC()
	// MTTR = 30 min → Elite
	openedAt := now.Add(-30 * time.Minute)
	closedAt := now
	incidents := []incidentpkg.Incident{
		{
			ID:       "INC-1",
			Severity: plugin.SeverityMedium,
			OpenedAt: openedAt,
			ClosedAt: &closedAt,
		},
	}
	m := calculateDORA(30*24*time.Hour, nil, incidents)
	if m.MTTRRating != BandElite {
		t.Errorf("expected Elite MTTR band for 30min restore, got %s", m.MTTRRating)
	}
}

func TestCalculateDORA_OverallRating_WorstBand(t *testing.T) {
	now := time.Now().UTC()
	// Elite DF but no incident data → overall should reflect worst of known metrics
	deps := []DeploymentEvent{
		{ID: "D1", Service: "svc", DeployedAt: now.Add(-1 * time.Hour), Success: true},
		{ID: "D2", Service: "svc", DeployedAt: now.Add(-2 * time.Hour), Success: true},
	}
	m := calculateDORA(2*time.Hour, deps, nil)
	// With no incidents CFR = 0% = Elite, MTTR = N/A
	// Overall should be at least Elite (N/A is excluded)
	if m.OverallRating == BandNA {
		t.Error("overall rating should not be N/A when some metrics are rated")
	}
}

// ─── rating function tests ────────────────────────────────────────────────────

func TestRateDeploymentFrequency(t *testing.T) {
	tests := []struct {
		freq  float64
		total int
		want  DORABand
	}{
		{0, 0, BandNA},
		{0.5 / 30, 1, BandLow},    // once per 2 months
		{1.0 / 20, 1, BandMedium}, // once per 20 days
		{1.0 / 5, 1, BandHigh},    // once per 5 days
		{2.0, 60, BandElite},      // twice per day
	}
	for _, tt := range tests {
		got := rateDeploymentFrequency(tt.freq, tt.total)
		if got != tt.want {
			t.Errorf("rateDeploymentFrequency(%.4f, %d) = %s, want %s", tt.freq, tt.total, got, tt.want)
		}
	}
}

func TestRateCFR(t *testing.T) {
	tests := []struct {
		cfr   float64
		total int
		want  DORABand
	}{
		{0, 0, BandNA},
		{0.03, 10, BandElite},
		{0.07, 10, BandHigh},
		{0.12, 10, BandMedium},
		{0.20, 10, BandLow},
	}
	for _, tt := range tests {
		got := rateCFR(tt.cfr, tt.total)
		if got != tt.want {
			t.Errorf("rateCFR(%.2f, %d) = %s, want %s", tt.cfr, tt.total, got, tt.want)
		}
	}
}

func TestRateMTTR(t *testing.T) {
	tests := []struct {
		hours  float64
		closed int
		want   DORABand
	}{
		{0, 0, BandNA},
		{0.5, 1, BandElite},
		{12, 1, BandHigh},
		{100, 1, BandMedium},
		{200, 1, BandLow},
	}
	for _, tt := range tests {
		got := rateMTTR(tt.hours, tt.closed)
		if got != tt.want {
			t.Errorf("rateMTTR(%.1f, %d) = %s, want %s", tt.hours, tt.closed, got, tt.want)
		}
	}
}

// ─── store tests ──────────────────────────────────────────────────────────────

func TestAppendAndLoadDeployments(t *testing.T) {
	dir := t.TempDir()
	DeploymentDir = dir
	defer func() { DeploymentDir = "" }()

	now := time.Now().UTC()
	ev := DeploymentEvent{
		ID:         newDeploymentID(now),
		Service:    "payments-api",
		Version:    "v1.4.2",
		DeployedAt: now,
		Success:    true,
	}

	if err := appendDeployment(ev); err != nil {
		t.Fatalf("appendDeployment: %v", err)
	}

	loaded, err := loadDeployments()
	if err != nil {
		t.Fatalf("loadDeployments: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 deployment, got %d", len(loaded))
	}
	if loaded[0].Service != "payments-api" {
		t.Errorf("got service %q, want %q", loaded[0].Service, "payments-api")
	}
	if loaded[0].Version != "v1.4.2" {
		t.Errorf("got version %q, want %q", loaded[0].Version, "v1.4.2")
	}
}

func TestLoadDeployments_EmptyWhenNoFile(t *testing.T) {
	dir := t.TempDir()
	DeploymentDir = dir
	defer func() { DeploymentDir = "" }()

	events, err := loadDeployments()
	if err != nil {
		t.Fatalf("loadDeployments on empty dir: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}

func TestLoadDeploymentsInWindow(t *testing.T) {
	dir := t.TempDir()
	DeploymentDir = dir
	defer func() { DeploymentDir = "" }()

	now := time.Now().UTC()
	old := DeploymentEvent{ID: "OLD", Service: "svc", DeployedAt: now.Add(-60 * 24 * time.Hour), Success: true}
	recent := DeploymentEvent{ID: "NEW", Service: "svc", DeployedAt: now.Add(-5 * 24 * time.Hour), Success: true}

	for _, ev := range []DeploymentEvent{old, recent} {
		if err := appendDeployment(ev); err != nil {
			t.Fatalf("appendDeployment: %v", err)
		}
	}

	window := 30 * 24 * time.Hour
	result, err := loadDeploymentsInWindow(window)
	if err != nil {
		t.Fatalf("loadDeploymentsInWindow: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 event in window, got %d", len(result))
	}
	if result[0].ID != "NEW" {
		t.Errorf("expected ID=NEW, got %s", result[0].ID)
	}
}

// ─── plugin subcommand tests ──────────────────────────────────────────────────

func TestLogDeploy_RequiresService(t *testing.T) {
	p := New()
	_, err := p.logDeploy(context.Background(), makeRunArgs(map[string]string{}))
	if err == nil {
		t.Fatal("expected error when --service is missing")
	}
}

func TestLogDeploy_WritesDeployment(t *testing.T) {
	dir := t.TempDir()
	DeploymentDir = dir
	defer func() { DeploymentDir = "" }()

	p := New()
	report, err := p.logDeploy(context.Background(), makeRunArgs(map[string]string{
		"service": "test-svc",
		"version": "v2.0.0",
	}))
	if err != nil {
		t.Fatalf("logDeploy: %v", err)
	}
	if report.Summary == "" {
		t.Error("expected non-empty summary")
	}

	loaded, err := loadDeployments()
	if err != nil {
		t.Fatalf("loadDeployments: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 deployment, got %d", len(loaded))
	}
	if !loaded[0].Success {
		t.Error("expected successful deployment")
	}
}

func TestLogDeploy_FailedDeployment(t *testing.T) {
	dir := t.TempDir()
	DeploymentDir = dir
	defer func() { DeploymentDir = "" }()

	p := New()
	_, err := p.logDeploy(context.Background(), makeRunArgs(map[string]string{
		"service": "broken-svc",
		"failed":  "true",
	}))
	if err != nil {
		t.Fatalf("logDeploy: %v", err)
	}

	loaded, _ := loadDeployments()
	if loaded[0].Success {
		t.Error("expected failed deployment")
	}
}

func TestReport_NoData(t *testing.T) {
	dir := t.TempDir()
	DeploymentDir = dir
	incidentpkg.IncidentDir = dir
	defer func() {
		DeploymentDir = ""
		incidentpkg.IncidentDir = ""
	}()

	p := New()
	report, err := p.report(context.Background(), makeRunArgs(map[string]string{}))
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if report.Title == "" {
		t.Error("expected non-empty title")
	}
	// With no data, should indicate no deployments.
	if report.Summary == "" {
		t.Error("expected non-empty summary")
	}
}

func TestReport_InvalidDays(t *testing.T) {
	p := New()
	_, err := p.report(context.Background(), makeRunArgs(map[string]string{"days": "abc"}))
	if err == nil {
		t.Fatal("expected error for invalid --days value")
	}
}

func TestFormatHours(t *testing.T) {
	tests := []struct {
		hours float64
		want  string
	}{
		{0, "0m"},
		{0.25, "15m"},
		{1.5, "1.5h"},
		{48, "2.0d"},
	}
	for _, tt := range tests {
		got := formatHours(tt.hours)
		if got != tt.want {
			t.Errorf("formatHours(%.2f) = %q, want %q", tt.hours, got, tt.want)
		}
	}
}

// ─── Phase 4: lead time tests ────────────────────────────────────────────────

func TestCalculateDORA_LeadTimeElite(t *testing.T) {
	now := time.Now().UTC()
	commitTime := now.Add(-30 * time.Minute)
	deps := []DeploymentEvent{
		{
			ID:         "DEP-LT-1",
			Service:    "payments-api",
			DeployedAt: now,
			Success:    true,
			CommitSHA:  "abc123",
			CommitTime: commitTime,
		},
	}
	m := calculateDORA(30*24*time.Hour, deps, nil)
	if m.LeadTimeRating != BandElite {
		t.Errorf("expected Elite lead time band for 30min, got %s", m.LeadTimeRating)
	}
	if m.LeadTimeHours >= 1 {
		t.Errorf("expected LeadTimeHours < 1, got %.4f", m.LeadTimeHours)
	}
}

func TestCalculateDORA_LeadTimeNA(t *testing.T) {
	now := time.Now().UTC()
	// Deployment with no CommitTime → lead time must be N/A.
	deps := []DeploymentEvent{
		{
			ID:         "DEP-LT-2",
			Service:    "payments-api",
			DeployedAt: now,
			Success:    true,
		},
	}
	m := calculateDORA(30*24*time.Hour, deps, nil)
	if m.LeadTimeRating != BandNA {
		t.Errorf("expected N/A lead time band when CommitTime is zero, got %s", m.LeadTimeRating)
	}
}

func TestLogDeploy_WithCommit(t *testing.T) {
	dir := t.TempDir()
	DeploymentDir = dir
	defer func() { DeploymentDir = "" }()

	commitSHA := "deadbeefcafe1234"
	commitTime := time.Now().UTC().Add(-45 * time.Minute)

	p := New()
	_, err := p.logDeploy(context.Background(), makeRunArgs(map[string]string{
		"service":     "api-gateway",
		"version":     "v3.1.0",
		"commit":      commitSHA,
		"commit-time": commitTime.Format(time.RFC3339),
	}))
	if err != nil {
		t.Fatalf("logDeploy: %v", err)
	}

	loaded, err := loadDeployments()
	if err != nil {
		t.Fatalf("loadDeployments: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 deployment, got %d", len(loaded))
	}
	if loaded[0].CommitSHA != commitSHA {
		t.Errorf("CommitSHA: got %q, want %q", loaded[0].CommitSHA, commitSHA)
	}
	if loaded[0].CommitTime.IsZero() {
		t.Error("CommitTime should not be zero after log-deploy with --commit-time")
	}
}

func TestNewDeploymentID_Unique(t *testing.T) {
	now := time.Now().UTC()
	id1 := newDeploymentID(now)
	id2 := newDeploymentID(now)
	if id1 == id2 {
		t.Errorf("expected unique IDs, got duplicate: %s", id1)
	}
	if len(id1) < 10 {
		t.Errorf("ID too short: %q", id1)
	}
}
