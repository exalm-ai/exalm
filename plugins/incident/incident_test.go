package incident

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// --- test doubles ---

// fakeLLM implements plugin.LLMClient for testing.
type fakeLLM struct {
	response string
	err      error
}

func (f *fakeLLM) Name() string { return "fake" }

func (f *fakeLLM) Complete(_ context.Context, _ plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	return plugin.CompleteResponse{Content: f.response}, f.err
}

// noopRedactor implements plugin.Redactor; returns the input unchanged.
type noopRedactor struct{}

func (noopRedactor) Redact(s string) string { return s }

// newTestPlugin returns a Plugin backed by the file store pointed at dir.
func newTestPlugin(dir string) *Plugin {
	IncidentDir = dir
	return &Plugin{store: newFileStore()}
}

// baseArgs returns a minimal RunArgs with working fakes.
func baseArgs(flags map[string]string) plugin.RunArgs {
	return plugin.RunArgs{
		Flags:    flags,
		LLM:      &fakeLLM{response: "{}"},
		Redactor: noopRedactor{},
	}
}

// --- TestOpen_CreatesIncident ---

func TestOpen_CreatesIncident(t *testing.T) {
	dir := t.TempDir()
	p := newTestPlugin(dir)

	report, err := p.open(context.Background(), baseArgs(map[string]string{
		"title":    "Payment service down",
		"severity": "critical",
	}))
	if err != nil {
		t.Fatalf("open returned error: %v", err)
	}
	if !strings.Contains(report.Summary, "opened") {
		t.Errorf("expected 'opened' in summary, got: %s", report.Summary)
	}

	// The incident file should now exist and be readable.
	incidents, err := p.store.List(context.Background())
	if err != nil {
		t.Fatalf("list returned error: %v", err)
	}
	if len(incidents) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(incidents))
	}
	inc := incidents[0]
	if inc.Title != "Payment service down" {
		t.Errorf("unexpected title: %s", inc.Title)
	}
	if inc.Severity != plugin.SeverityCritical {
		t.Errorf("unexpected severity: %s", inc.Severity)
	}
	if inc.Status != IncidentOpen {
		t.Errorf("unexpected status: %s", inc.Status)
	}
}

func TestOpen_DefaultSeverity(t *testing.T) {
	dir := t.TempDir()
	p := newTestPlugin(dir)

	_, err := p.open(context.Background(), baseArgs(map[string]string{
		"title": "Disk filling up",
	}))
	if err != nil {
		t.Fatalf("open returned error: %v", err)
	}

	incidents, _ := p.store.List(context.Background())
	if incidents[0].Severity != plugin.SeverityMedium {
		t.Errorf("expected default severity medium, got %s", incidents[0].Severity)
	}
}

func TestOpen_RequiresTitle(t *testing.T) {
	dir := t.TempDir()
	p := newTestPlugin(dir)

	_, err := p.open(context.Background(), baseArgs(map[string]string{}))
	if err == nil {
		t.Fatal("expected error when title is missing")
	}
}

// --- TestList_FormatsTable ---

func TestList_FormatsTable(t *testing.T) {
	dir := t.TempDir()
	p := newTestPlugin(dir)
	ctx := context.Background()

	for _, title := range []string{"Alpha incident", "Beta incident"} {
		_, err := p.open(ctx, baseArgs(map[string]string{"title": title}))
		if err != nil {
			t.Fatalf("open %q: %v", title, err)
		}
	}

	report, err := p.list(ctx, baseArgs(map[string]string{}))
	if err != nil {
		t.Fatalf("list returned error: %v", err)
	}
	if !strings.Contains(report.Raw, "Alpha incident") {
		t.Errorf("table missing Alpha incident:\n%s", report.Raw)
	}
	if !strings.Contains(report.Raw, "Beta incident") {
		t.Errorf("table missing Beta incident:\n%s", report.Raw)
	}
	// Should have a markdown table header.
	if !strings.Contains(report.Raw, "| ID |") {
		t.Errorf("table header not found:\n%s", report.Raw)
	}
}

func TestList_StatusFilter(t *testing.T) {
	dir := t.TempDir()
	p := newTestPlugin(dir)
	ctx := context.Background()

	_, _ = p.open(ctx, baseArgs(map[string]string{"title": "Open one"}))

	// Manually open a second incident and immediately close it.
	_, _ = p.open(ctx, baseArgs(map[string]string{"title": "Closed one", "severity": "low"}))
	incidents, _ := p.store.List(ctx)
	// incidents are sorted newest-first; the second open is incidents[0].
	incToClose := incidents[0]
	_, _ = p.close(ctx, baseArgs(map[string]string{"incident-id": incToClose.ID}))

	// Filter for open only.
	report, err := p.list(ctx, baseArgs(map[string]string{"status": "open"}))
	if err != nil {
		t.Fatalf("list returned error: %v", err)
	}
	if strings.Contains(report.Raw, "Closed one") {
		t.Errorf("closed incident should be filtered out:\n%s", report.Raw)
	}
	if !strings.Contains(report.Raw, "Open one") {
		t.Errorf("open incident should appear:\n%s", report.Raw)
	}
}

func TestList_EmptyState(t *testing.T) {
	dir := t.TempDir()
	p := newTestPlugin(dir)

	report, err := p.list(context.Background(), baseArgs(map[string]string{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(report.Summary, "No incidents") {
		t.Errorf("expected empty-state message, got: %s", report.Summary)
	}
}

// --- TestClose_SetsClosedAt ---

func TestClose_SetsClosedAt(t *testing.T) {
	dir := t.TempDir()
	p := newTestPlugin(dir)
	ctx := context.Background()

	_, err := p.open(ctx, baseArgs(map[string]string{
		"title":    "DB failover",
		"severity": "high",
	}))
	if err != nil {
		t.Fatalf("open error: %v", err)
	}

	incidents, _ := p.store.List(ctx)
	incID := incidents[0].ID

	report, err := p.close(ctx, baseArgs(map[string]string{"incident-id": incID}))
	if err != nil {
		t.Fatalf("close error: %v", err)
	}
	if !strings.Contains(report.Summary, "closed") {
		t.Errorf("expected 'closed' in summary: %s", report.Summary)
	}
	// MTTR must appear in summary.
	if !strings.Contains(report.Summary, "MTTR") {
		t.Errorf("expected MTTR in summary: %s", report.Summary)
	}

	// Verify ClosedAt is persisted.
	updated, err := p.store.Get(ctx, incID)
	if err != nil {
		t.Fatalf("get after close: %v", err)
	}
	if updated.Status != IncidentClosed {
		t.Errorf("expected status closed, got %s", updated.Status)
	}
	if updated.ClosedAt == nil {
		t.Error("ClosedAt should not be nil after close")
	}
}

func TestClose_RequiresID(t *testing.T) {
	dir := t.TempDir()
	p := newTestPlugin(dir)

	_, err := p.close(context.Background(), baseArgs(map[string]string{}))
	if err == nil {
		t.Fatal("expected error when incident-id is missing")
	}
}

// --- TestPostmortem_CallsLLM ---

func TestPostmortem_CallsLLM(t *testing.T) {
	dir := t.TempDir()
	p := newTestPlugin(dir)
	ctx := context.Background()

	// Open and close an incident so postmortem has a ClosedAt to compute MTTR.
	_, _ = p.open(ctx, baseArgs(map[string]string{
		"title":    "Redis eviction storm",
		"severity": "high",
	}))
	incidents, _ := p.store.List(ctx)
	incID := incidents[0].ID
	_, _ = p.close(ctx, baseArgs(map[string]string{"incident-id": incID}))

	// Prepare a fake LLM response that matches the expected JSON schema.
	llmJSON, _ := json.Marshal(postmortemLLMResponse{
		Summary:             "Redis ran out of memory due to missing eviction policy.",
		RootCauses:          []string{"No maxmemory-policy configured"},
		ContributingFactors: []string{"Sudden traffic spike"},
		Mitigation:          "Set maxmemory-policy to allkeys-lru and restarted Redis.",
		ActionItems:         []string{"Add eviction policy to Terraform config"},
	})

	args := plugin.RunArgs{
		Flags:    map[string]string{"incident-id": incID},
		LLM:      &fakeLLM{response: string(llmJSON)},
		Redactor: noopRedactor{},
	}

	report, err := p.postmortem(ctx, args)
	if err != nil {
		t.Fatalf("postmortem error: %v", err)
	}
	if !strings.Contains(report.Summary, incID) {
		t.Errorf("expected incident ID in summary: %s", report.Summary)
	}
	if !strings.Contains(report.Summary, "MTTR") {
		t.Errorf("expected MTTR in summary: %s", report.Summary)
	}

	// Postmortem should be persisted on the incident record.
	updated, err := p.store.Get(ctx, incID)
	if err != nil {
		t.Fatalf("get after postmortem: %v", err)
	}
	if updated.Postmortem == nil {
		t.Fatal("postmortem not persisted on incident record")
	}
	if updated.Postmortem.Summary == "" {
		t.Error("persisted postmortem has empty summary")
	}
	if len(updated.Postmortem.ActionItems) == 0 {
		t.Error("persisted postmortem has no action items")
	}
}

func TestPostmortem_LLMJSONParseFailure(t *testing.T) {
	dir := t.TempDir()
	p := newTestPlugin(dir)
	ctx := context.Background()

	_, _ = p.open(ctx, baseArgs(map[string]string{"title": "Flaky service"}))
	incidents, _ := p.store.List(ctx)
	incID := incidents[0].ID

	// Respond with non-JSON to exercise the fallback path.
	args := plugin.RunArgs{
		Flags:    map[string]string{"incident-id": incID},
		LLM:      &fakeLLM{response: "I cannot produce a postmortem — timeline is empty."},
		Redactor: noopRedactor{},
	}

	report, err := p.postmortem(ctx, args)
	if err != nil {
		t.Fatalf("postmortem error: %v", err)
	}
	// The report should still contain something useful.
	if report.Summary == "" {
		t.Error("expected non-empty summary even on parse failure")
	}
}

// --- TestOpen_WithRelatedDeploy ---

func TestOpen_WithRelatedDeploy(t *testing.T) {
	dir := t.TempDir()
	p := newTestPlugin(dir)
	ctx := context.Background()

	deployID := "DEP-20260115-120000-001"
	report, err := p.open(ctx, baseArgs(map[string]string{
		"title":       "Payments latency spike",
		"severity":    "high",
		"from-deploy": deployID,
	}))
	if err != nil {
		t.Fatalf("open returned error: %v", err)
	}

	// The finding detail should mention the deploy ID.
	if len(report.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	detail := report.Findings[0].Detail
	if !strings.Contains(detail, deployID) {
		t.Errorf("finding detail should contain deploy ID %q, got: %s", deployID, detail)
	}

	// The persisted incident must carry RelatedDeploymentID.
	incidents, err := p.store.List(ctx)
	if err != nil {
		t.Fatalf("list error: %v", err)
	}
	if len(incidents) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(incidents))
	}
	if incidents[0].RelatedDeploymentID != deployID {
		t.Errorf("RelatedDeploymentID: got %q, want %q", incidents[0].RelatedDeploymentID, deployID)
	}
}

// --- TestFileStore_ConcurrentCreate ---

// TestFileStore_ConcurrentCreate verifies that concurrent Create calls on
// different incident IDs do not corrupt each other's files and that all
// incidents are readable afterwards.
func TestFileStore_ConcurrentCreate(t *testing.T) {
	dir := t.TempDir()
	IncidentDir = dir
	s := newFileStore()
	ctx := context.Background()

	const n = 20
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			inc := Incident{
				ID:       newIncidentID(time.Now()),
				Title:    "concurrent incident",
				Status:   IncidentOpen,
				Severity: plugin.SeverityLow,
				OpenedAt: time.Now(),
			}
			errs[i] = s.Create(ctx, inc)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: Create error: %v", i, err)
		}
	}

	incidents, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List after concurrent creates: %v", err)
	}
	if len(incidents) != n {
		t.Errorf("expected %d incidents, got %d", n, len(incidents))
	}
}

// TestFileStore_ConcurrentUpdate verifies that concurrent Update calls on the
// same incident do not panic or corrupt the JSON file (last-write-wins).
func TestFileStore_ConcurrentUpdate(t *testing.T) {
	dir := t.TempDir()
	IncidentDir = dir
	s := newFileStore()
	ctx := context.Background()

	inc := Incident{
		ID:       "INC-CONCURRENT-001",
		Title:    "base incident",
		Status:   IncidentOpen,
		Severity: plugin.SeverityHigh,
		OpenedAt: time.Now(),
	}
	if err := s.Create(ctx, inc); err != nil {
		t.Fatalf("Create: %v", err)
	}

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			updated := inc
			updated.Title = "updated"
			_ = s.Update(ctx, updated) // last-write-wins; no panic expected
		}()
	}
	wg.Wait()

	// After all concurrent updates, the file must be valid JSON.
	result, err := s.Get(ctx, inc.ID)
	if err != nil {
		t.Fatalf("Get after concurrent updates: %v", err)
	}
	if result.ID != inc.ID {
		t.Errorf("ID corrupted: got %q, want %q", result.ID, inc.ID)
	}
}

// --- TestQueryByDateRange ---

func TestQueryByDateRange(t *testing.T) {
	dir := t.TempDir()
	IncidentDir = dir
	s := newFileStore()
	ctx := context.Background()

	base := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	inc1 := Incident{ID: "INC-20260115-120000", Title: "A", Status: IncidentOpen, Severity: plugin.SeverityHigh, OpenedAt: base}
	inc2 := Incident{ID: "INC-20260110-120000", Title: "B", Status: IncidentOpen, Severity: plugin.SeverityLow, OpenedAt: base.AddDate(0, 0, -5)}
	inc3 := Incident{ID: "INC-20260120-120000", Title: "C", Status: IncidentOpen, Severity: plugin.SeverityMedium, OpenedAt: base.AddDate(0, 0, 5)}

	for _, inc := range []Incident{inc1, inc2, inc3} {
		if err := s.Create(ctx, inc); err != nil {
			t.Fatalf("create %s: %v", inc.ID, err)
		}
	}

	from := base.AddDate(0, 0, -3)
	to := base.AddDate(0, 0, 3)

	result, err := s.QueryByDateRange(ctx, from, to)
	if err != nil {
		t.Fatalf("QueryByDateRange: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
	if result[0].ID != inc1.ID {
		t.Errorf("expected %s, got %s", inc1.ID, result[0].ID)
	}
}
