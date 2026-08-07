package eventlog

import (
	"strings"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

func findingByTitle(fs []plugin.Finding, sub string) (plugin.Finding, bool) {
	for _, f := range fs {
		if strings.Contains(f.Title, sub) {
			return f, true
		}
	}
	return plugin.Finding{}, false
}

func scmCrashSession(message string) *investigate.LogSession {
	s := investigate.NewLogSession("eventlog")
	src := s.AddSource(investigate.SourceDesc{Host: "win-01", Channel: "System"})
	s.Append(investigate.LogEvent{
		At: time.Now().UTC(), Severity: "Error", Unit: "Service Control Manager",
		Code: "7031", Message: message, Raw: message, Source: src,
	})
	return s
}

func (p *Plugin) profileForTest() investigate.Profile { return p.InvestigationProfile() }

func TestEventlogFindings_SingleTokenServiceProposesRestart(t *testing.T) {
	p := New()
	s := scmCrashSession("The Spooler service terminated unexpectedly. It has done this 3 time(s).")
	fs := investigate.FindingsFrom(p.profileForTest(), s, investigate.Target{}, "eventlog/win-01")

	f, ok := findingByTitle(fs, "Windows service crash")
	if !ok {
		t.Fatalf("expected a service-crash finding, got %+v", fs)
	}
	if f.Severity != plugin.SeverityHigh || f.Category != "Availability" {
		t.Errorf("header wrong: %+v", f)
	}
	if f.Remediation == nil {
		t.Fatalf("single-token service should propose a restart, got nil")
	}
	r := f.Remediation
	if r.Kind != "svc-restart-windows" || r.Name != "Spooler" || r.Shell != "powershell" {
		t.Errorf("remediation shape wrong: %+v", r)
	}
	if r.KubectlCmd != "Restart-Service -Name Spooler" {
		t.Errorf("display command wrong: %q", r.KubectlCmd)
	}
}

func TestEventlogFindings_MultiWordDisplayNameStaysAdviceOnly(t *testing.T) {
	p := New()
	// A multi-word display name cannot be safely turned into a -Name argument,
	// so the finding must NOT propose an executable restart.
	s := scmCrashSession("The World Wide Web Publishing Service service terminated unexpectedly.")
	fs := investigate.FindingsFrom(p.profileForTest(), s, investigate.Target{}, "eventlog/win-01")

	f, ok := findingByTitle(fs, "Windows service crash")
	if !ok {
		t.Fatalf("expected a service-crash finding, got %+v", fs)
	}
	if f.Remediation != nil {
		t.Errorf("multi-word service name must stay advice-only, got %+v", f.Remediation)
	}
}
