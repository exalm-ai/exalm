package syslog

import (
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// findingByTitle returns the first finding whose title contains sub, or a zero
// Finding when none match.
func findingByTitle(fs []plugin.Finding, sub string) (plugin.Finding, bool) {
	for _, f := range fs {
		if contains(f.Title, sub) {
			return f, true
		}
	}
	return plugin.Finding{}, false
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestSyslogFindings_OOMKillIsCritical(t *testing.T) {
	fs := investigate.FindingsFrom(syslogProfile(), oomSession(), investigate.Target{}, "syslog/web-01")
	f, ok := findingByTitle(fs, "Out-of-memory")
	if !ok {
		t.Fatalf("expected an OOM finding, got %+v", fs)
	}
	if f.Severity != plugin.SeverityCritical || f.Category != "Reliability" {
		t.Errorf("OOM finding header wrong: %+v", f)
	}
	if f.Source != "syslog/web-01" {
		t.Errorf("source not threaded through: %q", f.Source)
	}
	if f.Detail == "" || f.RootCause == "" {
		t.Errorf("expected populated Detail/RootCause, got %+v", f)
	}
	// OOM has no executable remediation (restart is not the root-cause fix).
	if f.Remediation != nil {
		t.Errorf("OOM should be advice-only, got remediation %+v", f.Remediation)
	}
}

// serviceFailureSession builds a corpus with a systemd unit failure naming a
// single-token unit, so the service-failure Remediate hook can extract it.
func serviceFailureSession() *investigate.LogSession {
	s := investigate.NewLogSession("syslog")
	src := s.AddSource(investigate.SourceDesc{Path: "/var/log/syslog"})
	now := time.Now().UTC()
	s.Append(
		investigate.LogEvent{At: now, Severity: "err", Unit: "nginx.service",
			Message: "nginx.service: Failed to start The nginx web server.",
			Raw:     "systemd[1]: nginx.service: Failed to start The nginx web server.", Source: src},
	)
	return s
}

func TestSyslogFindings_ServiceFailureProposesRestart(t *testing.T) {
	fs := investigate.FindingsFrom(syslogProfile(), serviceFailureSession(), investigate.Target{}, "syslog/db-02")
	f, ok := findingByTitle(fs, "service failure")
	if !ok {
		t.Fatalf("expected a service-failure finding, got %+v", fs)
	}
	if f.Severity != plugin.SeverityHigh || f.Category != "Availability" {
		t.Errorf("service-failure header wrong: %+v", f)
	}
	if f.Remediation == nil {
		t.Fatalf("expected an executable remediation, got nil")
	}
	r := f.Remediation
	if r.Kind != "svc-restart-linux" || r.Name != "nginx.service" || r.Shell != "bash" {
		t.Errorf("remediation shape wrong: %+v", r)
	}
	if r.KubectlCmd != "systemctl restart nginx.service" {
		t.Errorf("display command wrong: %q", r.KubectlCmd)
	}
	if r.FixType != "temporary" || r.Risk == "" || r.Warning == "" {
		t.Errorf("remediation should be classified temporary with a warning: %+v", r)
	}
}

func TestSyslogFindings_EmptyCorpusNoFindings(t *testing.T) {
	fs := investigate.FindingsFrom(syslogProfile(), investigate.NewLogSession("syslog"), investigate.Target{}, "syslog")
	if len(fs) != 0 {
		t.Errorf("empty corpus should yield no findings, got %+v", fs)
	}
}
