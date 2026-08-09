package investigate

// logsession_collectors_test.go — the shared corpus collectors: search,
// window, frequency, stats summary, and the diag wrapper's tier gating +
// redaction.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func collectorSession() *LogSession {
	s := NewLogSession("syslog")
	src := s.AddSource(SourceDesc{Path: "/var/log/syslog"})
	base := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	s.Append(
		LogEvent{At: base, Severity: "info", Scope: "web-01", Unit: "nginx.service", Message: "started", Raw: "12:00 nginx started", Source: src},
		LogEvent{At: base.Add(time.Minute), Severity: "err", Scope: "web-01", Unit: "nginx.service", Message: "worker crashed token sk-corpus-secret", Raw: "12:01 nginx worker crashed token sk-corpus-secret", Source: src},
		LogEvent{At: base.Add(time.Minute), Severity: "err", Scope: "web-01", Unit: "nginx.service", Message: "upstream timed out", Raw: "12:01 upstream timed out", Source: src},
		LogEvent{At: base.Add(2 * time.Minute), Severity: "crit", Scope: "web-01", Unit: "kernel", Message: "Out of memory", Raw: "12:02 kernel: Out of memory", Source: src},
	)
	return s
}

func collectCtxFor(s *LogSession, unit string) CollectCtx {
	return CollectCtx{
		Target: Target{Scope: "web-01", Name: unit}, Focus: "web-01/" + unit,
		Now: time.Now(), Facts: s, Red: toyRedactorCorpus{},
	}
}

type toyRedactorCorpus struct{}

func (toyRedactorCorpus) Redact(in string) string {
	return strings.ReplaceAll(in, "sk-corpus-secret", "[REDACTED]")
}

func TestCorpusSearchCollector_MatchesAndRedacts(t *testing.T) {
	s := collectorSession()
	col := CorpusSearchCollector("Crash lines searched", Re(`crashed|out of memory`), "grep -i crashed /var/log/syslog")
	steps, evid := col(context.Background(), collectCtxFor(s, "nginx.service"))
	if steps[0].Status != "done" || len(evid) != 1 {
		t.Fatalf("steps=%+v evid=%+v", steps, evid)
	}
	if strings.Contains(evid[0].Excerpt, "sk-corpus-secret") {
		t.Fatal("SECRET LEAKED into corpus evidence")
	}
	if !strings.Contains(evid[0].Excerpt, "[REDACTED]") {
		t.Errorf("expected redaction marker: %q", evid[0].Excerpt)
	}
	if evid[0].Anchor == "" {
		t.Error("search evidence must carry the reproduce anchor")
	}

	// No focus → whole corpus (kernel OOM matches too).
	_, evidAll := col(context.Background(), CollectCtx{Facts: s, Red: toyRedactorCorpus{}})
	if len(evidAll) != 2 {
		t.Errorf("corpus-wide search should hit 2, got %d", len(evidAll))
	}
}

func TestCorpusWindowCollector_AroundWorstEvent(t *testing.T) {
	s := collectorSession()
	col := CorpusWindowCollector("Lines around the failure", 2*time.Minute, 2*time.Minute)
	steps, evid := col(context.Background(), CollectCtx{Facts: s, Red: toyRedactorCorpus{}})
	if steps[0].Status != "done" || len(evid) != 1 {
		t.Fatalf("steps=%+v evid=%+v", steps, evid)
	}
	// Worst event is the kernel crit at 12:02; window covers all 4 lines.
	if !strings.Contains(evid[0].Excerpt, "nginx started") || !strings.Contains(evid[0].Excerpt, "Out of memory") {
		t.Errorf("window excerpt: %q", evid[0].Excerpt)
	}
}

func TestCorpusFrequencyCollector_Buckets(t *testing.T) {
	s := collectorSession()
	col := CorpusFrequencyCollector("Error rate profiled")
	steps, evid := col(context.Background(), CollectCtx{Facts: s, Red: toyRedactorCorpus{}})
	if steps[0].Status != "done" || len(evid) != 1 {
		t.Fatalf("steps=%+v evid=%+v", steps, evid)
	}
	if !strings.Contains(evid[0].Excerpt, "3 error-class events") || !strings.Contains(evid[0].Excerpt, "12:01 → 2/min") {
		t.Errorf("frequency excerpt: %q", evid[0].Excerpt)
	}
}

func TestStatsSummaryCollector(t *testing.T) {
	s := collectorSession()
	s.Stats = map[string]int{"errors": 3}
	col := StatsSummaryCollector("Stats summarized", func(stats any) string {
		m, _ := stats.(map[string]int)
		return fmt.Sprintf("errors=%d", m["errors"])
	})
	_, evid := col(context.Background(), CollectCtx{Facts: s, Red: toyRedactorCorpus{}})
	if len(evid) != 1 || evid[0].Excerpt != "errors=3" {
		t.Errorf("stats evidence: %+v", evid)
	}

	empty := NewLogSession("syslog")
	steps, _ := col(context.Background(), CollectCtx{Facts: empty})
	if steps[0].Status != "unavailable" {
		t.Errorf("no stats should be unavailable: %+v", steps)
	}
}

func TestDiagCollector_TierGatingAndRedaction(t *testing.T) {
	run := func(_ context.Context, _ *LogSession, name, param string) (string, string, error) {
		return "MemFree: 128 MB token sk-corpus-secret (param=" + param + ")", "free -m on the remote host", nil
	}
	col := DiagCollector("Memory checked", "sys-memory", func(cc CollectCtx) string { return cc.Target.Name }, run)

	// No SSH attached.
	local := collectorSession()
	steps, _ := col(context.Background(), CollectCtx{Facts: local})
	if steps[0].Status != "unavailable" || !strings.Contains(steps[0].Detail, "no remote host") {
		t.Errorf("local session: %+v", steps)
	}

	// Tier off.
	remote := collectorSession()
	remote.SSH = &RemoteParams{Host: "web-01", OSFamily: "linux"}
	remote.DiagTier = "off"
	steps, _ = col(context.Background(), CollectCtx{Facts: remote})
	if steps[0].Status != "unavailable" || !strings.Contains(steps[0].Detail, "disabled") {
		t.Errorf("tier off: %+v", steps)
	}

	// Enabled: runs, redacts, anchors with the description.
	remote.DiagTier = "readonly"
	steps, evid := col(context.Background(), collectCtxWithSSH(remote, "nginx.service"))
	if steps[0].Status != "done" || len(evid) != 1 {
		t.Fatalf("enabled: steps=%+v evid=%+v", steps, evid)
	}
	if strings.Contains(evid[0].Excerpt, "sk-corpus-secret") {
		t.Fatal("SECRET LEAKED from diagnostic output")
	}
	if !strings.Contains(evid[0].Excerpt, "param=nginx.service") {
		t.Errorf("param not threaded: %q", evid[0].Excerpt)
	}

	// Runner error → unavailable step, never a hard failure.
	failing := DiagCollector("Memory checked", "sys-memory", nil, func(_ context.Context, _ *LogSession, _, _ string) (string, string, error) {
		return "", "", fmt.Errorf("ssh: connection refused")
	})
	steps, _ = failing(context.Background(), collectCtxWithSSH(remote, ""))
	if steps[0].Status != "unavailable" || !strings.Contains(steps[0].Detail, "connection refused") {
		t.Errorf("runner error: %+v", steps)
	}
}

func collectCtxWithSSH(s *LogSession, unit string) CollectCtx {
	cc := collectCtxFor(s, unit)
	cc.Facts = s
	return cc
}
