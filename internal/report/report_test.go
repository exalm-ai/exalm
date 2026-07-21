package report

import (
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func sampleConv(id string) *plugin.Conversation {
	return &plugin.Conversation{
		ID: id, Focus: "prod/payment-api",
		Messages: []plugin.ConversationMessage{
			{Role: "user", Content: "Why is payment-api crashing?"},
			{Role: "assistant", Content: "It was OOM-killed.", Confidence: "high"},
		},
	}
}

func TestMarkdown_ExecutiveSummary(t *testing.T) {
	conv := sampleConv("c9")
	conv.Fingerprint = "oom-kill\x1fweb-01/nginx"
	conv.Messages[1].Score = 85
	conv.Messages[1].ScoreRationale = "kernel OOM line"
	conv.Messages[1].Hypotheses = []plugin.Hypothesis{{Title: "Memory exhaustion", Score: 85}}
	md := Markdown(conv)
	for _, want := range []string{"## Executive summary", "Memory exhaustion", "85%", "`oom-kill`", "Investigation turns:** 1"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown exec summary missing %q", want)
		}
	}
	// Existing structure preserved below the summary.
	if !strings.Contains(md, "## Question") || !strings.Contains(md, "## Answer") {
		t.Error("technical transcript sections missing")
	}
}

func TestMarkdown_FixPartitioning(t *testing.T) {
	conv := sampleConv("c1")
	conv.Messages[1].Fixes = []plugin.RemediationAction{
		{Description: "restart the pod", FixType: "temporary"},
		{Description: "raise the memory limit", FixType: "root-cause"},
	}
	md := Markdown(conv)
	tempIdx := strings.Index(md, "Immediate mitigation (temporary)")
	rootIdx := strings.Index(md, "Root-cause fix")
	if tempIdx < 0 || rootIdx < 0 || tempIdx > rootIdx {
		t.Fatalf("expected temporary section before root-cause section, got:\n%s", md)
	}
	if !strings.Contains(md[:rootIdx], "restart the pod") {
		t.Error("temporary fix should render under the temporary section")
	}
	if !strings.Contains(md[rootIdx:], "raise the memory limit") {
		t.Error("root-cause fix should render under the root-cause section")
	}
}

func TestHTML_EscapesHostileContent(t *testing.T) {
	conv := sampleConv("c1")
	conv.Messages[1].Evidence = []plugin.EvidenceItem{{
		Kind: "log", Source: "nginx", Label: "E1",
		Excerpt: `<script>alert("xss")</script> & <img src=x>`,
	}}
	html := HTML(conv, "syslog")
	if strings.Contains(html, `<script>alert`) {
		t.Fatal("HOSTILE CONTENT EMITTED UNESCAPED")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected the hostile excerpt to be escaped into the document")
	}
	if !strings.Contains(html, "syslog") {
		t.Error("expected the analyzer label in the meta line")
	}
}

func TestHTML_FixPartitioning(t *testing.T) {
	conv := sampleConv("c1")
	conv.Messages[1].Fixes = []plugin.RemediationAction{
		{Description: "restart the pod", FixType: "temporary"},
		{Description: "raise the memory limit", FixType: "root-cause"},
	}
	html := HTML(conv, "")
	if !strings.Contains(html, `class="fix-temp">restart the pod`) {
		t.Error("temporary fix should render in the fix-temp group")
	}
	if !strings.Contains(html, `class="fix-root">raise the memory limit`) {
		t.Error("root-cause fix should render in the fix-root group")
	}
}
