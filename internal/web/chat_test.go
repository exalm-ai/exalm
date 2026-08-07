package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func chatTestServer() *liveServer {
	srv := newTestServer(plugin.Report{Title: "t"})
	srv.chatSem = make(chan struct{}, maxConcurrentChats)
	return srv
}

func sampleConv(id string) *plugin.Conversation {
	return &plugin.Conversation{
		ID: id, Focus: "prod/payment-api",
		Messages: []plugin.ConversationMessage{
			{Role: "user", Content: "Why is payment-api crashing?"},
			{Role: "assistant", Content: "It was OOM-killed.", Confidence: "high"},
		},
	}
}

func TestHandleChat_Unwired503(t *testing.T) {
	srv := chatTestServer() // converseFn nil
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"message":"hi"}`))
	srv.handleChat(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when chat is unwired, got %d", rr.Code)
	}
}

func TestHandleChat_RequiresMessage(t *testing.T) {
	srv := chatTestServer()
	srv.converseFn = func(_ context.Context, req ConverseRequest) (*plugin.Conversation, error) {
		return sampleConv("c1"), nil
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"message":""}`))
	srv.handleChat(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for an empty message, got %d", rr.Code)
	}
}

func TestHandleChat_HappyPath(t *testing.T) {
	srv := chatTestServer()
	var gotReq ConverseRequest
	srv.converseFn = func(_ context.Context, req ConverseRequest) (*plugin.Conversation, error) {
		gotReq = req
		return sampleConv("c1"), nil
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"message":"Why is payment-api crashing?","namespace":"prod"}`))
	srv.handleChat(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	if gotReq.Message != "Why is payment-api crashing?" || gotReq.Namespace != "prod" {
		t.Errorf("converseFn did not receive the decoded request: %+v", gotReq)
	}
	if !strings.Contains(rr.Body.String(), "OOM-killed") {
		t.Errorf("expected the conversation reply in the response, got: %s", rr.Body.String())
	}
}

func TestHandleChat_MethodNotAllowed(t *testing.T) {
	srv := chatTestServer()
	srv.converseFn = func(_ context.Context, _ ConverseRequest) (*plugin.Conversation, error) { return sampleConv("c1"), nil }
	rr := httptest.NewRecorder()
	srv.handleChat(rr, httptest.NewRequest(http.MethodGet, "/api/chat", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", rr.Code)
	}
}

func TestHandleChat_ConcurrencyGate(t *testing.T) {
	srv := chatTestServer()
	srv.converseFn = func(_ context.Context, _ ConverseRequest) (*plugin.Conversation, error) { return sampleConv("c1"), nil }
	// Fill the semaphore to simulate maxConcurrentChats in-flight requests.
	for i := 0; i < maxConcurrentChats; i++ {
		srv.chatSem <- struct{}{}
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"message":"hi"}`))
	srv.handleChat(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 once the concurrency gate is full, got %d", rr.Code)
	}
}

func TestHandleGetConversation_Unwired503(t *testing.T) {
	srv := chatTestServer() // getConvoFn nil
	rr := httptest.NewRecorder()
	srv.handleGetConversation(rr, httptest.NewRequest(http.MethodGet, "/api/chat/c1", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when GetConversation is unwired, got %d", rr.Code)
	}
}

func TestHandleGetConversation_Found(t *testing.T) {
	srv := chatTestServer()
	srv.getConvoFn = func(_ context.Context, id string) (*plugin.Conversation, error) {
		if id != "c1" {
			t.Fatalf("expected id c1, got %q", id)
		}
		return sampleConv(id), nil
	}
	rr := httptest.NewRecorder()
	srv.handleGetConversation(rr, httptest.NewRequest(http.MethodGet, "/api/chat/c1", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "payment-api") {
		t.Errorf("expected the conversation body, got: %s", rr.Body.String())
	}
}

func TestHandleGetConversation_NotFound(t *testing.T) {
	srv := chatTestServer()
	srv.getConvoFn = func(_ context.Context, id string) (*plugin.Conversation, error) {
		return nil, errors.New("conversation not found")
	}
	rr := httptest.NewRecorder()
	srv.handleGetConversation(rr, httptest.NewRequest(http.MethodGet, "/api/chat/does-not-exist", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// ─── export endpoint ────────────────────────────────────────────────────────

func exportTestServer(t *testing.T) *liveServer {
	t.Helper()
	srv := chatTestServer()
	srv.getConvoFn = func(_ context.Context, id string) (*plugin.Conversation, error) {
		if id != "c1" {
			return nil, errors.New("conversation not found")
		}
		conv := sampleConv(id)
		conv.Focus = "prod/payment-api"
		conv.Messages[1].Score = 85
		conv.Messages[1].ScoreRationale = "recent change before first failure"
		conv.Messages[1].Plan = []plugin.PlanStep{{ID: "p1", Collector: "owner-chain", Edge: "pod→ownerDeployment", Reason: "check limits", Status: "done"}}
		conv.Messages[1].Hypotheses = []plugin.Hypothesis{{Title: "Memory limit too low", Score: 85, Rationale: "supported by [E1]", EvidenceFor: []string{"E1"}}}
		conv.Messages[1].Evidence = []plugin.EvidenceItem{{Kind: "log", Source: "pod/payment-api", Excerpt: "OOMKilled", Label: "E1", Anchor: "kubectl logs payment-api -n prod --previous"}}
		conv.Messages[1].Prevention = []plugin.RemediationAction{{Kind: "advice", FixType: "prevention", Description: "Alert at 80% of the memory limit"}}
		return conv, nil
	}
	return srv
}

func TestHandleGetConversation_ExportMarkdown(t *testing.T) {
	srv := exportTestServer(t)
	rr := httptest.NewRecorder()
	srv.handleGetConversation(rr, httptest.NewRequest(http.MethodGet, "/api/chat/c1/export?format=md", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("Content-Type: %q", ct)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "investigation-c1.md") {
		t.Errorf("Content-Disposition: %q", cd)
	}
	body := rr.Body.String()
	for _, want := range []string{"# Investigation report", "prod/payment-api", "confidence 85%", "### Investigation plan", "owner-chain", "### Hypotheses considered", "Memory limit too low", "**[E1]**", "kubectl logs payment-api", "### Prevention"} {
		if !strings.Contains(body, want) {
			t.Errorf("markdown export missing %q", want)
		}
	}
}

func TestHandleGetConversation_ExportJSONAndDefaultFormat(t *testing.T) {
	srv := exportTestServer(t)
	rr := httptest.NewRecorder()
	srv.handleGetConversation(rr, httptest.NewRequest(http.MethodGet, "/api/chat/c1/export?format=json", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("json export: expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"scoreRationale"`) {
		t.Errorf("json export should use the camelCase DTO, got: %s", rr.Body.String()[:200])
	}

	// Default format (no query) is markdown.
	rr2 := httptest.NewRecorder()
	srv.handleGetConversation(rr2, httptest.NewRequest(http.MethodGet, "/api/chat/c1/export", nil))
	if !strings.HasPrefix(rr2.Header().Get("Content-Type"), "text/markdown") {
		t.Errorf("default export format should be markdown, got %q", rr2.Header().Get("Content-Type"))
	}
}

func TestHandleGetConversation_ExportErrors(t *testing.T) {
	srv := exportTestServer(t)

	rr := httptest.NewRecorder()
	srv.handleGetConversation(rr, httptest.NewRequest(http.MethodGet, "/api/chat/c1/export?format=pdf", nil))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unsupported format should 400, got %d", rr.Code)
	}

	rr2 := httptest.NewRecorder()
	srv.handleGetConversation(rr2, httptest.NewRequest(http.MethodGet, "/api/chat/nope/export", nil))
	if rr2.Code != http.StatusNotFound {
		t.Errorf("unknown id export should 404, got %d", rr2.Code)
	}
}

// ─── /api/logs/analyze ──────────────────────────────────────────────────────

func TestHandleLogAnalyze(t *testing.T) {
	srv := chatTestServer()

	// Unwired → 503.
	rr := httptest.NewRecorder()
	srv.handleLogAnalyze(rr, httptest.NewRequest(http.MethodPost, "/api/logs/analyze", strings.NewReader(`{"message":"x"}`)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("unwired should 503, got %d", rr.Code)
	}

	var got LogAnalyzeRequest
	srv.logAnalyzeFn = func(_ context.Context, req LogAnalyzeRequest) (string, error) {
		got = req
		return "## Root Cause Analysis\nOOM.", nil
	}

	// Happy path.
	rr = httptest.NewRecorder()
	body := `{"namespace":"prod","pod":"payment-api","message":"OOMKilled","context":"a\nb"}`
	srv.handleLogAnalyze(rr, httptest.NewRequest(http.MethodPost, "/api/logs/analyze", strings.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	if got.Pod != "payment-api" || got.Message != "OOMKilled" {
		t.Errorf("decoded request wrong: %+v", got)
	}
	if !strings.Contains(rr.Body.String(), "Root Cause Analysis") {
		t.Errorf("expected the analysis in the response: %s", rr.Body.String())
	}

	// Empty message → 400.
	rr = httptest.NewRecorder()
	srv.handleLogAnalyze(rr, httptest.NewRequest(http.MethodPost, "/api/logs/analyze", strings.NewReader(`{"message":""}`)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("empty message should 400, got %d", rr.Code)
	}

	// GET → 405.
	rr = httptest.NewRecorder()
	srv.handleLogAnalyze(rr, httptest.NewRequest(http.MethodGet, "/api/logs/analyze", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET should 405, got %d", rr.Code)
	}

	// Concurrency gate shared with chat → 429 when full.
	for i := 0; i < maxConcurrentChats; i++ {
		srv.chatSem <- struct{}{}
	}
	rr = httptest.NewRecorder()
	srv.handleLogAnalyze(rr, httptest.NewRequest(http.MethodPost, "/api/logs/analyze", strings.NewReader(`{"message":"x"}`)))
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("full gate should 429, got %d", rr.Code)
	}
}

func TestHandleGetConversation_ExportHTMLAndEscaping(t *testing.T) {
	srv := exportTestServer(t)
	srv.analyzer = "syslog"
	srv.getConvoFn = func(_ context.Context, id string) (*plugin.Conversation, error) {
		conv := sampleConv(id)
		conv.Focus = "web-01/nginx.service"
		conv.Fingerprint = "oom-kill\x1fweb-01/nginx.service"
		conv.Messages[1].Score = 85
		conv.Messages[1].ScoreRationale = "kernel OOM line"
		conv.Messages[1].Hypotheses = []plugin.Hypothesis{{Title: "Memory exhaustion", Score: 85}}
		// Hostile content must come out escaped, never as markup.
		conv.Messages[1].Evidence = []plugin.EvidenceItem{{
			Kind: "log", Source: "nginx", Label: "E1",
			Excerpt: `<script>alert("xss")</script> & <img src=x>`,
		}}
		return conv, nil
	}

	rr := httptest.NewRecorder()
	srv.handleGetConversation(rr, httptest.NewRequest(http.MethodGet, "/api/chat/c1/export?format=html", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type: %q", ct)
	}
	body := rr.Body.String()
	for _, want := range []string{"<h1>", "Executive summary", "Memory exhaustion", "85%", "oom-kill", "syslog", "@media print"} {
		if !strings.Contains(body, want) {
			t.Errorf("html export missing %q", want)
		}
	}
	if strings.Contains(body, `<script>alert`) {
		t.Fatal("HOSTILE CONTENT EMITTED UNESCAPED")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("expected the hostile excerpt to be escaped into the document")
	}
}
