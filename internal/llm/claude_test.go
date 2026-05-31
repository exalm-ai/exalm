package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// claudeServer spins up a test HTTP server that mimics the Anthropic Messages
// endpoint at POST /v1/messages.
func claudeServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

// happyClaudeHandler returns a valid Anthropic Messages response.
func happyClaudeHandler(text string, inputTok, outputTok int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(claudeResponse{ //nolint:errcheck
			Content: []claudeContentBlock{
				{Type: "text", Text: text},
			},
			Usage: claudeUsage{
				InputTokens:  inputTok,
				OutputTokens: outputTok,
			},
		})
	}
}

// ---- constructor tests ----

func TestNewClaude_missingKey(t *testing.T) {
	_, err := NewClaude(ClaudeOptions{})
	if err == nil {
		t.Fatal("expected error for empty API key")
	}
	if !strings.Contains(err.Error(), "ANTHROPIC_API_KEY") {
		t.Errorf("error should mention ANTHROPIC_API_KEY, got: %v", err)
	}
}

func TestNewClaude_DefaultModel(t *testing.T) {
	c, err := NewClaude(ClaudeOptions{APIKey: "sk-ant-EXAMPLE"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.model != DefaultClaudeModel {
		t.Errorf("default model = %q, want %q", c.model, DefaultClaudeModel)
	}
}

func TestNewClaude_DefaultBaseURL(t *testing.T) {
	c, err := NewClaude(ClaudeOptions{APIKey: "sk-ant-EXAMPLE"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.baseURL != defaultClaudeBaseURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, defaultClaudeBaseURL)
	}
}

func TestNewClaude_TrailingSlashStripped(t *testing.T) {
	c, err := NewClaude(ClaudeOptions{APIKey: "sk-ant-EXAMPLE", BaseURL: "http://localhost:9000/"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasSuffix(c.baseURL, "/") {
		t.Errorf("baseURL should have trailing slash stripped, got %q", c.baseURL)
	}
}

// ---- Name test ----

func TestClaude_Name(t *testing.T) {
	c, _ := NewClaude(ClaudeOptions{APIKey: "sk-ant-EXAMPLE"})
	if c.Name() != "claude" {
		t.Errorf("Name() = %q, want claude", c.Name())
	}
}

// ---- Complete() tests ----

func TestClaude_Complete_success(t *testing.T) {
	srv := claudeServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify request path and method.
		if r.URL.Path != "/v1/messages" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		// Verify required Anthropic headers.
		if r.Header.Get("X-Api-Key") == "" {
			t.Error("missing X-Api-Key header")
		}
		if r.Header.Get("Anthropic-Version") == "" {
			t.Error("missing Anthropic-Version header")
		}
		// Verify request body is decodable.
		var body claudeRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		happyClaudeHandler("Root cause: OOM killer.", 60, 15)(w, r)
	})
	defer srv.Close()

	client, err := NewClaude(ClaudeOptions{
		APIKey:  "sk-ant-EXAMPLE",
		Model:   DefaultClaudeModel,
		BaseURL: srv.URL + "/v1",
		HTTP:    srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewClaude: %v", err)
	}

	resp, err := client.Complete(context.Background(), plugin.CompleteRequest{
		System:    "You are an SRE.",
		Messages:  []plugin.Message{{Role: "user", Content: "What failed?"}},
		MaxTokens: 256,
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Content != "Root cause: OOM killer." {
		t.Errorf("content = %q, want %q", resp.Content, "Root cause: OOM killer.")
	}
	if resp.InputTokens != 60 || resp.OutputTokens != 15 {
		t.Errorf("tokens: input=%d output=%d, want 60/15", resp.InputTokens, resp.OutputTokens)
	}
}

func TestClaude_Complete_apiError(t *testing.T) {
	srv := claudeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error","message":"invalid model"}}`))
	})
	defer srv.Close()

	client, _ := NewClaude(ClaudeOptions{
		APIKey:  "sk-ant-EXAMPLE",
		BaseURL: srv.URL + "/v1",
		HTTP:    srv.Client(),
	})
	_, err := client.Complete(context.Background(), plugin.CompleteRequest{
		Messages: []plugin.Message{{Role: "user", Content: "hello"}},
	})

	if err == nil {
		t.Fatal("expected error for HTTP 400")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should contain status code 400, got: %v", err)
	}
}

func TestClaude_Complete_emptyContent(t *testing.T) {
	srv := claudeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(claudeResponse{ //nolint:errcheck
			Content: []claudeContentBlock{},
			Usage:   claudeUsage{InputTokens: 5, OutputTokens: 0},
		})
	})
	defer srv.Close()

	client, _ := NewClaude(ClaudeOptions{
		APIKey:  "sk-ant-EXAMPLE",
		BaseURL: srv.URL + "/v1",
		HTTP:    srv.Client(),
	})
	_, err := client.Complete(context.Background(), plugin.CompleteRequest{
		Messages: []plugin.Message{{Role: "user", Content: "hello"}},
	})

	if err == nil {
		t.Fatal("expected error for empty content array")
	}
}

func TestClaude_Complete_MalformedJSON(t *testing.T) {
	srv := claudeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not valid json`))
	})
	defer srv.Close()

	client, _ := NewClaude(ClaudeOptions{
		APIKey:  "sk-ant-EXAMPLE",
		BaseURL: srv.URL + "/v1",
		HTTP:    srv.Client(),
	})
	_, err := client.Complete(context.Background(), plugin.CompleteRequest{
		Messages: []plugin.Message{{Role: "user", Content: "hello"}},
	})

	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

// ---- toClaudeMessages tests ----

func TestToClaudeMessages(t *testing.T) {
	msgs := toClaudeMessages([]plugin.Message{
		{Role: "user", Content: "u1"},
		{Role: "assistant", Content: "a1"},
	})
	if len(msgs) != 2 {
		t.Fatalf("want 2 messages, got %d", len(msgs))
	}
	if msgs[0].Role != "user" || msgs[0].Content != "u1" {
		t.Errorf("first message wrong: %+v", msgs[0])
	}
	if msgs[1].Role != "assistant" || msgs[1].Content != "a1" {
		t.Errorf("second message wrong: %+v", msgs[1])
	}
}
