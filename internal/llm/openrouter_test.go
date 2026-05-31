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

// openRouterServer spins up a test HTTP server that mimics the OpenRouter
// chat completions endpoint at POST /v1/chat/completions.
func openRouterServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

// happyOpenRouterHandler returns a successful OpenRouter response.
func happyOpenRouterHandler(content string, promptTok, completionTok int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(openRouterResponse{ //nolint:errcheck
			Choices: []openRouterChoice{
				{Message: openRouterMessage{Role: "assistant", Content: content}},
			},
			Usage: openRouterUsage{
				PromptTokens:     promptTok,
				CompletionTokens: completionTok,
			},
		})
	}
}

// ---- constructor tests ----

func TestNewOpenRouter_missingKey(t *testing.T) {
	_, err := NewOpenRouter(OpenRouterOptions{})
	if err == nil {
		t.Fatal("expected error for empty API key")
	}
	if !strings.Contains(err.Error(), "OPENROUTER_API_KEY") {
		t.Errorf("error should mention OPENROUTER_API_KEY, got: %v", err)
	}
}

func TestNewOpenRouter_DefaultModel(t *testing.T) {
	c, err := NewOpenRouter(OpenRouterOptions{APIKey: "sk-or-EXAMPLE"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.model != DefaultOpenRouterModel {
		t.Errorf("default model = %q, want %q", c.model, DefaultOpenRouterModel)
	}
}

func TestNewOpenRouter_DefaultBaseURL(t *testing.T) {
	c, err := NewOpenRouter(OpenRouterOptions{APIKey: "sk-or-EXAMPLE"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.baseURL != defaultOpenRouterBaseURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, defaultOpenRouterBaseURL)
	}
}

func TestNewOpenRouter_TrailingSlashStripped(t *testing.T) {
	c, err := NewOpenRouter(OpenRouterOptions{APIKey: "sk-or-EXAMPLE", BaseURL: "http://localhost:9001/"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasSuffix(c.baseURL, "/") {
		t.Errorf("baseURL should have trailing slash stripped, got %q", c.baseURL)
	}
}

// ---- Name test ----

func TestOpenRouter_Name(t *testing.T) {
	c, _ := NewOpenRouter(OpenRouterOptions{APIKey: "sk-or-EXAMPLE"})
	if c.Name() != "openrouter" {
		t.Errorf("Name() = %q, want openrouter", c.Name())
	}
}

// ---- Complete() tests ----

func TestOpenRouter_Complete_success(t *testing.T) {
	srv := openRouterServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify request path and method.
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		// Verify Authorization header.
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Error("missing Bearer token in Authorization header")
		}
		// Verify OpenRouter-specific headers.
		if r.Header.Get("HTTP-Referer") == "" {
			t.Error("missing HTTP-Referer header")
		}
		// Verify request body is decodable.
		var body openRouterRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		happyOpenRouterHandler("Root cause: disk full.", 45, 10)(w, r)
	})
	defer srv.Close()

	client, err := NewOpenRouter(OpenRouterOptions{
		APIKey:  "sk-or-EXAMPLE",
		Model:   DefaultOpenRouterModel,
		BaseURL: srv.URL + "/v1",
		HTTP:    srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewOpenRouter: %v", err)
	}

	resp, err := client.Complete(context.Background(), plugin.CompleteRequest{
		System:    "You are an SRE.",
		Messages:  []plugin.Message{{Role: "user", Content: "What failed?"}},
		MaxTokens: 256,
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Content != "Root cause: disk full." {
		t.Errorf("content = %q, want %q", resp.Content, "Root cause: disk full.")
	}
	if resp.InputTokens != 45 || resp.OutputTokens != 10 {
		t.Errorf("tokens: input=%d output=%d, want 45/10", resp.InputTokens, resp.OutputTokens)
	}
}

func TestOpenRouter_Complete_apiError(t *testing.T) {
	srv := openRouterServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"rate limit exceeded","code":429}}`))
	})
	defer srv.Close()

	client, _ := NewOpenRouter(OpenRouterOptions{
		APIKey:  "sk-or-EXAMPLE",
		BaseURL: srv.URL + "/v1",
		HTTP:    srv.Client(),
	})
	_, err := client.Complete(context.Background(), plugin.CompleteRequest{
		Messages: []plugin.Message{{Role: "user", Content: "hello"}},
	})

	if err == nil {
		t.Fatal("expected error for HTTP 429")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error should contain 429, got: %v", err)
	}
}

func TestOpenRouter_Complete_noChoices(t *testing.T) {
	srv := openRouterServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(openRouterResponse{Choices: []openRouterChoice{}}) //nolint:errcheck
	})
	defer srv.Close()

	client, _ := NewOpenRouter(OpenRouterOptions{
		APIKey:  "sk-or-EXAMPLE",
		BaseURL: srv.URL + "/v1",
		HTTP:    srv.Client(),
	})
	_, err := client.Complete(context.Background(), plugin.CompleteRequest{
		Messages: []plugin.Message{{Role: "user", Content: "hello"}},
	})

	if err == nil {
		t.Fatal("expected error for empty choices")
	}
	if !strings.Contains(err.Error(), "no choices") {
		t.Errorf("error should mention no choices, got: %v", err)
	}
}

func TestOpenRouter_Complete_MalformedJSON(t *testing.T) {
	srv := openRouterServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not valid json`))
	})
	defer srv.Close()

	client, _ := NewOpenRouter(OpenRouterOptions{
		APIKey:  "sk-or-EXAMPLE",
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

func TestOpenRouter_Complete_SystemPromptPrepended(t *testing.T) {
	var gotMessages []openRouterMessage

	srv := openRouterServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body openRouterRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotMessages = body.Messages
		happyOpenRouterHandler("ok", 10, 1)(w, r)
	})
	defer srv.Close()

	client, _ := NewOpenRouter(OpenRouterOptions{APIKey: "sk-or-EXAMPLE", BaseURL: srv.URL + "/v1", HTTP: srv.Client()})
	_, _ = client.Complete(context.Background(), plugin.CompleteRequest{
		System:   "Be concise.",
		Messages: []plugin.Message{{Role: "user", Content: "hello"}},
	})

	if len(gotMessages) != 2 {
		t.Fatalf("want 2 messages (system + user), got %d", len(gotMessages))
	}
	if gotMessages[0].Role != "system" || gotMessages[0].Content != "Be concise." {
		t.Errorf("first message should be system, got %+v", gotMessages[0])
	}
	if gotMessages[1].Role != "user" {
		t.Errorf("second message should be user, got %+v", gotMessages[1])
	}
}

// ---- toOpenRouterMessages tests ----

func TestToOpenRouterMessages_WithSystem(t *testing.T) {
	msgs := toOpenRouterMessages("sys", []plugin.Message{
		{Role: "user", Content: "u1"},
	})
	if len(msgs) != 2 {
		t.Fatalf("want 2 messages, got %d", len(msgs))
	}
	if msgs[0].Role != "system" || msgs[0].Content != "sys" {
		t.Errorf("first message wrong: %+v", msgs[0])
	}
}

func TestToOpenRouterMessages_NoSystem(t *testing.T) {
	msgs := toOpenRouterMessages("", []plugin.Message{{Role: "user", Content: "hi"}})
	if len(msgs) != 1 {
		t.Fatalf("want 1 message, got %d", len(msgs))
	}
	if msgs[0].Role != "user" {
		t.Errorf("wrong role: %s", msgs[0].Role)
	}
}
