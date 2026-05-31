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

// openAIServer spins up a test HTTP server that mimics the OpenAI Chat
// Completions endpoint at POST /v1/chat/completions.
func openAIServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

// happyOpenAIHandler returns a successful Chat Completions response.
func happyOpenAIHandler(content string, promptTok, completionTok int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(openAIResponse{ //nolint:errcheck
			Choices: []openAIChoice{
				{Message: openAIMessage{Role: "assistant", Content: content}},
			},
			Usage: openAIUsage{
				PromptTokens:     promptTok,
				CompletionTokens: completionTok,
			},
		})
	}
}

// ---- constructor tests ----

func TestNewOpenAI_MissingAPIKey(t *testing.T) {
	_, err := NewOpenAI(OpenAIOptions{})
	if err == nil {
		t.Fatal("expected error for empty API key")
	}
	if !strings.Contains(err.Error(), "OPENAI_API_KEY") {
		t.Errorf("error should mention OPENAI_API_KEY, got: %v", err)
	}
}

func TestNewOpenAI_DefaultModel(t *testing.T) {
	c, err := NewOpenAI(OpenAIOptions{APIKey: "sk-test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.model != DefaultOpenAIModel {
		t.Errorf("default model = %q, want %q", c.model, DefaultOpenAIModel)
	}
}

func TestNewOpenAI_CustomModel(t *testing.T) {
	c, err := NewOpenAI(OpenAIOptions{APIKey: "sk-test", Model: "gpt-4-turbo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.model != "gpt-4-turbo" {
		t.Errorf("model = %q, want gpt-4-turbo", c.model)
	}
}

func TestNewOpenAI_DefaultBaseURL(t *testing.T) {
	c, err := NewOpenAI(OpenAIOptions{APIKey: "sk-test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.baseURL != defaultOpenAIBaseURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, defaultOpenAIBaseURL)
	}
}

func TestNewOpenAI_TrailingSlashStripped(t *testing.T) {
	c, err := NewOpenAI(OpenAIOptions{APIKey: "sk-test", BaseURL: "http://localhost:8080/"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasSuffix(c.baseURL, "/") {
		t.Errorf("baseURL should have trailing slash stripped, got %q", c.baseURL)
	}
}

func TestOpenAI_Name(t *testing.T) {
	c, _ := NewOpenAI(OpenAIOptions{APIKey: "sk-test"})
	if c.Name() != "openai" {
		t.Errorf("Name() = %q, want openai", c.Name())
	}
}

// ---- Complete() tests ----

func TestOpenAI_Complete_Success(t *testing.T) {
	srv := openAIServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify request path and method.
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		// Verify Authorization header.
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing Bearer token")
		}
		// Verify request body can be decoded.
		var body openAIRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		happyOpenAIHandler("Root cause: OOM killer.", 50, 12)(w, r)
	})
	defer srv.Close()

	client, err := NewOpenAI(OpenAIOptions{
		APIKey:  "sk-test",
		Model:   "gpt-4o",
		BaseURL: srv.URL + "/v1",
		HTTP:    srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewOpenAI: %v", err)
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
	if resp.InputTokens != 50 || resp.OutputTokens != 12 {
		t.Errorf("tokens: input=%d output=%d, want 50/12", resp.InputTokens, resp.OutputTokens)
	}
}

func TestOpenAI_Complete_SystemPromptPrepended(t *testing.T) {
	var gotMessages []openAIMessage

	srv := openAIServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body openAIRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotMessages = body.Messages
		happyOpenAIHandler("ok", 10, 1)(w, r)
	})
	defer srv.Close()

	client, _ := NewOpenAI(OpenAIOptions{APIKey: "sk-test", BaseURL: srv.URL + "/v1", HTTP: srv.Client()})
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

func TestOpenAI_Complete_NoSystemPrompt(t *testing.T) {
	var gotMessages []openAIMessage

	srv := openAIServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body openAIRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotMessages = body.Messages
		happyOpenAIHandler("ok", 5, 1)(w, r)
	})
	defer srv.Close()

	client, _ := NewOpenAI(OpenAIOptions{APIKey: "sk-test", BaseURL: srv.URL + "/v1", HTTP: srv.Client()})
	_, _ = client.Complete(context.Background(), plugin.CompleteRequest{
		Messages: []plugin.Message{{Role: "user", Content: "hello"}},
	})

	if len(gotMessages) != 1 {
		t.Fatalf("want 1 message (no system), got %d", len(gotMessages))
	}
	if gotMessages[0].Role != "user" {
		t.Errorf("only message should be user, got %q", gotMessages[0].Role)
	}
}

func TestOpenAI_Complete_APIError_StructuredJSON(t *testing.T) {
	srv := openAIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(openAIErrorEnvelope{ //nolint:errcheck
			Error: struct {
				Message string `json:"message"`
				Type    string `json:"type"`
				Code    string `json:"code"`
			}{
				Message: "Incorrect API key provided",
				Type:    "invalid_request_error",
				Code:    "invalid_api_key",
			},
		})
	})
	defer srv.Close()

	client, _ := NewOpenAI(OpenAIOptions{APIKey: "sk-bad", BaseURL: srv.URL + "/v1", HTTP: srv.Client()})
	_, err := client.Complete(context.Background(), plugin.CompleteRequest{
		Messages: []plugin.Message{{Role: "user", Content: "hello"}},
	})

	if err == nil {
		t.Fatal("expected error for 401")
	}
	if !strings.Contains(err.Error(), "Incorrect API key") {
		t.Errorf("error should contain the API message, got: %v", err)
	}
}

func TestOpenAI_Complete_APIError_RawBody(t *testing.T) {
	srv := openAIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service temporarily unavailable"))
	})
	defer srv.Close()

	client, _ := NewOpenAI(OpenAIOptions{APIKey: "sk-test", BaseURL: srv.URL + "/v1", HTTP: srv.Client()})
	_, err := client.Complete(context.Background(), plugin.CompleteRequest{
		Messages: []plugin.Message{{Role: "user", Content: "hello"}},
	})

	if err == nil {
		t.Fatal("expected error for 503")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should mention status code 503, got: %v", err)
	}
}

func TestOpenAI_Complete_NoChoices(t *testing.T) {
	srv := openAIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(openAIResponse{Choices: nil}) //nolint:errcheck
	})
	defer srv.Close()

	client, _ := NewOpenAI(OpenAIOptions{APIKey: "sk-test", BaseURL: srv.URL + "/v1", HTTP: srv.Client()})
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

func TestOpenAI_Complete_MalformedJSON(t *testing.T) {
	srv := openAIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not valid json`))
	})
	defer srv.Close()

	client, _ := NewOpenAI(OpenAIOptions{APIKey: "sk-test", BaseURL: srv.URL + "/v1", HTTP: srv.Client()})
	_, err := client.Complete(context.Background(), plugin.CompleteRequest{
		Messages: []plugin.Message{{Role: "user", Content: "hello"}},
	})

	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestOpenAI_Complete_DefaultMaxTokens(t *testing.T) {
	var gotMaxTokens int

	srv := openAIServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body openAIRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotMaxTokens = body.MaxTokens
		happyOpenAIHandler("ok", 5, 1)(w, r)
	})
	defer srv.Close()

	client, _ := NewOpenAI(OpenAIOptions{APIKey: "sk-test", BaseURL: srv.URL + "/v1", HTTP: srv.Client()})
	// MaxTokens=0 → should default to 2048
	_, _ = client.Complete(context.Background(), plugin.CompleteRequest{
		Messages:  []plugin.Message{{Role: "user", Content: "hello"}},
		MaxTokens: 0,
	})

	if gotMaxTokens != 2048 {
		t.Errorf("default MaxTokens = %d, want 2048", gotMaxTokens)
	}
}

// ---- toOpenAIMessages tests ----

func TestToOpenAIMessages_WithSystem(t *testing.T) {
	msgs := toOpenAIMessages("sys", []plugin.Message{
		{Role: "user", Content: "u1"},
		{Role: "assistant", Content: "a1"},
	})
	if len(msgs) != 3 {
		t.Fatalf("want 3, got %d", len(msgs))
	}
	if msgs[0].Role != "system" || msgs[0].Content != "sys" {
		t.Errorf("first message wrong: %+v", msgs[0])
	}
}

func TestToOpenAIMessages_NoSystem(t *testing.T) {
	msgs := toOpenAIMessages("", []plugin.Message{{Role: "user", Content: "hi"}})
	if len(msgs) != 1 {
		t.Fatalf("want 1, got %d", len(msgs))
	}
	if msgs[0].Role != "user" {
		t.Errorf("wrong role: %s", msgs[0].Role)
	}
}
