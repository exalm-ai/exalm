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

// testOllamaServer spins up a tiny httptest server that mimics the
// Ollama /api/chat endpoint. No real Ollama installation needed.
func testOllamaServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

func TestOllama_Complete_Success(t *testing.T) {
	srv := testOllamaServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}

		// Verify the request body is well-formed.
		var body ollamaChatRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if body.Stream {
			t.Errorf("stream should be false")
		}

		// Respond like a real Ollama server.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ollamaChatResponse{
			Model:           "llama3.1:8b",
			Message:         ollamaMessage{Role: "assistant", Content: "Root cause: disk full."},
			Done:            true,
			PromptEvalCount: 42,
			EvalCount:       8,
		})
	})
	defer srv.Close()

	client, err := NewOllama(OllamaOptions{
		BaseURL: srv.URL,
		Model:   "llama3.1:8b",
	})
	if err != nil {
		t.Fatalf("NewOllama: %v", err)
	}

	resp, err := client.Complete(context.Background(), plugin.CompleteRequest{
		System: "You are an SRE.",
		Messages: []plugin.Message{
			{Role: "user", Content: "What is wrong?"},
		},
		MaxTokens: 256,
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if resp.Content != "Root cause: disk full." {
		t.Errorf("unexpected content: %q", resp.Content)
	}
	if resp.InputTokens != 42 || resp.OutputTokens != 8 {
		t.Errorf("unexpected token counts: input=%d output=%d", resp.InputTokens, resp.OutputTokens)
	}
}

func TestOllama_Complete_SystemPromptPrepended(t *testing.T) {
	var gotMessages []ollamaMessage

	srv := testOllamaServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body ollamaChatRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotMessages = body.Messages

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ollamaChatResponse{
			Message: ollamaMessage{Role: "assistant", Content: "ok"},
			Done:    true,
		})
	})
	defer srv.Close()

	client, _ := NewOllama(OllamaOptions{BaseURL: srv.URL, Model: "llama3.1:8b"})
	_, _ = client.Complete(context.Background(), plugin.CompleteRequest{
		System:   "Be concise.",
		Messages: []plugin.Message{{Role: "user", Content: "hello"}},
	})

	if len(gotMessages) != 2 {
		t.Fatalf("expected 2 messages (system + user), got %d", len(gotMessages))
	}
	if gotMessages[0].Role != "system" || gotMessages[0].Content != "Be concise." {
		t.Errorf("first message should be system prompt, got %+v", gotMessages[0])
	}
	if gotMessages[1].Role != "user" {
		t.Errorf("second message should be user, got %+v", gotMessages[1])
	}
}

func TestOllama_Complete_ModelNotFound(t *testing.T) {
	srv := testOllamaServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"model not found"}`))
	})
	defer srv.Close()

	client, _ := NewOllama(OllamaOptions{BaseURL: srv.URL, Model: "nonexistent:latest"})
	_, err := client.Complete(context.Background(), plugin.CompleteRequest{
		Messages: []plugin.Message{{Role: "user", Content: "hello"}},
	})

	if err == nil {
		t.Fatal("expected error for 404")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention model not found: %v", err)
	}
	// Should give a helpful hint about ollama pull.
	if !strings.Contains(err.Error(), "ollama pull") {
		t.Errorf("error should suggest ollama pull: %v", err)
	}
}

func TestOllama_Complete_APIError(t *testing.T) {
	srv := testOllamaServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	})
	defer srv.Close()

	client, _ := NewOllama(OllamaOptions{BaseURL: srv.URL, Model: "llama3.1:8b"})
	_, err := client.Complete(context.Background(), plugin.CompleteRequest{
		Messages: []plugin.Message{{Role: "user", Content: "hello"}},
	})

	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestOllama_Name(t *testing.T) {
	o, _ := NewOllama(OllamaOptions{})
	if o.Name() != "ollama" {
		t.Errorf("Name() = %q, want ollama", o.Name())
	}
}

func TestOllama_DefaultModel(t *testing.T) {
	o, _ := NewOllama(OllamaOptions{})
	if o.model != DefaultOllamaModel {
		t.Errorf("default model = %q, want %q", o.model, DefaultOllamaModel)
	}
}

func TestOllama_DefaultBaseURL(t *testing.T) {
	o, _ := NewOllama(OllamaOptions{})
	if o.baseURL != "http://localhost:11434" {
		t.Errorf("default baseURL = %q", o.baseURL)
	}
}

func TestOllama_TrailingSlashStripped(t *testing.T) {
	o, _ := NewOllama(OllamaOptions{BaseURL: "http://localhost:11434/"})
	if strings.HasSuffix(o.baseURL, "/") {
		t.Errorf("baseURL should have trailing slash stripped, got %q", o.baseURL)
	}
}
