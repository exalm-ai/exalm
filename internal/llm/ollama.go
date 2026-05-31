package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// DefaultOllamaModel is the model used when EXALM_LLM_MODEL is not set.
// gemma3:4b (~3.3 GB) balances quality and availability on a typical desktop.
// Override with EXALM_LLM_MODEL or --model flag for smaller/larger models.
const DefaultOllamaModel = "gemma3:4b"

// Ollama is an adapter for the Ollama local LLM server (https://ollama.ai).
// It talks to the /api/chat endpoint with stream:false, mapping our
// CompleteRequest directly to Ollama's message format.
//
// No API key needed. Install Ollama, pull a model, and point EXALM_OLLAMA_URL
// at it (default: http://localhost:11434).
type Ollama struct {
	baseURL string
	model   string
	http    *http.Client
}

// OllamaOptions configures an Ollama client.
type OllamaOptions struct {
	// BaseURL is the Ollama server address. Default: http://localhost:11434.
	BaseURL string
	// Model is the model tag to use. Default: llama3.1:8b.
	// Run `ollama list` to see what's installed.
	Model string
	// HTTP is an optional custom HTTP client.
	HTTP *http.Client
}

// NewOllama constructs a ready-to-use Ollama client. It does not connect
// on construction — connection errors appear on the first Complete() call.
func NewOllama(opts OllamaOptions) (*Ollama, error) {
	if opts.BaseURL == "" {
		opts.BaseURL = "http://localhost:11434"
	}
	// Strip trailing slash so URL joins are always clean.
	opts.BaseURL = strings.TrimRight(opts.BaseURL, "/")

	if opts.Model == "" {
		opts.Model = DefaultOllamaModel
	}
	httpClient := opts.HTTP
	if httpClient == nil {
		// Ollama can be slow on first token with large models (gemma3:4b takes
		// ~60s cold start on 16 GB). 600s covers worst-case load time.
		// Users can override by passing their own HTTP client.
		httpClient = &http.Client{Timeout: 600 * time.Second}
	}
	return &Ollama{baseURL: opts.BaseURL, model: opts.Model, http: httpClient}, nil
}

// Name returns "ollama".
func (o *Ollama) Name() string { return "ollama" }

// Complete sends a chat completion request to the Ollama /api/chat endpoint.
// It blocks until the response is complete (stream: false).
//
// Common errors and how to fix them:
//
//	connection refused → Ollama isn't running. Run: ollama serve
//	model not found    → Pull the model first: ollama pull llama3.1:8b
//	context deadline   → Model is slow; use a smaller model or increase timeout
func (o *Ollama) Complete(ctx context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	messages := o.buildMessages(req)

	body, err := json.Marshal(ollamaChatRequest{
		Model:    o.model,
		Messages: messages,
		Stream:   false,
		Options: ollamaOptions{
			Temperature: req.Temperature,
			NumPredict:  req.MaxTokens,
		},
	})
	if err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("ollama: marshal request: %w", err)
	}

	url := o.baseURL + "/api/chat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body)) //nolint:gosec // G107: URL is operator-configured Ollama endpoint
	if err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("ollama: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := o.http.Do(httpReq)
	if err != nil {
		// Make connection-refused errors actionable.
		if isConnectionRefused(err) {
			return plugin.CompleteResponse{}, fmt.Errorf(
				"ollama: connection refused at %s\n\n"+
					"  Is Ollama running? Start it with:  ollama serve\n"+
					"  Then pull a model:               ollama pull %s",
				o.baseURL, o.model,
			)
		}
		return plugin.CompleteResponse{}, fmt.Errorf("ollama: http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("ollama: read response: %w", err)
	}

	if resp.StatusCode == 404 {
		// Include the raw body — some Ollama versions return different 404 reasons.
		return plugin.CompleteResponse{}, fmt.Errorf(
			"ollama: model %q not found (HTTP 404, body: %s)\n\n"+
				"  Pull it first:  ollama pull %s\n"+
				"  List available: ollama list",
			o.model, truncate(string(respBody), 300), o.model,
		)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return plugin.CompleteResponse{}, fmt.Errorf(
			"ollama: api error %d: %s", resp.StatusCode, truncate(string(respBody), 500),
		)
	}

	var parsed ollamaChatResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("ollama: parse response: %w", err)
	}

	return plugin.CompleteResponse{
		Content:      parsed.Message.Content,
		InputTokens:  parsed.PromptEvalCount,
		OutputTokens: parsed.EvalCount,
	}, nil
}

// buildMessages converts a CompleteRequest to Ollama's message slice.
// Ollama's /api/chat accepts "system", "user", and "assistant" roles —
// so we prepend the system prompt as a system-role message if present.
func (o *Ollama) buildMessages(req plugin.CompleteRequest) []ollamaMessage {
	var messages []ollamaMessage

	if req.System != "" {
		messages = append(messages, ollamaMessage{
			Role:    "system",
			Content: req.System,
		})
	}

	for _, m := range req.Messages {
		messages = append(messages, ollamaMessage{
			Role:    m.Role,
			Content: m.Content,
		})
	}

	return messages
}

// --- internal request/response shapes ---

type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Options  ollamaOptions   `json:"options,omitempty"`
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ollamaOptions maps to Ollama's model parameter overrides.
type ollamaOptions struct {
	Temperature float64 `json:"temperature,omitempty"`
	// NumPredict maps to max_tokens. Ollama calls this num_predict.
	NumPredict int `json:"num_predict,omitempty"`
}

type ollamaChatResponse struct {
	Model   string        `json:"model"`
	Message ollamaMessage `json:"message"`
	Done    bool          `json:"done"`
	// Token counts. Ollama uses different field names than Anthropic.
	PromptEvalCount int `json:"prompt_eval_count"`
	EvalCount       int `json:"eval_count"`
}

// isConnectionRefused returns true if the error looks like a refused
// TCP connection — the most common "Ollama isn't running" symptom.
func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connect: connection refused") ||
		strings.Contains(msg, "dial tcp")
}
