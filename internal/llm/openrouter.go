// Strength: openobserve — "AGPL-3.0 open source core with BYOB object storage:
// air-gapped, data-sovereign self-hosted deployments possible." OpenRouter +
// Ollama (in llm.go) together let Exalm run fully air-gapped (Ollama) or with
// 100+ models via OpenRouter, matching OO's BYOAI ethos.
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

// DefaultOpenRouterModel is used when OpenRouterOptions.Model is empty.
const DefaultOpenRouterModel = "openai/gpt-4o"

const defaultOpenRouterBaseURL = "https://openrouter.ai/api/v1"

// OpenRouter is an OpenRouter API adapter implementing plugin.LLMClient.
// OpenRouter exposes an OpenAI-compatible chat completions endpoint and
// supports hundreds of models from different providers via a single key.
type OpenRouter struct {
	apiKey  string
	model   string
	baseURL string
	http    *http.Client
}

// OpenRouterOptions configures an OpenRouter client.
type OpenRouterOptions struct {
	APIKey string
	Model  string
	// BaseURL overrides the default OpenRouter endpoint.
	// Leave empty to use the standard OpenRouter API.
	BaseURL string
	HTTP    *http.Client
}

// NewOpenRouter constructs an OpenRouter client. APIKey is required.
func NewOpenRouter(opts OpenRouterOptions) (*OpenRouter, error) {
	if opts.APIKey == "" {
		return nil, fmt.Errorf("openrouter: OPENROUTER_API_KEY is not set")
	}
	model := opts.Model
	if model == "" {
		model = DefaultOpenRouterModel
	}
	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = defaultOpenRouterBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	httpClient := opts.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 120 * time.Second}
	}
	return &OpenRouter{apiKey: opts.APIKey, model: model, baseURL: baseURL, http: httpClient}, nil
}

// Name returns "openrouter".
func (o *OpenRouter) Name() string { return "openrouter" }

// Complete sends a completion request to the OpenRouter API.
func (o *OpenRouter) Complete(ctx context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	messages := toOpenRouterMessages(req.System, req.Messages)

	body, err := json.Marshal(openRouterRequest{
		Model:       o.model,
		Messages:    messages,
		MaxTokens:   defaultInt(req.MaxTokens, 2048),
		Temperature: req.Temperature,
	})
	if err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("openrouter: marshal request: %w", err)
	}

	endpoint := o.baseURL + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body)) //nolint:gosec // G107: endpoint is operator-configured OpenRouter base URL
	if err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("openrouter: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)
	httpReq.Header.Set("HTTP-Referer", "https://exalm.com")
	httpReq.Header.Set("X-Title", "Exalm")

	resp, err := o.http.Do(httpReq)
	if err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("openrouter: http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("openrouter: read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return plugin.CompleteResponse{}, fmt.Errorf("openrouter: api error %d: %s", resp.StatusCode, truncate(string(respBody), 500))
	}

	var parsed openRouterResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("openrouter: parse response: %w", err)
	}

	if len(parsed.Choices) == 0 {
		return plugin.CompleteResponse{}, fmt.Errorf("openrouter: no choices in response")
	}

	return plugin.CompleteResponse{
		Content:      parsed.Choices[0].Message.Content,
		InputTokens:  parsed.Usage.PromptTokens,
		OutputTokens: parsed.Usage.CompletionTokens,
	}, nil
}

// --- internal request/response shapes ---

type openRouterRequest struct {
	Model       string              `json:"model"`
	Messages    []openRouterMessage `json:"messages"`
	MaxTokens   int                 `json:"max_tokens,omitempty"`
	Temperature float64             `json:"temperature,omitempty"`
}

type openRouterMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openRouterResponse struct {
	Choices []openRouterChoice `json:"choices"`
	Usage   openRouterUsage    `json:"usage"`
}

type openRouterChoice struct {
	Message openRouterMessage `json:"message"`
}

type openRouterUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

func toOpenRouterMessages(system string, in []plugin.Message) []openRouterMessage {
	out := make([]openRouterMessage, 0, len(in)+1)
	if system != "" {
		out = append(out, openRouterMessage{Role: "system", Content: system})
	}
	for _, m := range in {
		out = append(out, openRouterMessage{Role: m.Role, Content: m.Content})
	}
	return out
}
