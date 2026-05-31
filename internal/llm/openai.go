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

// DefaultOpenAIModel is used when OpenAIOptions.Model is empty.
const DefaultOpenAIModel = "gpt-4o"

// defaultOpenAIBaseURL is the standard OpenAI API base URL.
// Override via OpenAIOptions.BaseURL for Azure OpenAI, LM Studio, LocalAI, etc.
const defaultOpenAIBaseURL = "https://api.openai.com/v1"

// OpenAI is an OpenAI Chat Completions adapter implementing plugin.LLMClient.
// Compatible with any service that exposes the same endpoint shape:
// Azure OpenAI, LM Studio, LocalAI, Together AI, Groq, etc.
type OpenAI struct {
	apiKey  string
	model   string
	baseURL string
	http    *http.Client
}

// OpenAIOptions configures an OpenAI client.
type OpenAIOptions struct {
	APIKey string
	Model  string
	// BaseURL overrides the default OpenAI endpoint.
	// Example: "https://<resource>.openai.azure.com/openai/deployments/<deployment>"
	// Leave empty to use the standard OpenAI API.
	BaseURL string
	HTTP    *http.Client
}

// NewOpenAI constructs an OpenAI client. APIKey is required.
func NewOpenAI(opts OpenAIOptions) (*OpenAI, error) {
	if opts.APIKey == "" {
		return nil, fmt.Errorf("openai: OPENAI_API_KEY is not set")
	}
	model := opts.Model
	if model == "" {
		model = DefaultOpenAIModel
	}
	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = defaultOpenAIBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	httpClient := opts.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 120 * time.Second}
	}
	return &OpenAI{
		apiKey:  opts.APIKey,
		model:   model,
		baseURL: baseURL,
		http:    httpClient,
	}, nil
}

// Name returns "openai".
func (o *OpenAI) Name() string { return "openai" }

// Complete sends a Chat Completions request to the OpenAI API.
func (o *OpenAI) Complete(ctx context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	messages := toOpenAIMessages(req.System, req.Messages)

	body, err := json.Marshal(openAIRequest{
		Model:       o.model,
		Messages:    messages,
		MaxTokens:   defaultInt(req.MaxTokens, 2048),
		Temperature: req.Temperature,
	})
	if err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("openai: marshal request: %w", err)
	}

	endpoint := o.baseURL + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body)) //nolint:gosec // G107: endpoint is operator-configured OpenAI base URL
	if err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("openai: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)

	resp, err := o.http.Do(httpReq)
	if err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("openai: http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("openai: read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Surface the API's structured error message when available.
		var apiErr openAIErrorEnvelope
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Error.Message != "" {
			return plugin.CompleteResponse{}, fmt.Errorf("openai: api error %d: %s", resp.StatusCode, apiErr.Error.Message)
		}
		return plugin.CompleteResponse{}, fmt.Errorf("openai: api error %d: %s", resp.StatusCode, truncate(string(respBody), 500))
	}

	var parsed openAIResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("openai: parse response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return plugin.CompleteResponse{}, fmt.Errorf("openai: no choices in response")
	}

	return plugin.CompleteResponse{
		Content:      parsed.Choices[0].Message.Content,
		InputTokens:  parsed.Usage.PromptTokens,
		OutputTokens: parsed.Usage.CompletionTokens,
	}, nil
}

// --- internal request/response shapes ---

type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Temperature float64         `json:"temperature,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []openAIChoice `json:"choices"`
	Usage   openAIUsage    `json:"usage"`
}

type openAIChoice struct {
	Message openAIMessage `json:"message"`
}

type openAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

// openAIErrorEnvelope is the error body returned by the OpenAI API on 4xx/5xx.
type openAIErrorEnvelope struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

// toOpenAIMessages converts a system prompt + message list into the OpenAI
// messages array. When system is non-empty it is prepended as a "system" role
// message, following the OpenAI Chat Completions convention.
func toOpenAIMessages(system string, in []plugin.Message) []openAIMessage {
	out := make([]openAIMessage, 0, len(in)+1)
	if system != "" {
		out = append(out, openAIMessage{Role: "system", Content: system})
	}
	for _, m := range in {
		out = append(out, openAIMessage{Role: m.Role, Content: m.Content})
	}
	return out
}
