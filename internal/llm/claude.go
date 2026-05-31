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

// DefaultClaudeModel is the model used when ClaudeOptions.Model is empty.
// Update this when Anthropic releases a new general-purpose model.
const DefaultClaudeModel = "claude-sonnet-4-6"

const defaultClaudeBaseURL = "https://api.anthropic.com/v1"
const claudeAPIVersion = "2023-06-01"

// Claude is an Anthropic API adapter implementing plugin.LLMClient.
type Claude struct {
	apiKey  string
	model   string
	baseURL string
	http    *http.Client
}

// ClaudeOptions configures a Claude client.
type ClaudeOptions struct {
	APIKey string
	Model  string
	// BaseURL overrides the default Anthropic endpoint.
	// Leave empty to use the standard Anthropic API.
	BaseURL string
	HTTP    *http.Client
}

// NewClaude constructs a Claude client. APIKey is required.
func NewClaude(opts ClaudeOptions) (*Claude, error) {
	if opts.APIKey == "" {
		return nil, fmt.Errorf("claude: ANTHROPIC_API_KEY is not set")
	}
	model := opts.Model
	if model == "" {
		model = DefaultClaudeModel
	}
	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = defaultClaudeBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	httpClient := opts.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 120 * time.Second}
	}
	return &Claude{apiKey: opts.APIKey, model: model, baseURL: baseURL, http: httpClient}, nil
}

// Name returns "claude".
func (c *Claude) Name() string { return "claude" }

// Complete sends a single completion request to the Anthropic API.
func (c *Claude) Complete(ctx context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	body, err := json.Marshal(claudeRequest{
		Model:       c.model,
		MaxTokens:   defaultInt(req.MaxTokens, 2048),
		System:      req.System,
		Messages:    toClaudeMessages(req.Messages),
		Temperature: req.Temperature,
	})
	if err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("claude: marshal request: %w", err)
	}

	endpoint := c.baseURL + "/messages"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body)) //nolint:gosec // G107: endpoint is operator-configured LLM URL
	if err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("claude: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Api-Key", c.apiKey)
	httpReq.Header.Set("Anthropic-Version", claudeAPIVersion)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("claude: http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("claude: read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return plugin.CompleteResponse{}, fmt.Errorf("claude: api error %d: %s", resp.StatusCode, truncate(string(respBody), 500))
	}

	var parsed claudeResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return plugin.CompleteResponse{}, fmt.Errorf("claude: parse response: %w", err)
	}

	if len(parsed.Content) == 0 {
		return plugin.CompleteResponse{}, fmt.Errorf("claude: no content blocks in response")
	}

	var content string
	for _, block := range parsed.Content {
		if block.Type == "text" {
			content += block.Text
		}
	}

	return plugin.CompleteResponse{
		Content:      content,
		InputTokens:  parsed.Usage.InputTokens,
		OutputTokens: parsed.Usage.OutputTokens,
	}, nil
}

// --- internal request/response shapes ---

type claudeRequest struct {
	Model       string          `json:"model"`
	MaxTokens   int             `json:"max_tokens"`
	System      string          `json:"system,omitempty"`
	Messages    []claudeMessage `json:"messages"`
	Temperature float64         `json:"temperature,omitempty"`
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeResponse struct {
	Content []claudeContentBlock `json:"content"`
	Usage   claudeUsage          `json:"usage"`
}

type claudeContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type claudeUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

func toClaudeMessages(in []plugin.Message) []claudeMessage {
	out := make([]claudeMessage, 0, len(in))
	for _, m := range in {
		out = append(out, claudeMessage{Role: m.Role, Content: m.Content})
	}
	return out
}

func defaultInt(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
