// Package llm provides adapters for LLM providers used by Exalm plugins.
//
// Plugins should never import a specific provider; they take a
// plugin.LLMClient and call Complete(). This file wires concrete providers
// behind that interface.
//
// Adding a new provider:
//
//  1. Add a file in this package implementing plugin.LLMClient.
//  2. Add a case in NewFromConfig() below.
//  3. Document required env vars in docs/configuration.md.
package llm

import (
	"errors"
	"fmt"

	"github.com/exalm-ai/exalm/internal/config"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// ErrNoProvider is returned when no LLM provider is configured.
var ErrNoProvider = errors.New("no LLM provider configured: set EXALM_LLM_PROVIDER and the relevant API key")

// NewFromConfig constructs the provider named in cfg.
func NewFromConfig(cfg config.Config) (plugin.LLMClient, error) {
	switch cfg.LLMProvider {
	case "":
		return nil, ErrNoProvider
	case "claude", "anthropic":
		return NewClaude(ClaudeOptions{
			APIKey: cfg.AnthropicAPIKey,
			Model:  cfg.LLMModel,
		})
	case "openai":
		return NewOpenAI(OpenAIOptions{
			APIKey:  cfg.OpenAIAPIKey,
			Model:   cfg.LLMModel,
			BaseURL: cfg.OpenAIBaseURL,
		})
	case "ollama":
		return NewOllama(OllamaOptions{
			BaseURL: cfg.OllamaBaseURL,
			Model:   cfg.LLMModel,
		})
	case "openrouter":
		return NewOpenRouter(OpenRouterOptions{
			APIKey: cfg.OpenRouterAPIKey,
			Model:  cfg.LLMModel,
		})
	case "mock":
		// Deterministic no-network provider for integration tests and CI.
		// Set EXALM_LLM_PROVIDER=mock — no API key required.
		return NewMock(), nil
	default:
		return nil, fmt.Errorf("unknown LLM provider: %q", cfg.LLMProvider)
	}
}
