// Package config loads Exalm configuration from environment variables and
// (later) a config file at ~/.config/exalm/config.yaml.
//
// Precedence (highest first):
//  1. Command-line flags
//  2. Environment variables
//  3. Config file
//  4. Defaults
package config

import "os"

// Config is the resolved configuration for one Exalm invocation.
type Config struct {
	// LLMProvider selects the provider: "claude", "openai", "ollama".
	LLMProvider string
	// LLMModel optionally overrides the provider's default model.
	LLMModel string

	// Provider-specific credentials.
	AnthropicAPIKey string
	OpenAIAPIKey    string
	// OpenAIBaseURL overrides the default OpenAI endpoint. Set to use Azure
	// OpenAI, LM Studio, LocalAI, or any OpenAI-compatible server.
	OpenAIBaseURL    string
	OpenRouterAPIKey string
	OllamaBaseURL    string

	// Output controls.
	OutputFormat string // "markdown" (default) or "json"
	NoColor      bool

	// Safety controls.
	Apply          bool // required for any mutating plugin
	ShowRedactions bool

	// Optional redaction patterns (comma-separated names).
	OptionalRedactions []string
}

// Load reads configuration from environment variables. CLI flags should be
// applied after Load() in cmd/exalm/main.go to take precedence.
func Load() Config {
	c := Config{
		LLMProvider:      getenv("EXALM_LLM_PROVIDER", "ollama"),
		LLMModel:         os.Getenv("EXALM_LLM_MODEL"),
		AnthropicAPIKey:  os.Getenv("ANTHROPIC_API_KEY"),
		OpenAIAPIKey:     os.Getenv("OPENAI_API_KEY"),
		OpenAIBaseURL:    os.Getenv("OPENAI_BASE_URL"),
		OpenRouterAPIKey: os.Getenv("OPENROUTER_API_KEY"),
		OllamaBaseURL:    getenv("EXALM_OLLAMA_URL", "http://localhost:11434"),
		OutputFormat:     getenv("EXALM_OUTPUT", "markdown"),
	}
	return c
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
