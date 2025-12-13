// Package llm provides LLM client implementation using eino
package llm

import (
	"context"
	"fmt"

	"github.com/cloudwego/eino/components/model"
)

// Provider interface for initializing different LLM backends
// Each provider implementation should create a ToolCallingChatModel

// initOpenAI initializes an OpenAI chat model
func (c *Client) initOpenAI(ctx context.Context) (model.ToolCallingChatModel, error) {
	// Use OpenAI provider from eino-ext
	cfg := &OpenAIConfig{
		APIKey:      c.config.LLMAPIKey,
		Model:       c.config.LLMModel,
		Temperature: c.config.LLMTemperature,
		MaxTokens:   c.config.LLMMaxTokens,
		BaseURL:     c.config.LLMAPIBase,
	}

	return NewOpenAIChatModel(ctx, cfg)
}

// initClaude initializes a Claude/Anthropic chat model
func (c *Client) initClaude(ctx context.Context) (model.ToolCallingChatModel, error) {
	cfg := &ClaudeConfig{
		APIKey:      c.config.LLMAPIKey,
		Model:       c.config.LLMModel,
		MaxTokens:   c.config.LLMMaxTokens,
		Temperature: c.config.LLMTemperature,
	}

	return NewClaudeChatModel(ctx, cfg)
}

// initOllama initializes an Ollama chat model
func (c *Client) initOllama(ctx context.Context) (model.ToolCallingChatModel, error) {
	baseURL := c.config.LLMAPIBase
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}

	cfg := &OllamaConfig{
		BaseURL: baseURL,
		Model:   c.config.LLMModel,
	}

	return NewOllamaChatModel(ctx, cfg)
}

// initDeepSeek initializes a DeepSeek chat model
func (c *Client) initDeepSeek(ctx context.Context) (model.ToolCallingChatModel, error) {
	baseURL := c.config.LLMAPIBase
	if baseURL == "" {
		baseURL = "https://api.deepseek.com/beta"
	}

	cfg := &DeepSeekConfig{
		APIKey:  c.config.LLMAPIKey,
		BaseURL: baseURL,
		Model:   c.config.LLMModel,
	}

	return NewDeepSeekChatModel(ctx, cfg)
}

// initGemini initializes a Google Gemini chat model
func (c *Client) initGemini(ctx context.Context) (model.ToolCallingChatModel, error) {
	cfg := &GeminiConfig{
		APIKey: c.config.LLMAPIKey,
		Model:  c.config.LLMModel,
	}

	return NewGeminiChatModel(ctx, cfg)
}

// initAzureOpenAI initializes an Azure OpenAI chat model
func (c *Client) initAzureOpenAI(ctx context.Context) (model.ToolCallingChatModel, error) {
	cfg := &OpenAIConfig{
		APIKey:      c.config.LLMAPIKey,
		Model:       c.config.LLMModel,
		BaseURL:     c.config.LLMAPIBase,
		Temperature: c.config.LLMTemperature,
		MaxTokens:   c.config.LLMMaxTokens,
		IsAzure:     true,
		Deployment:  c.config.AzureDeployment,
		APIVersion:  c.config.AzureAPIVersion,
	}

	return NewOpenAIChatModel(ctx, cfg)
}

// initBedrock initializes an AWS Bedrock Claude model
func (c *Client) initBedrock(ctx context.Context) (model.ToolCallingChatModel, error) {
	cfg := &ClaudeConfig{
		Model:          c.config.LLMModel,
		MaxTokens:      c.config.LLMMaxTokens,
		ByBedrock:      true,
		AWSRegion:      c.config.AWSRegion,
		AWSAccessKey:   c.config.AWSAccessKey,
		AWSSecretKey:   c.config.AWSSecretKey,
	}

	return NewClaudeChatModel(ctx, cfg)
}

// ProviderInfo represents information about an LLM provider
type ProviderInfo struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Models      []string `json:"models"`
	Features    []string `json:"features"`
}

// GetSupportedProviders returns information about all supported providers
func GetSupportedProviders() []ProviderInfo {
	return []ProviderInfo{
		{
			Name:        "openai",
			DisplayName: "OpenAI",
			Models:      []string{"gpt-4", "gpt-4-turbo", "gpt-4o", "gpt-4o-mini", "o1", "o1-mini", "o3-mini"},
			Features:    []string{"chat", "tools", "streaming", "vision"},
		},
		{
			Name:        "claude",
			DisplayName: "Anthropic Claude",
			Models:      []string{"claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022", "claude-3-opus-20240229"},
			Features:    []string{"chat", "tools", "streaming", "vision", "extended_thinking"},
		},
		{
			Name:        "ollama",
			DisplayName: "Ollama (Local)",
			Models:      []string{"llama3.2", "mistral", "codellama", "qwen2.5"},
			Features:    []string{"chat", "tools", "streaming"},
		},
		{
			Name:        "deepseek",
			DisplayName: "DeepSeek",
			Models:      []string{"deepseek-chat", "deepseek-reasoner"},
			Features:    []string{"chat", "tools", "streaming", "reasoning"},
		},
		{
			Name:        "gemini",
			DisplayName: "Google Gemini",
			Models:      []string{"gemini-2.0-flash-exp", "gemini-1.5-pro", "gemini-1.5-flash"},
			Features:    []string{"chat", "tools", "streaming", "vision", "code_execution"},
		},
		{
			Name:        "azure",
			DisplayName: "Azure OpenAI",
			Models:      []string{"gpt-4", "gpt-4-turbo"},
			Features:    []string{"chat", "tools", "streaming"},
		},
		{
			Name:        "bedrock",
			DisplayName: "AWS Bedrock",
			Models:      []string{"anthropic.claude-3-sonnet-20240229-v1:0", "anthropic.claude-3-haiku-20240307-v1:0"},
			Features:    []string{"chat", "tools", "streaming"},
		},
	}
}

// ValidateModelForProvider checks if a model is valid for a given provider
func ValidateModelForProvider(provider, modelName string) error {
	providers := GetSupportedProviders()
	for _, p := range providers {
		if p.Name == provider {
			// For now, allow any model name as providers often add new models
			return nil
		}
	}
	return fmt.Errorf("unknown provider: %s", provider)
}
