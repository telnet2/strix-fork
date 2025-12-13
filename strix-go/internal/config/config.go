// Package config provides configuration management for Strix
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// LLMProvider represents the LLM provider type
type LLMProvider string

const (
	ProviderOpenAI    LLMProvider = "openai"
	ProviderClaude    LLMProvider = "claude"
	ProviderAnthropic LLMProvider = "anthropic"
	ProviderOllama    LLMProvider = "ollama"
	ProviderDeepSeek  LLMProvider = "deepseek"
	ProviderGemini    LLMProvider = "gemini"
	ProviderAzure     LLMProvider = "azure"
	ProviderBedrock   LLMProvider = "bedrock"
)

// Config holds the application configuration
type Config struct {
	// LLM Configuration
	LLMProvider     LLMProvider `json:"llm_provider"`
	LLMModel        string      `json:"llm_model"`
	LLMAPIKey       string      `json:"llm_api_key"`
	LLMAPIBase      string      `json:"llm_api_base,omitempty"`
	LLMTemperature  float32     `json:"llm_temperature"`
	LLMMaxTokens    int         `json:"llm_max_tokens"`

	// Azure-specific
	AzureDeployment string `json:"azure_deployment,omitempty"`
	AzureAPIVersion string `json:"azure_api_version,omitempty"`

	// AWS Bedrock-specific
	AWSRegion     string `json:"aws_region,omitempty"`
	AWSAccessKey  string `json:"aws_access_key,omitempty"`
	AWSSecretKey  string `json:"aws_secret_key,omitempty"`

	// Optional providers
	PerplexityAPIKey string `json:"perplexity_api_key,omitempty"`

	// Docker Configuration
	DockerImage   string `json:"docker_image"`
	DockerTimeout time.Duration `json:"docker_timeout"`
	UseLocalTools bool   `json:"use_local_tools"`

	// Agent Configuration
	MaxAgentIterations int           `json:"max_agent_iterations"`
	MaxConcurrentAgents int          `json:"max_concurrent_agents"`
	AgentTimeout        time.Duration `json:"agent_timeout"`

	// Request Queue Configuration
	MaxConcurrentRequests int           `json:"max_concurrent_requests"`
	RequestDelay          time.Duration `json:"request_delay"`
	MaxRetries            int           `json:"max_retries"`

	// Memory Configuration
	MaxTotalTokens  int `json:"max_total_tokens"`
	MinRecentMessages int `json:"min_recent_messages"`
	MaxCachedImages  int `json:"max_cached_images"`

	// Output Configuration
	OutputDir   string `json:"output_dir"`
	Verbose     bool   `json:"verbose"`
	Debug       bool   `json:"debug"`
	Interactive bool   `json:"interactive"`

	// Workspace
	WorkspaceDir string `json:"workspace_dir"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		LLMProvider:         ProviderOpenAI,
		LLMModel:            "gpt-4",
		LLMTemperature:      0.7,
		LLMMaxTokens:        4096,
		DockerImage:         "ghcr.io/usestrix/strix-sandbox:0.1.10",
		DockerTimeout:       5 * time.Minute,
		UseLocalTools:       false,
		MaxAgentIterations:  300,
		MaxConcurrentAgents: 5,
		AgentTimeout:        2 * time.Hour,
		MaxConcurrentRequests: 1,
		RequestDelay:        4 * time.Second,
		MaxRetries:          3,
		MaxTotalTokens:      100000,
		MinRecentMessages:   15,
		MaxCachedImages:     3,
		OutputDir:           "./strix-output",
		Interactive:         true,
		WorkspaceDir:        "/workspace",
	}
}

// LoadFromEnv loads configuration from environment variables
func LoadFromEnv() (*Config, error) {
	cfg := DefaultConfig()

	// Parse STRIX_LLM (format: provider/model or just model)
	llmConfig := os.Getenv("STRIX_LLM")
	if llmConfig == "" {
		return nil, fmt.Errorf("STRIX_LLM environment variable is required (e.g., openai/gpt-4, claude/claude-3-5-sonnet)")
	}

	provider, model := parseLLMConfig(llmConfig)
	cfg.LLMProvider = provider
	cfg.LLMModel = model

	// API Key
	if apiKey := os.Getenv("LLM_API_KEY"); apiKey != "" {
		cfg.LLMAPIKey = apiKey
	} else if apiKey := os.Getenv("OPENAI_API_KEY"); apiKey != "" && cfg.LLMProvider == ProviderOpenAI {
		cfg.LLMAPIKey = apiKey
	} else if apiKey := os.Getenv("ANTHROPIC_API_KEY"); apiKey != "" && (cfg.LLMProvider == ProviderClaude || cfg.LLMProvider == ProviderAnthropic) {
		cfg.LLMAPIKey = apiKey
	} else if apiKey := os.Getenv("CLAUDE_API_KEY"); apiKey != "" && (cfg.LLMProvider == ProviderClaude || cfg.LLMProvider == ProviderAnthropic) {
		cfg.LLMAPIKey = apiKey
	}

	// API Base URL (for local models or custom endpoints)
	if apiBase := os.Getenv("LLM_API_BASE"); apiBase != "" {
		cfg.LLMAPIBase = apiBase
	}

	// Azure configuration
	if deployment := os.Getenv("AZURE_DEPLOYMENT"); deployment != "" {
		cfg.AzureDeployment = deployment
	}
	if apiVersion := os.Getenv("AZURE_API_VERSION"); apiVersion != "" {
		cfg.AzureAPIVersion = apiVersion
	}

	// AWS Bedrock configuration
	if region := os.Getenv("AWS_REGION"); region != "" {
		cfg.AWSRegion = region
	}
	if accessKey := os.Getenv("AWS_ACCESS_KEY_ID"); accessKey != "" {
		cfg.AWSAccessKey = accessKey
	}
	if secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY"); secretKey != "" {
		cfg.AWSSecretKey = secretKey
	}

	// Perplexity (for web search)
	if apiKey := os.Getenv("PERPLEXITY_API_KEY"); apiKey != "" {
		cfg.PerplexityAPIKey = apiKey
	}

	// Docker configuration
	if image := os.Getenv("STRIX_DOCKER_IMAGE"); image != "" {
		cfg.DockerImage = image
	}

	// Optional overrides
	if temp := os.Getenv("LLM_TEMPERATURE"); temp != "" {
		if t, err := strconv.ParseFloat(temp, 32); err == nil {
			cfg.LLMTemperature = float32(t)
		}
	}

	if maxTokens := os.Getenv("LLM_MAX_TOKENS"); maxTokens != "" {
		if t, err := strconv.Atoi(maxTokens); err == nil {
			cfg.LLMMaxTokens = t
		}
	}

	if maxIter := os.Getenv("STRIX_MAX_ITERATIONS"); maxIter != "" {
		if t, err := strconv.Atoi(maxIter); err == nil {
			cfg.MaxAgentIterations = t
		}
	}

	if verbose := os.Getenv("STRIX_VERBOSE"); verbose == "true" || verbose == "1" {
		cfg.Verbose = true
	}

	if debug := os.Getenv("STRIX_DEBUG"); debug == "true" || debug == "1" {
		cfg.Debug = true
	}

	if outputDir := os.Getenv("STRIX_OUTPUT_DIR"); outputDir != "" {
		cfg.OutputDir = outputDir
	}

	return cfg, nil
}

// parseLLMConfig parses the LLM configuration string
func parseLLMConfig(config string) (LLMProvider, string) {
	parts := strings.SplitN(config, "/", 2)
	if len(parts) == 2 {
		provider := strings.ToLower(parts[0])
		model := parts[1]

		switch provider {
		case "openai":
			return ProviderOpenAI, model
		case "claude", "anthropic":
			return ProviderClaude, model
		case "ollama":
			return ProviderOllama, model
		case "deepseek":
			return ProviderDeepSeek, model
		case "gemini", "google":
			return ProviderGemini, model
		case "azure":
			return ProviderAzure, model
		case "bedrock", "aws":
			return ProviderBedrock, model
		default:
			// Unknown provider, treat as OpenAI-compatible
			return ProviderOpenAI, model
		}
	}

	// No provider specified, infer from model name
	model := config
	switch {
	case strings.HasPrefix(model, "gpt-") || strings.HasPrefix(model, "o1") || strings.HasPrefix(model, "o3"):
		return ProviderOpenAI, model
	case strings.HasPrefix(model, "claude"):
		return ProviderClaude, model
	case strings.Contains(model, "gemini"):
		return ProviderGemini, model
	case strings.Contains(model, "deepseek"):
		return ProviderDeepSeek, model
	default:
		return ProviderOpenAI, model
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.LLMModel == "" {
		return fmt.Errorf("LLM model is required")
	}

	// Check API key requirements
	switch c.LLMProvider {
	case ProviderOpenAI, ProviderClaude, ProviderAnthropic, ProviderDeepSeek, ProviderGemini:
		if c.LLMAPIKey == "" && c.LLMAPIBase == "" {
			return fmt.Errorf("API key is required for provider %s (set LLM_API_KEY)", c.LLMProvider)
		}
	case ProviderAzure:
		if c.LLMAPIKey == "" || c.LLMAPIBase == "" {
			return fmt.Errorf("Azure requires both LLM_API_KEY and LLM_API_BASE")
		}
	case ProviderBedrock:
		if c.AWSAccessKey == "" || c.AWSSecretKey == "" {
			return fmt.Errorf("AWS Bedrock requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
		}
	case ProviderOllama:
		// Ollama doesn't require API key
		if c.LLMAPIBase == "" {
			c.LLMAPIBase = "http://localhost:11434"
		}
	}

	return nil
}

// String returns a string representation of the config (hiding secrets)
func (c *Config) String() string {
	apiKeyDisplay := "***"
	if c.LLMAPIKey == "" {
		apiKeyDisplay = "(not set)"
	}

	return fmt.Sprintf(
		"Config{Provider: %s, Model: %s, APIKey: %s, MaxIterations: %d}",
		c.LLMProvider, c.LLMModel, apiKeyDisplay, c.MaxAgentIterations,
	)
}
