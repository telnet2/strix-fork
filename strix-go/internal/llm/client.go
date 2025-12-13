// Package llm provides LLM client implementation using eino
package llm

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"github.com/strix-go/internal/config"
)

// Client represents the LLM client that supports multiple providers
type Client struct {
	mu sync.RWMutex

	config       *config.Config
	chatModel    model.ToolCallingChatModel
	requestQueue *RequestQueue

	// Statistics
	totalRequests   int64
	totalTokens     int64
	totalErrors     int64
}

// NewClient creates a new LLM client based on configuration
func NewClient(ctx context.Context, cfg *config.Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	client := &Client{
		config: cfg,
		requestQueue: NewRequestQueue(
			cfg.MaxConcurrentRequests,
			cfg.RequestDelay,
			cfg.MaxRetries,
		),
	}

	// Initialize the chat model based on provider
	chatModel, err := client.initChatModel(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize chat model: %w", err)
	}
	client.chatModel = chatModel

	return client, nil
}

// initChatModel initializes the chat model based on the provider
func (c *Client) initChatModel(ctx context.Context) (model.ToolCallingChatModel, error) {
	switch c.config.LLMProvider {
	case config.ProviderOpenAI:
		return c.initOpenAI(ctx)
	case config.ProviderClaude, config.ProviderAnthropic:
		return c.initClaude(ctx)
	case config.ProviderOllama:
		return c.initOllama(ctx)
	case config.ProviderDeepSeek:
		return c.initDeepSeek(ctx)
	case config.ProviderGemini:
		return c.initGemini(ctx)
	case config.ProviderAzure:
		return c.initAzureOpenAI(ctx)
	case config.ProviderBedrock:
		return c.initBedrock(ctx)
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %s", c.config.LLMProvider)
	}
}

// Generate generates a response from the LLM
func (c *Client) Generate(ctx context.Context, messages []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	c.mu.Lock()
	c.totalRequests++
	c.mu.Unlock()

	// Execute through request queue with retries
	result, err := c.requestQueue.Execute(ctx, func() (*schema.Message, error) {
		return c.chatModel.Generate(ctx, messages, opts...)
	})

	if err != nil {
		c.mu.Lock()
		c.totalErrors++
		c.mu.Unlock()
		return nil, err
	}

	// Track token usage if available
	if result.ResponseMeta != nil && result.ResponseMeta.Usage != nil {
		c.mu.Lock()
		c.totalTokens += int64(result.ResponseMeta.Usage.TotalTokens)
		c.mu.Unlock()
	}

	return result, nil
}

// Stream streams a response from the LLM
func (c *Client) Stream(ctx context.Context, messages []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	c.mu.Lock()
	c.totalRequests++
	c.mu.Unlock()

	stream, err := c.chatModel.Stream(ctx, messages, opts...)
	if err != nil {
		c.mu.Lock()
		c.totalErrors++
		c.mu.Unlock()
		return nil, err
	}

	return stream, nil
}

// WithTools binds tools to the model and returns a new model instance
func (c *Client) WithTools(tools []*schema.ToolInfo) (*Client, error) {
	newModel, err := c.chatModel.WithTools(tools)
	if err != nil {
		return nil, fmt.Errorf("failed to bind tools: %w", err)
	}

	return &Client{
		config:       c.config,
		chatModel:    newModel,
		requestQueue: c.requestQueue,
	}, nil
}

// GetModel returns the underlying chat model
func (c *Client) GetModel() model.ToolCallingChatModel {
	return c.chatModel
}

// GetConfig returns the configuration
func (c *Client) GetConfig() *config.Config {
	return c.config
}

// GetStats returns the client statistics
func (c *Client) GetStats() (requests, tokens, errors int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.totalRequests, c.totalTokens, c.totalErrors
}

// Test performs a simple test to verify the LLM connection
func (c *Client) Test(ctx context.Context) error {
	testMessages := []*schema.Message{
		schema.UserMessage("Say 'OK' if you can hear me."),
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := c.Generate(ctx, testMessages, model.WithMaxTokens(10))
	if err != nil {
		return fmt.Errorf("LLM test failed: %w", err)
	}

	if resp.Content == "" {
		return fmt.Errorf("LLM returned empty response")
	}

	return nil
}

// Close closes the client
func (c *Client) Close() error {
	c.requestQueue.Close()
	return nil
}

// StreamToString collects a stream into a single message
func StreamToString(stream *schema.StreamReader[*schema.Message]) (string, error) {
	var content string
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		content += msg.Content
	}
	return content, nil
}
