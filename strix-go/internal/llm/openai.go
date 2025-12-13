// Package llm provides LLM client implementation using eino
package llm

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// OpenAIConfig holds the configuration for OpenAI models
type OpenAIConfig struct {
	APIKey      string
	Model       string
	BaseURL     string
	Temperature float32
	MaxTokens   int
	TopP        float32
	Timeout     time.Duration

	// Azure-specific
	IsAzure    bool
	Deployment string
	APIVersion string
}

// OpenAIChatModel implements the ToolCallingChatModel interface for OpenAI
type OpenAIChatModel struct {
	config     *OpenAIConfig
	httpClient *http.Client
	tools      []*schema.ToolInfo
}

// NewOpenAIChatModel creates a new OpenAI chat model
func NewOpenAIChatModel(ctx context.Context, cfg *OpenAIConfig) (model.ToolCallingChatModel, error) {
	if cfg.APIKey == "" && !cfg.IsAzure {
		return nil, fmt.Errorf("OpenAI API key is required")
	}

	if cfg.Model == "" {
		cfg.Model = "gpt-4"
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 120 * time.Second
	}

	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.openai.com/v1"
	}

	return &OpenAIChatModel{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		tools: make([]*schema.ToolInfo, 0),
	}, nil
}

// Generate generates a response from the OpenAI model
func (m *OpenAIChatModel) Generate(ctx context.Context, messages []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	// Apply options
	options := model.GetCommonOptions(&model.Options{}, opts...)

	// Build request
	reqBody := m.buildRequest(messages, options, false)

	// Make HTTP request to OpenAI API
	resp, err := m.doRequest(ctx, reqBody)
	if err != nil {
		return nil, fmt.Errorf("OpenAI request failed: %w", err)
	}

	return resp, nil
}

// Stream streams a response from the OpenAI model
func (m *OpenAIChatModel) Stream(ctx context.Context, messages []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	options := model.GetCommonOptions(&model.Options{}, opts...)

	// Build streaming request
	reqBody := m.buildRequest(messages, options, true)

	// Create stream reader
	reader, writer := schema.Pipe[*schema.Message](10)

	go func() {
		defer writer.Close()

		err := m.doStreamRequest(ctx, reqBody, writer)
		if err != nil {
			writer.Send(nil, err)
		}
	}()

	return reader, nil
}

// WithTools returns a new model with the given tools bound
func (m *OpenAIChatModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	newModel := &OpenAIChatModel{
		config:     m.config,
		httpClient: m.httpClient,
		tools:      tools,
	}
	return newModel, nil
}

// buildRequest builds the OpenAI API request body
func (m *OpenAIChatModel) buildRequest(messages []*schema.Message, options *model.Options, stream bool) map[string]interface{} {
	reqMessages := make([]map[string]interface{}, 0, len(messages))

	for _, msg := range messages {
		reqMsg := map[string]interface{}{
			"role":    string(msg.Role),
			"content": msg.Content,
		}

		// Handle tool calls in assistant messages
		if msg.Role == schema.Assistant && len(msg.ToolCalls) > 0 {
			toolCalls := make([]map[string]interface{}, len(msg.ToolCalls))
			for i, tc := range msg.ToolCalls {
				toolCalls[i] = map[string]interface{}{
					"id":   tc.ID,
					"type": "function",
					"function": map[string]interface{}{
						"name":      tc.Function.Name,
						"arguments": tc.Function.Arguments,
					},
				}
			}
			reqMsg["tool_calls"] = toolCalls
		}

		// Handle tool response messages
		if msg.Role == schema.Tool {
			reqMsg["tool_call_id"] = msg.ToolCallID
		}

		reqMessages = append(reqMessages, reqMsg)
	}

	req := map[string]interface{}{
		"model":    m.config.Model,
		"messages": reqMessages,
		"stream":   stream,
	}

	// Apply temperature
	temp := m.config.Temperature
	if options.Temperature != nil {
		temp = *options.Temperature
	}
	if temp > 0 {
		req["temperature"] = temp
	}

	// Apply max tokens
	maxTokens := m.config.MaxTokens
	if options.MaxTokens != nil {
		maxTokens = *options.MaxTokens
	}
	if maxTokens > 0 {
		req["max_tokens"] = maxTokens
	}

	// Apply top_p
	if m.config.TopP > 0 {
		req["top_p"] = m.config.TopP
	}

	// Add tools if bound
	if len(m.tools) > 0 {
		tools := make([]map[string]interface{}, len(m.tools))
		for i, t := range m.tools {
			tools[i] = map[string]interface{}{
				"type": "function",
				"function": map[string]interface{}{
					"name":        t.Name,
					"description": t.Desc,
					"parameters":  m.convertParams(t.ParamsOneOf),
				},
			}
		}
		req["tools"] = tools
	}

	return req
}

// convertParams converts eino params to OpenAI format
func (m *OpenAIChatModel) convertParams(params *schema.ParamsOneOf) map[string]interface{} {
	if params == nil {
		return map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		}
	}

	properties := make(map[string]interface{})
	required := make([]string, 0)

	if params.Params != nil {
		for name, param := range params.Params {
			prop := map[string]interface{}{
				"type":        string(param.Type),
				"description": param.Desc,
			}
			if len(param.Enum) > 0 {
				prop["enum"] = param.Enum
			}
			properties[name] = prop

			if param.Required {
				required = append(required, name)
			}
		}
	}

	result := map[string]interface{}{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		result["required"] = required
	}

	return result
}

// doRequest makes an HTTP request to the OpenAI API
func (m *OpenAIChatModel) doRequest(ctx context.Context, reqBody map[string]interface{}) (*schema.Message, error) {
	// This is a placeholder - in production, this would make an actual HTTP request
	// For now, we'll use the eino-ext openai package

	// Placeholder response for structure validation
	return &schema.Message{
		Role:    schema.Assistant,
		Content: "This is a placeholder response. In production, this would call the OpenAI API.",
	}, nil
}

// doStreamRequest makes a streaming HTTP request to the OpenAI API
func (m *OpenAIChatModel) doStreamRequest(ctx context.Context, reqBody map[string]interface{}, writer *schema.StreamWriter[*schema.Message]) error {
	// Placeholder for streaming implementation
	writer.Send(&schema.Message{
		Role:    schema.Assistant,
		Content: "Streaming placeholder response.",
	}, nil)
	return nil
}
