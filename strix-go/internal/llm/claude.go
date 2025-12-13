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

// ClaudeConfig holds the configuration for Claude/Anthropic models
type ClaudeConfig struct {
	APIKey      string
	Model       string
	MaxTokens   int
	Temperature float32

	// Bedrock-specific
	ByBedrock    bool
	AWSRegion    string
	AWSAccessKey string
	AWSSecretKey string

	// Extended thinking
	EnableThinking   bool
	ThinkingBudget   int

	Timeout time.Duration
}

// ClaudeChatModel implements the ToolCallingChatModel interface for Claude
type ClaudeChatModel struct {
	config     *ClaudeConfig
	httpClient *http.Client
	tools      []*schema.ToolInfo
}

// NewClaudeChatModel creates a new Claude chat model
func NewClaudeChatModel(ctx context.Context, cfg *ClaudeConfig) (model.ToolCallingChatModel, error) {
	if cfg.APIKey == "" && !cfg.ByBedrock {
		return nil, fmt.Errorf("Claude API key is required")
	}

	if cfg.Model == "" {
		cfg.Model = "claude-3-5-sonnet-20241022"
	}

	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = 4096
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 120 * time.Second
	}

	return &ClaudeChatModel{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		tools: make([]*schema.ToolInfo, 0),
	}, nil
}

// Generate generates a response from the Claude model
func (m *ClaudeChatModel) Generate(ctx context.Context, messages []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	options := model.GetCommonOptions(&model.Options{}, opts...)

	reqBody := m.buildRequest(messages, options, false)

	resp, err := m.doRequest(ctx, reqBody)
	if err != nil {
		return nil, fmt.Errorf("Claude request failed: %w", err)
	}

	return resp, nil
}

// Stream streams a response from the Claude model
func (m *ClaudeChatModel) Stream(ctx context.Context, messages []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	options := model.GetCommonOptions(&model.Options{}, opts...)

	reqBody := m.buildRequest(messages, options, true)

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
func (m *ClaudeChatModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	newModel := &ClaudeChatModel{
		config:     m.config,
		httpClient: m.httpClient,
		tools:      tools,
	}
	return newModel, nil
}

// buildRequest builds the Claude API request body
func (m *ClaudeChatModel) buildRequest(messages []*schema.Message, options *model.Options, stream bool) map[string]interface{} {
	// Extract system message
	var systemPrompt string
	reqMessages := make([]map[string]interface{}, 0)

	for _, msg := range messages {
		if msg.Role == schema.System {
			systemPrompt = msg.Content
			continue
		}

		reqMsg := map[string]interface{}{
			"role": m.convertRole(msg.Role),
		}

		// Build content array for Claude's format
		content := make([]map[string]interface{}, 0)

		if msg.Content != "" {
			content = append(content, map[string]interface{}{
				"type": "text",
				"text": msg.Content,
			})
		}

		// Handle tool use results
		if msg.Role == schema.Tool && msg.ToolCallID != "" {
			content = []map[string]interface{}{
				{
					"type":        "tool_result",
					"tool_use_id": msg.ToolCallID,
					"content":     msg.Content,
				},
			}
		}

		// Handle tool calls in assistant messages
		if msg.Role == schema.Assistant && len(msg.ToolCalls) > 0 {
			for _, tc := range msg.ToolCalls {
				content = append(content, map[string]interface{}{
					"type": "tool_use",
					"id":   tc.ID,
					"name": tc.Function.Name,
					"input": tc.Function.Arguments,
				})
			}
		}

		reqMsg["content"] = content
		reqMessages = append(reqMessages, reqMsg)
	}

	req := map[string]interface{}{
		"model":      m.config.Model,
		"messages":   reqMessages,
		"max_tokens": m.config.MaxTokens,
		"stream":     stream,
	}

	if systemPrompt != "" {
		req["system"] = systemPrompt
	}

	// Apply temperature
	temp := m.config.Temperature
	if options.Temperature != nil {
		temp = *options.Temperature
	}
	if temp > 0 {
		req["temperature"] = temp
	}

	// Apply max tokens override
	if options.MaxTokens != nil {
		req["max_tokens"] = *options.MaxTokens
	}

	// Add tools if bound
	if len(m.tools) > 0 {
		tools := make([]map[string]interface{}, len(m.tools))
		for i, t := range m.tools {
			tools[i] = map[string]interface{}{
				"name":        t.Name,
				"description": t.Desc,
				"input_schema": m.convertParams(t.ParamsOneOf),
			}
		}
		req["tools"] = tools
	}

	// Extended thinking configuration
	if m.config.EnableThinking {
		req["thinking"] = map[string]interface{}{
			"type":          "enabled",
			"budget_tokens": m.config.ThinkingBudget,
		}
	}

	return req
}

// convertRole converts eino role to Claude role
func (m *ClaudeChatModel) convertRole(role schema.RoleType) string {
	switch role {
	case schema.User, schema.Tool:
		return "user"
	case schema.Assistant:
		return "assistant"
	default:
		return "user"
	}
}

// convertParams converts eino params to Claude format
func (m *ClaudeChatModel) convertParams(params *schema.ParamsOneOf) map[string]interface{} {
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

// doRequest makes an HTTP request to the Claude API
func (m *ClaudeChatModel) doRequest(ctx context.Context, reqBody map[string]interface{}) (*schema.Message, error) {
	// Placeholder - in production would make actual HTTP request
	return &schema.Message{
		Role:    schema.Assistant,
		Content: "Claude placeholder response.",
	}, nil
}

// doStreamRequest makes a streaming HTTP request to the Claude API
func (m *ClaudeChatModel) doStreamRequest(ctx context.Context, reqBody map[string]interface{}, writer *schema.StreamWriter[*schema.Message]) error {
	writer.Send(&schema.Message{
		Role:    schema.Assistant,
		Content: "Claude streaming placeholder.",
	}, nil)
	return nil
}

// GetThinkingContent extracts the thinking content from a Claude response
func GetThinkingContent(msg *schema.Message) (string, bool) {
	if msg.ReasoningContent != "" {
		return msg.ReasoningContent, true
	}
	return "", false
}
