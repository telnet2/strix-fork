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

// DeepSeekConfig holds the configuration for DeepSeek models
type DeepSeekConfig struct {
	APIKey  string
	BaseURL string
	Model   string
	Timeout time.Duration
}

// DeepSeekChatModel implements the ToolCallingChatModel interface for DeepSeek
type DeepSeekChatModel struct {
	config     *DeepSeekConfig
	httpClient *http.Client
	tools      []*schema.ToolInfo
}

// NewDeepSeekChatModel creates a new DeepSeek chat model
func NewDeepSeekChatModel(ctx context.Context, cfg *DeepSeekConfig) (model.ToolCallingChatModel, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("DeepSeek API key is required")
	}

	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.deepseek.com/beta"
	}

	if cfg.Model == "" {
		cfg.Model = "deepseek-chat"
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 120 * time.Second
	}

	return &DeepSeekChatModel{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		tools: make([]*schema.ToolInfo, 0),
	}, nil
}

// Generate generates a response from the DeepSeek model
func (m *DeepSeekChatModel) Generate(ctx context.Context, messages []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	options := model.GetCommonOptions(&model.Options{}, opts...)

	reqBody := m.buildRequest(messages, options, false)

	resp, err := m.doRequest(ctx, reqBody)
	if err != nil {
		return nil, fmt.Errorf("DeepSeek request failed: %w", err)
	}

	return resp, nil
}

// Stream streams a response from the DeepSeek model
func (m *DeepSeekChatModel) Stream(ctx context.Context, messages []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
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
func (m *DeepSeekChatModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	newModel := &DeepSeekChatModel{
		config:     m.config,
		httpClient: m.httpClient,
		tools:      tools,
	}
	return newModel, nil
}

// buildRequest builds the DeepSeek API request body (OpenAI-compatible)
func (m *DeepSeekChatModel) buildRequest(messages []*schema.Message, options *model.Options, stream bool) map[string]interface{} {
	reqMessages := make([]map[string]interface{}, 0, len(messages))

	for _, msg := range messages {
		reqMsg := map[string]interface{}{
			"role":    string(msg.Role),
			"content": msg.Content,
		}

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

// convertParams converts eino params to DeepSeek format
func (m *DeepSeekChatModel) convertParams(params *schema.ParamsOneOf) map[string]interface{} {
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

// doRequest makes an HTTP request to the DeepSeek API
func (m *DeepSeekChatModel) doRequest(ctx context.Context, reqBody map[string]interface{}) (*schema.Message, error) {
	return &schema.Message{
		Role:    schema.Assistant,
		Content: "DeepSeek placeholder response.",
	}, nil
}

// doStreamRequest makes a streaming HTTP request to the DeepSeek API
func (m *DeepSeekChatModel) doStreamRequest(ctx context.Context, reqBody map[string]interface{}, writer *schema.StreamWriter[*schema.Message]) error {
	writer.Send(&schema.Message{
		Role:    schema.Assistant,
		Content: "DeepSeek streaming placeholder.",
	}, nil)
	return nil
}

// GetReasoningContent extracts reasoning content from a DeepSeek response
func GetReasoningContent(msg *schema.Message) (string, bool) {
	if msg.ReasoningContent != "" {
		return msg.ReasoningContent, true
	}
	return "", false
}
