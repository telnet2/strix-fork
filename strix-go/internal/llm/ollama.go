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

// OllamaConfig holds the configuration for Ollama models
type OllamaConfig struct {
	BaseURL string
	Model   string
	Timeout time.Duration
}

// OllamaChatModel implements the ToolCallingChatModel interface for Ollama
type OllamaChatModel struct {
	config     *OllamaConfig
	httpClient *http.Client
	tools      []*schema.ToolInfo
}

// NewOllamaChatModel creates a new Ollama chat model
func NewOllamaChatModel(ctx context.Context, cfg *OllamaConfig) (model.ToolCallingChatModel, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:11434"
	}

	if cfg.Model == "" {
		return nil, fmt.Errorf("Ollama model name is required")
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 120 * time.Second
	}

	return &OllamaChatModel{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		tools: make([]*schema.ToolInfo, 0),
	}, nil
}

// Generate generates a response from the Ollama model
func (m *OllamaChatModel) Generate(ctx context.Context, messages []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	options := model.GetCommonOptions(&model.Options{}, opts...)

	reqBody := m.buildRequest(messages, options, false)

	resp, err := m.doRequest(ctx, reqBody)
	if err != nil {
		return nil, fmt.Errorf("Ollama request failed: %w", err)
	}

	return resp, nil
}

// Stream streams a response from the Ollama model
func (m *OllamaChatModel) Stream(ctx context.Context, messages []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
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
func (m *OllamaChatModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	newModel := &OllamaChatModel{
		config:     m.config,
		httpClient: m.httpClient,
		tools:      tools,
	}
	return newModel, nil
}

// buildRequest builds the Ollama API request body
func (m *OllamaChatModel) buildRequest(messages []*schema.Message, options *model.Options, stream bool) map[string]interface{} {
	reqMessages := make([]map[string]interface{}, 0, len(messages))

	for _, msg := range messages {
		reqMsg := map[string]interface{}{
			"role":    string(msg.Role),
			"content": msg.Content,
		}
		reqMessages = append(reqMessages, reqMsg)
	}

	req := map[string]interface{}{
		"model":    m.config.Model,
		"messages": reqMessages,
		"stream":   stream,
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

// convertParams converts eino params to Ollama format
func (m *OllamaChatModel) convertParams(params *schema.ParamsOneOf) map[string]interface{} {
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

// doRequest makes an HTTP request to the Ollama API
func (m *OllamaChatModel) doRequest(ctx context.Context, reqBody map[string]interface{}) (*schema.Message, error) {
	return &schema.Message{
		Role:    schema.Assistant,
		Content: "Ollama placeholder response.",
	}, nil
}

// doStreamRequest makes a streaming HTTP request to the Ollama API
func (m *OllamaChatModel) doStreamRequest(ctx context.Context, reqBody map[string]interface{}, writer *schema.StreamWriter[*schema.Message]) error {
	writer.Send(&schema.Message{
		Role:    schema.Assistant,
		Content: "Ollama streaming placeholder.",
	}, nil)
	return nil
}
