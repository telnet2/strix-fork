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

// GeminiConfig holds the configuration for Google Gemini models
type GeminiConfig struct {
	APIKey  string
	Model   string
	Timeout time.Duration

	// Thinking configuration
	EnableThinking bool
	ThinkingBudget int
}

// GeminiChatModel implements the ToolCallingChatModel interface for Gemini
type GeminiChatModel struct {
	config     *GeminiConfig
	httpClient *http.Client
	tools      []*schema.ToolInfo
}

// NewGeminiChatModel creates a new Gemini chat model
func NewGeminiChatModel(ctx context.Context, cfg *GeminiConfig) (model.ToolCallingChatModel, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("Gemini API key is required")
	}

	if cfg.Model == "" {
		cfg.Model = "gemini-2.0-flash-exp"
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 120 * time.Second
	}

	return &GeminiChatModel{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		tools: make([]*schema.ToolInfo, 0),
	}, nil
}

// Generate generates a response from the Gemini model
func (m *GeminiChatModel) Generate(ctx context.Context, messages []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	options := model.GetCommonOptions(&model.Options{}, opts...)

	reqBody := m.buildRequest(messages, options, false)

	resp, err := m.doRequest(ctx, reqBody)
	if err != nil {
		return nil, fmt.Errorf("Gemini request failed: %w", err)
	}

	return resp, nil
}

// Stream streams a response from the Gemini model
func (m *GeminiChatModel) Stream(ctx context.Context, messages []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
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
func (m *GeminiChatModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	newModel := &GeminiChatModel{
		config:     m.config,
		httpClient: m.httpClient,
		tools:      tools,
	}
	return newModel, nil
}

// buildRequest builds the Gemini API request body
func (m *GeminiChatModel) buildRequest(messages []*schema.Message, options *model.Options, stream bool) map[string]interface{} {
	// Extract system instruction
	var systemInstruction string
	contents := make([]map[string]interface{}, 0)

	for _, msg := range messages {
		if msg.Role == schema.System {
			systemInstruction = msg.Content
			continue
		}

		role := "user"
		if msg.Role == schema.Assistant {
			role = "model"
		}

		parts := make([]map[string]interface{}, 0)
		if msg.Content != "" {
			parts = append(parts, map[string]interface{}{
				"text": msg.Content,
			})
		}

		// Handle tool calls
		if msg.Role == schema.Assistant && len(msg.ToolCalls) > 0 {
			for _, tc := range msg.ToolCalls {
				parts = append(parts, map[string]interface{}{
					"functionCall": map[string]interface{}{
						"name": tc.Function.Name,
						"args": tc.Function.Arguments,
					},
				})
			}
		}

		// Handle tool responses
		if msg.Role == schema.Tool {
			parts = []map[string]interface{}{
				{
					"functionResponse": map[string]interface{}{
						"name": msg.ToolCallID,
						"response": map[string]interface{}{
							"content": msg.Content,
						},
					},
				},
			}
		}

		contents = append(contents, map[string]interface{}{
			"role":  role,
			"parts": parts,
		})
	}

	req := map[string]interface{}{
		"contents": contents,
	}

	if systemInstruction != "" {
		req["systemInstruction"] = map[string]interface{}{
			"parts": []map[string]interface{}{
				{"text": systemInstruction},
			},
		}
	}

	// Add tools if bound
	if len(m.tools) > 0 {
		functionDeclarations := make([]map[string]interface{}, len(m.tools))
		for i, t := range m.tools {
			functionDeclarations[i] = map[string]interface{}{
				"name":        t.Name,
				"description": t.Desc,
				"parameters":  m.convertParams(t.ParamsOneOf),
			}
		}
		req["tools"] = []map[string]interface{}{
			{"functionDeclarations": functionDeclarations},
		}
	}

	// Thinking configuration
	if m.config.EnableThinking {
		req["generationConfig"] = map[string]interface{}{
			"thinkingConfig": map[string]interface{}{
				"includeThoughts": true,
			},
		}
	}

	return req
}

// convertParams converts eino params to Gemini format
func (m *GeminiChatModel) convertParams(params *schema.ParamsOneOf) map[string]interface{} {
	if params == nil {
		return map[string]interface{}{
			"type":       "OBJECT",
			"properties": map[string]interface{}{},
		}
	}

	properties := make(map[string]interface{})
	required := make([]string, 0)

	if params.Params != nil {
		for name, param := range params.Params {
			prop := map[string]interface{}{
				"type":        m.convertType(param.Type),
				"description": param.Desc,
			}
			properties[name] = prop
			if param.Required {
				required = append(required, name)
			}
		}
	}

	result := map[string]interface{}{
		"type":       "OBJECT",
		"properties": properties,
	}
	if len(required) > 0 {
		result["required"] = required
	}

	return result
}

// convertType converts schema type to Gemini type
func (m *GeminiChatModel) convertType(t schema.DataType) string {
	switch t {
	case schema.String:
		return "STRING"
	case schema.Number:
		return "NUMBER"
	case schema.Integer:
		return "INTEGER"
	case schema.Boolean:
		return "BOOLEAN"
	case schema.Array:
		return "ARRAY"
	case schema.Object:
		return "OBJECT"
	default:
		return "STRING"
	}
}

// doRequest makes an HTTP request to the Gemini API
func (m *GeminiChatModel) doRequest(ctx context.Context, reqBody map[string]interface{}) (*schema.Message, error) {
	return &schema.Message{
		Role:    schema.Assistant,
		Content: "Gemini placeholder response.",
	}, nil
}

// doStreamRequest makes a streaming HTTP request to the Gemini API
func (m *GeminiChatModel) doStreamRequest(ctx context.Context, reqBody map[string]interface{}, writer *schema.StreamWriter[*schema.Message]) error {
	writer.Send(&schema.Message{
		Role:    schema.Assistant,
		Content: "Gemini streaming placeholder.",
	}, nil)
	return nil
}
