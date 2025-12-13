// Package schema provides core types for the Strix application
package schema

import (
	"time"

	einoschema "github.com/cloudwego/eino/schema"
)

// Message represents a chat message in the system
type Message struct {
	*einoschema.Message
	Timestamp time.Time              `json:"timestamp"`
	AgentID   string                 `json:"agent_id,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// NewSystemMessage creates a new system message
func NewSystemMessage(content string) *Message {
	return &Message{
		Message:   einoschema.SystemMessage(content),
		Timestamp: time.Now(),
	}
}

// NewUserMessage creates a new user message
func NewUserMessage(content string) *Message {
	return &Message{
		Message:   einoschema.UserMessage(content),
		Timestamp: time.Now(),
	}
}

// NewAssistantMessage creates a new assistant message
func NewAssistantMessage(content string, toolCalls []einoschema.ToolCall) *Message {
	return &Message{
		Message:   einoschema.AssistantMessage(content, toolCalls),
		Timestamp: time.Now(),
	}
}

// NewToolMessage creates a new tool response message
func NewToolMessage(content string, toolCallID string) *Message {
	return &Message{
		Message:   einoschema.ToolMessage(content, toolCallID),
		Timestamp: time.Now(),
	}
}

// ConversationHistory represents the conversation history for an agent
type ConversationHistory struct {
	Messages     []*Message `json:"messages"`
	TokenCount   int        `json:"token_count"`
	MaxTokens    int        `json:"max_tokens"`
	MinMessages  int        `json:"min_messages"`
	ImageCount   int        `json:"image_count"`
	MaxImages    int        `json:"max_images"`
}

// NewConversationHistory creates a new conversation history
func NewConversationHistory(maxTokens, minMessages, maxImages int) *ConversationHistory {
	return &ConversationHistory{
		Messages:    make([]*Message, 0),
		MaxTokens:   maxTokens,
		MinMessages: minMessages,
		MaxImages:   maxImages,
	}
}

// Add adds a message to the conversation history
func (h *ConversationHistory) Add(msg *Message) {
	h.Messages = append(h.Messages, msg)
}

// GetMessages returns all messages as eino schema messages
func (h *ConversationHistory) GetMessages() []*einoschema.Message {
	result := make([]*einoschema.Message, len(h.Messages))
	for i, msg := range h.Messages {
		result[i] = msg.Message
	}
	return result
}

// Clear clears the conversation history
func (h *ConversationHistory) Clear() {
	h.Messages = make([]*Message, 0)
	h.TokenCount = 0
	h.ImageCount = 0
}

// Len returns the number of messages in the history
func (h *ConversationHistory) Len() int {
	return len(h.Messages)
}
