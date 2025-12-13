// Package executor provides tool execution functionality
package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/cloudwego/eino/schema"
	strixschema "github.com/strix-go/internal/schema"
	"github.com/strix-go/internal/tools/registry"
)

// ExecutionMode defines how tools are executed
type ExecutionMode string

const (
	// ExecutionModeLocal executes tools locally
	ExecutionModeLocal ExecutionMode = "local"
	// ExecutionModeSandbox executes tools in a sandbox
	ExecutionModeSandbox ExecutionMode = "sandbox"
	// ExecutionModeAuto automatically chooses based on tool requirements
	ExecutionModeAuto ExecutionMode = "auto"
)

// ExecutorConfig holds the configuration for the executor
type ExecutorConfig struct {
	Mode           ExecutionMode
	Timeout        time.Duration
	SandboxURL     string
	SandboxToken   string
	MaxConcurrent  int
	RetryCount     int
	RetryDelay     time.Duration
}

// DefaultExecutorConfig returns the default executor configuration
func DefaultExecutorConfig() *ExecutorConfig {
	return &ExecutorConfig{
		Mode:          ExecutionModeAuto,
		Timeout:       120 * time.Second,
		MaxConcurrent: 5,
		RetryCount:    2,
		RetryDelay:    1 * time.Second,
	}
}

// Executor handles tool execution
type Executor struct {
	mu sync.RWMutex

	config   *ExecutorConfig
	registry *registry.Registry

	// Execution tracking
	executions  map[string]*Execution
	execCounter int64

	// Sandbox client (if using sandbox mode)
	sandboxClient SandboxClient

	// Event callbacks
	onExecutionStart func(exec *Execution)
	onExecutionEnd   func(exec *Execution)
}

// Execution represents a tool execution
type Execution struct {
	ID          string                    `json:"id"`
	ToolName    string                    `json:"tool_name"`
	ToolCallID  string                    `json:"tool_call_id"`
	Arguments   string                    `json:"arguments"`
	Result      string                    `json:"result"`
	Error       string                    `json:"error,omitempty"`
	Success     bool                      `json:"success"`
	StartedAt   time.Time                 `json:"started_at"`
	CompletedAt *time.Time                `json:"completed_at,omitempty"`
	Duration    time.Duration             `json:"duration"`
	Mode        ExecutionMode             `json:"mode"`
	Metadata    map[string]interface{}    `json:"metadata,omitempty"`
}

// SandboxClient interface for executing tools in a sandbox
type SandboxClient interface {
	Execute(ctx context.Context, toolName, arguments string) (string, error)
	IsHealthy(ctx context.Context) bool
	Close() error
}

// NewExecutor creates a new tool executor
func NewExecutor(config *ExecutorConfig, reg *registry.Registry) *Executor {
	if config == nil {
		config = DefaultExecutorConfig()
	}

	return &Executor{
		config:     config,
		registry:   reg,
		executions: make(map[string]*Execution),
	}
}

// SetSandboxClient sets the sandbox client for remote execution
func (e *Executor) SetSandboxClient(client SandboxClient) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sandboxClient = client
}

// SetOnExecutionStart sets the callback for execution start
func (e *Executor) SetOnExecutionStart(fn func(exec *Execution)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onExecutionStart = fn
}

// SetOnExecutionEnd sets the callback for execution end
func (e *Executor) SetOnExecutionEnd(fn func(exec *Execution)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onExecutionEnd = fn
}

// Execute executes a tool call
func (e *Executor) Execute(ctx context.Context, toolCall schema.ToolCall) (*strixschema.ToolResult, error) {
	// Get the tool
	tool, ok := e.registry.Get(toolCall.Function.Name)
	if !ok {
		return &strixschema.ToolResult{
			ToolCallID: toolCall.ID,
			Name:       toolCall.Function.Name,
			Error:      fmt.Sprintf("tool %s not found", toolCall.Function.Name),
			Success:    false,
		}, nil
	}

	// Check if tool is enabled
	if !tool.IsEnabled() {
		return &strixschema.ToolResult{
			ToolCallID: toolCall.ID,
			Name:       toolCall.Function.Name,
			Error:      fmt.Sprintf("tool %s is disabled", toolCall.Function.Name),
			Success:    false,
		}, nil
	}

	// Create execution record
	exec := e.createExecution(toolCall)

	// Notify start
	e.mu.RLock()
	if e.onExecutionStart != nil {
		e.onExecutionStart(exec)
	}
	e.mu.RUnlock()

	// Determine execution mode
	mode := e.config.Mode
	if mode == ExecutionModeAuto {
		if tool.RequiresSandbox() && e.sandboxClient != nil {
			mode = ExecutionModeSandbox
		} else {
			mode = ExecutionModeLocal
		}
	}
	exec.Mode = mode

	// Execute with timeout
	ctx, cancel := context.WithTimeout(ctx, e.config.Timeout)
	defer cancel()

	var result string
	var err error

	startTime := time.Now()

	switch mode {
	case ExecutionModeSandbox:
		result, err = e.executeSandbox(ctx, toolCall)
	default:
		result, err = e.executeLocal(ctx, tool, toolCall)
	}

	duration := time.Since(startTime)

	// Update execution record
	now := time.Now()
	exec.CompletedAt = &now
	exec.Duration = duration

	if err != nil {
		exec.Error = err.Error()
		exec.Success = false
	} else {
		exec.Result = result
		exec.Success = true
	}

	// Store execution
	e.mu.Lock()
	e.executions[exec.ID] = exec
	e.mu.Unlock()

	// Notify end
	e.mu.RLock()
	if e.onExecutionEnd != nil {
		e.onExecutionEnd(exec)
	}
	e.mu.RUnlock()

	return &strixschema.ToolResult{
		ToolCallID: toolCall.ID,
		Name:       toolCall.Function.Name,
		Output:     result,
		Error:      exec.Error,
		Success:    exec.Success,
		Duration:   duration,
	}, nil
}

// ExecuteMultiple executes multiple tool calls
func (e *Executor) ExecuteMultiple(ctx context.Context, toolCalls []schema.ToolCall) ([]*strixschema.ToolResult, error) {
	results := make([]*strixschema.ToolResult, len(toolCalls))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstError error

	// Semaphore for concurrency control
	sem := make(chan struct{}, e.config.MaxConcurrent)

	for i, tc := range toolCalls {
		wg.Add(1)
		go func(index int, toolCall schema.ToolCall) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				if firstError == nil {
					firstError = ctx.Err()
				}
				mu.Unlock()
				return
			}

			result, err := e.Execute(ctx, toolCall)

			mu.Lock()
			results[index] = result
			if err != nil && firstError == nil {
				firstError = err
			}
			mu.Unlock()
		}(i, tc)
	}

	wg.Wait()

	return results, firstError
}

// createExecution creates a new execution record
func (e *Executor) createExecution(toolCall schema.ToolCall) *Execution {
	e.mu.Lock()
	e.execCounter++
	id := fmt.Sprintf("exec-%d-%d", time.Now().UnixNano(), e.execCounter)
	e.mu.Unlock()

	return &Execution{
		ID:         id,
		ToolName:   toolCall.Function.Name,
		ToolCallID: toolCall.ID,
		Arguments:  toolCall.Function.Arguments,
		StartedAt:  time.Now(),
		Metadata:   make(map[string]interface{}),
	}
}

// executeLocal executes a tool locally
func (e *Executor) executeLocal(ctx context.Context, tool registry.Tool, toolCall schema.ToolCall) (string, error) {
	return tool.InvokableRun(ctx, toolCall.Function.Arguments)
}

// executeSandbox executes a tool in the sandbox
func (e *Executor) executeSandbox(ctx context.Context, toolCall schema.ToolCall) (string, error) {
	if e.sandboxClient == nil {
		return "", fmt.Errorf("sandbox client not configured")
	}

	return e.sandboxClient.Execute(ctx, toolCall.Function.Name, toolCall.Function.Arguments)
}

// GetExecution returns an execution by ID
func (e *Executor) GetExecution(id string) (*Execution, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	exec, ok := e.executions[id]
	return exec, ok
}

// GetExecutions returns all executions
func (e *Executor) GetExecutions() []*Execution {
	e.mu.RLock()
	defer e.mu.RUnlock()

	execs := make([]*Execution, 0, len(e.executions))
	for _, exec := range e.executions {
		execs = append(execs, exec)
	}
	return execs
}

// ClearExecutions clears the execution history
func (e *Executor) ClearExecutions() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.executions = make(map[string]*Execution)
}

// Close closes the executor
func (e *Executor) Close() error {
	if e.sandboxClient != nil {
		return e.sandboxClient.Close()
	}
	return nil
}

// ToolResultsToMessages converts tool results to schema messages
func ToolResultsToMessages(results []*strixschema.ToolResult) []*schema.Message {
	messages := make([]*schema.Message, len(results))
	for i, result := range results {
		content := result.Output
		if result.Error != "" {
			content = fmt.Sprintf("Error: %s", result.Error)
		}
		messages[i] = schema.ToolMessage(content, result.ToolCallID)
	}
	return messages
}

// ParseToolArguments parses tool arguments from JSON
func ParseToolArguments(argsJSON string, dest interface{}) error {
	if argsJSON == "" {
		return nil
	}
	return json.Unmarshal([]byte(argsJSON), dest)
}

// FormatToolResult formats a tool result for the LLM
func FormatToolResult(result interface{}) (string, error) {
	if result == nil {
		return "", nil
	}

	switch v := result.(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	case error:
		return fmt.Sprintf("Error: %v", v), nil
	default:
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return fmt.Sprintf("%v", v), nil
		}
		return string(data), nil
	}
}
