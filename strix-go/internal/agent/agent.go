// Package agent provides the agent system with ReAct pattern
package agent

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/eino/schema"
	"github.com/strix-go/internal/config"
	"github.com/strix-go/internal/llm"
	strixschema "github.com/strix-go/internal/schema"
	"github.com/strix-go/internal/tools/executor"
	"github.com/strix-go/internal/tools/registry"
)

// Agent represents an AI agent that can execute tools
type Agent struct {
	mu sync.RWMutex

	id          string
	name        string
	config      *AgentConfig
	state       *strixschema.AgentState
	llmClient   *llm.Client
	registry    *registry.Registry
	executor    *executor.Executor

	// Parent-child relationship
	parentAgent *Agent
	childAgents map[string]*Agent

	// Callbacks
	onMessage      func(msg *schema.Message)
	onToolCall     func(toolCall schema.ToolCall)
	onToolResult   func(result *strixschema.ToolResult)
	onVulnerability func(vuln *strixschema.VulnerabilityReport)
	onStatusChange func(status strixschema.AgentStatus)
	onError        func(err error)

	// Control
	stopChan chan struct{}
	stopped  bool
}

// AgentConfig holds the configuration for an agent
type AgentConfig struct {
	Name              string
	Type              strixschema.AgentType
	SystemPrompt      string
	MaxIterations     int
	MaxConsecutiveErrors int
	IterationWarningThreshold float64
	StreamOutput      bool
	Workspace         string
	ParentID          string
	ExtraContext      map[string]string
	EnabledTools      []string
	DisabledTools     []string
}

// DefaultAgentConfig returns the default agent configuration
func DefaultAgentConfig(name string) *AgentConfig {
	return &AgentConfig{
		Name:                      name,
		Type:                      strixschema.AgentTypeRoot,
		MaxIterations:             300,
		MaxConsecutiveErrors:      5,
		IterationWarningThreshold: 0.85,
		StreamOutput:              true,
		ExtraContext:              make(map[string]string),
		EnabledTools:              make([]string, 0),
		DisabledTools:             make([]string, 0),
	}
}

// NewAgent creates a new agent
func NewAgent(
	id string,
	cfg *AgentConfig,
	llmClient *llm.Client,
	reg *registry.Registry,
	exec *executor.Executor,
) (*Agent, error) {
	if cfg == nil {
		cfg = DefaultAgentConfig(id)
	}

	state := strixschema.NewAgentState(id, cfg.Name, cfg.Type, cfg.MaxIterations)

	agent := &Agent{
		id:          id,
		name:        cfg.Name,
		config:      cfg,
		state:       state,
		llmClient:   llmClient,
		registry:    reg,
		executor:    exec,
		childAgents: make(map[string]*Agent),
		stopChan:    make(chan struct{}),
	}

	return agent, nil
}

// SetCallbacks sets the agent callbacks
func (a *Agent) SetCallbacks(
	onMessage func(msg *schema.Message),
	onToolCall func(toolCall schema.ToolCall),
	onToolResult func(result *strixschema.ToolResult),
	onVulnerability func(vuln *strixschema.VulnerabilityReport),
	onStatusChange func(status strixschema.AgentStatus),
	onError func(err error),
) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onMessage = onMessage
	a.onToolCall = onToolCall
	a.onToolResult = onToolResult
	a.onVulnerability = onVulnerability
	a.onStatusChange = onStatusChange
	a.onError = onError
}

// Run starts the agent execution loop
func (a *Agent) Run(ctx context.Context, initialMessage string) error {
	a.state.SetStatus(strixschema.AgentStatusRunning)
	a.state.StartedAt = time.Now()
	a.notifyStatusChange(strixschema.AgentStatusRunning)

	// Add system prompt
	if a.config.SystemPrompt != "" {
		a.state.History.Add(strixschema.NewSystemMessage(a.config.SystemPrompt))
	}

	// Add initial user message
	a.state.History.Add(strixschema.NewUserMessage(initialMessage))

	// Get tool infos
	toolInfos, err := a.registry.GetToolInfos(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tool infos: %w", err)
	}

	// Bind tools to LLM client
	llmWithTools, err := a.llmClient.WithTools(toolInfos)
	if err != nil {
		return fmt.Errorf("failed to bind tools: %w", err)
	}

	consecutiveErrors := 0

	// Main agent loop
	for {
		select {
		case <-ctx.Done():
			a.state.SetStatus(strixschema.AgentStatusStopped)
			a.notifyStatusChange(strixschema.AgentStatusStopped)
			return ctx.Err()
		case <-a.stopChan:
			a.state.SetStatus(strixschema.AgentStatusStopped)
			a.notifyStatusChange(strixschema.AgentStatusStopped)
			return nil
		default:
		}

		// Check iteration limit
		iteration := a.state.IncrementIteration()
		if iteration >= a.config.MaxIterations {
			a.state.SetStatus(strixschema.AgentStatusCompleted)
			a.notifyStatusChange(strixschema.AgentStatusCompleted)
			return fmt.Errorf("max iterations reached (%d)", a.config.MaxIterations)
		}

		// Check iteration warning threshold
		if a.state.IsNearIterationLimit(a.config.IterationWarningThreshold) {
			remaining := a.config.MaxIterations - iteration
			a.notifyError(fmt.Errorf("warning: only %d iterations remaining", remaining))
		}

		// Generate response
		messages := a.state.History.GetMessages()
		var response *schema.Message
		var genErr error

		if a.config.StreamOutput {
			response, genErr = a.generateStreaming(ctx, llmWithTools, messages)
		} else {
			response, genErr = llmWithTools.Generate(ctx, messages)
		}

		if genErr != nil {
			consecutiveErrors++
			a.state.SetError(genErr.Error())
			a.notifyError(genErr)

			if consecutiveErrors >= a.config.MaxConsecutiveErrors {
				a.state.SetStatus(strixschema.AgentStatusError)
				a.notifyStatusChange(strixschema.AgentStatusError)
				return fmt.Errorf("max consecutive errors reached: %w", genErr)
			}

			// Wait before retry
			time.Sleep(time.Duration(consecutiveErrors) * time.Second)
			continue
		}

		consecutiveErrors = 0

		// Add assistant message to history
		a.state.History.Add(strixschema.NewAssistantMessage(response.Content, response.ToolCalls))
		a.notifyMessage(response)

		// Check if there are tool calls
		if len(response.ToolCalls) == 0 {
			// Check for agent_finish or similar completion signals
			if a.isAgentFinished(response) {
				a.state.SetStatus(strixschema.AgentStatusCompleted)
				a.notifyStatusChange(strixschema.AgentStatusCompleted)
				return nil
			}
			continue
		}

		// Execute tool calls
		for _, toolCall := range response.ToolCalls {
			a.notifyToolCall(toolCall)

			result, execErr := a.executor.Execute(ctx, toolCall)
			if execErr != nil {
				a.notifyError(execErr)
			}

			a.notifyToolResult(result)

			// Add tool result to history
			content := result.Output
			if result.Error != "" {
				content = fmt.Sprintf("Error: %s", result.Error)
			}
			a.state.History.Add(strixschema.NewToolMessage(content, toolCall.ID))

			// Check for special tool results (vulnerabilities, agent commands)
			a.processToolResult(toolCall.Function.Name, result)
		}
	}
}

// generateStreaming generates a response with streaming
func (a *Agent) generateStreaming(ctx context.Context, client *llm.Client, messages []*schema.Message) (*schema.Message, error) {
	stream, err := client.Stream(ctx, messages)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	var fullContent strings.Builder
	var toolCalls []schema.ToolCall

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		fullContent.WriteString(msg.Content)
		if len(msg.ToolCalls) > 0 {
			toolCalls = append(toolCalls, msg.ToolCalls...)
		}

		// Notify partial message
		a.notifyMessage(msg)
	}

	return &schema.Message{
		Role:      schema.Assistant,
		Content:   fullContent.String(),
		ToolCalls: toolCalls,
	}, nil
}

// isAgentFinished checks if the agent should finish
func (a *Agent) isAgentFinished(response *schema.Message) bool {
	// Check for explicit finish signals in the content
	content := strings.ToLower(response.Content)
	finishSignals := []string{
		"task complete",
		"task completed",
		"finished",
		"done with the task",
		"all tasks completed",
	}

	for _, signal := range finishSignals {
		if strings.Contains(content, signal) {
			return true
		}
	}

	return false
}

// processToolResult processes special tool results
func (a *Agent) processToolResult(toolName string, result *strixschema.ToolResult) {
	switch toolName {
	case "create_vulnerability_report":
		// Parse vulnerability from result
		if result.Success {
			vuln := &strixschema.VulnerabilityReport{
				ID:        result.ToolCallID,
				AgentID:   a.id,
				Timestamp: time.Now(),
			}
			a.state.AddVulnerability(vuln)
			a.notifyVulnerability(vuln)
		}
	case "agent_finish":
		a.mu.Lock()
		a.stopped = true
		a.mu.Unlock()
	}
}

// Stop stops the agent
func (a *Agent) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.stopped {
		a.stopped = true
		close(a.stopChan)
	}
}

// GetState returns the agent state
func (a *Agent) GetState() *strixschema.AgentState {
	return a.state
}

// GetID returns the agent ID
func (a *Agent) GetID() string {
	return a.id
}

// GetName returns the agent name
func (a *Agent) GetName() string {
	return a.name
}

// SpawnChild spawns a child agent
func (a *Agent) SpawnChild(ctx context.Context, cfg *AgentConfig, task string) (*Agent, error) {
	childID := fmt.Sprintf("%s-child-%d", a.id, len(a.childAgents)+1)
	cfg.ParentID = a.id
	cfg.Type = strixschema.AgentTypeChild

	child, err := NewAgent(childID, cfg, a.llmClient, a.registry, a.executor)
	if err != nil {
		return nil, err
	}

	child.parentAgent = a
	a.childAgents[childID] = child
	a.state.AddChild(childID)

	// Inherit callbacks
	child.SetCallbacks(a.onMessage, a.onToolCall, a.onToolResult, a.onVulnerability, a.onStatusChange, a.onError)

	// Start child in background
	go func() {
		if err := child.Run(ctx, task); err != nil {
			a.notifyError(fmt.Errorf("child agent %s error: %w", childID, err))
		}
	}()

	return child, nil
}

// WaitForChildren waits for all child agents to complete
func (a *Agent) WaitForChildren(ctx context.Context) error {
	for {
		allCompleted := true
		for _, child := range a.childAgents {
			status := child.GetState().GetStatus()
			if status == strixschema.AgentStatusRunning || status == strixschema.AgentStatusPending {
				allCompleted = false
				break
			}
		}

		if allCompleted {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// Notification helpers
func (a *Agent) notifyMessage(msg *schema.Message) {
	a.mu.RLock()
	fn := a.onMessage
	a.mu.RUnlock()
	if fn != nil {
		fn(msg)
	}
}

func (a *Agent) notifyToolCall(toolCall schema.ToolCall) {
	a.mu.RLock()
	fn := a.onToolCall
	a.mu.RUnlock()
	if fn != nil {
		fn(toolCall)
	}
}

func (a *Agent) notifyToolResult(result *strixschema.ToolResult) {
	a.mu.RLock()
	fn := a.onToolResult
	a.mu.RUnlock()
	if fn != nil {
		fn(result)
	}
}

func (a *Agent) notifyVulnerability(vuln *strixschema.VulnerabilityReport) {
	a.mu.RLock()
	fn := a.onVulnerability
	a.mu.RUnlock()
	if fn != nil {
		fn(vuln)
	}
}

func (a *Agent) notifyStatusChange(status strixschema.AgentStatus) {
	a.mu.RLock()
	fn := a.onStatusChange
	a.mu.RUnlock()
	if fn != nil {
		fn(status)
	}
}

func (a *Agent) notifyError(err error) {
	a.mu.RLock()
	fn := a.onError
	a.mu.RUnlock()
	if fn != nil {
		fn(err)
	}
}

// StrixAgent is the main agent for penetration testing
type StrixAgent struct {
	*Agent
	cfg    *config.Config
	target *strixschema.Target
}

// NewStrixAgent creates a new Strix agent
func NewStrixAgent(
	cfg *config.Config,
	llmClient *llm.Client,
	reg *registry.Registry,
	exec *executor.Executor,
	target *strixschema.Target,
) (*StrixAgent, error) {
	agentCfg := &AgentConfig{
		Name:          "StrixAgent",
		Type:          strixschema.AgentTypeRoot,
		SystemPrompt:  buildStrixSystemPrompt(target),
		MaxIterations: cfg.MaxAgentIterations,
		StreamOutput:  true,
	}

	agent, err := NewAgent("strix-root", agentCfg, llmClient, reg, exec)
	if err != nil {
		return nil, err
	}

	return &StrixAgent{
		Agent:  agent,
		cfg:    cfg,
		target: target,
	}, nil
}

// buildStrixSystemPrompt builds the system prompt for Strix
func buildStrixSystemPrompt(target *strixschema.Target) string {
	return fmt.Sprintf(`You are Strix, an AI-powered penetration testing assistant. Your mission is to identify security vulnerabilities in the target system.

## Target Information
- Type: %s
- Target: %s

## Your Capabilities
1. Browser automation for testing web applications
2. Terminal commands for reconnaissance and exploitation
3. HTTP proxy for intercepting and modifying requests
4. Python code execution for custom exploits

## Guidelines
1. Start with reconnaissance to understand the attack surface
2. Identify potential vulnerabilities systematically
3. Validate vulnerabilities with proof-of-concepts
4. Document all findings using the vulnerability reporting tool
5. Prioritize critical and high severity issues
6. Be thorough but efficient in your testing

## Security Categories to Test
- Authentication & Authorization (IDOR, privilege escalation, auth bypass)
- Injection Attacks (SQL, NoSQL, command injection)
- Server-Side Vulnerabilities (SSRF, XXE, deserialization)
- Client-Side Vulnerabilities (XSS, CSRF, prototype pollution)
- Business Logic Flaws (race conditions, workflow manipulation)
- Configuration Issues (exposed secrets, misconfigurations)

Begin your security assessment now. Think step by step and use the available tools effectively.`, target.Type, target.Value)
}
