// Package registry provides tool registration and management
package registry

import (
	"context"
	"fmt"
	"sync"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	strixschema "github.com/strix-go/internal/schema"
)

// Tool interface extends eino's tool interface with additional metadata
type Tool interface {
	tool.InvokableTool

	// Name returns the tool name
	Name() string

	// Category returns the tool category
	Category() strixschema.ToolCategory

	// RequiresSandbox returns true if the tool requires sandbox execution
	RequiresSandbox() bool

	// IsEnabled returns true if the tool is enabled
	IsEnabled() bool

	// Enable enables the tool
	Enable()

	// Disable disables the tool
	Disable()
}

// BaseTool provides a base implementation for tools
type BaseTool struct {
	mu sync.RWMutex

	name            string
	description     string
	category        strixschema.ToolCategory
	params          map[string]*schema.ParameterInfo
	requiresSandbox bool
	enabled         bool
	handler         func(ctx context.Context, args string) (string, error)
}

// NewBaseTool creates a new base tool
func NewBaseTool(name, description string, category strixschema.ToolCategory, params map[string]*schema.ParameterInfo, handler func(ctx context.Context, args string) (string, error)) *BaseTool {
	return &BaseTool{
		name:            name,
		description:     description,
		category:        category,
		params:          params,
		requiresSandbox: false,
		enabled:         true,
		handler:         handler,
	}
}

// Info returns the tool info
func (t *BaseTool) Info(ctx context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{
		Name:        t.name,
		Desc:        t.description,
		ParamsOneOf: schema.NewParamsOneOfByParams(t.params),
	}, nil
}

// InvokableRun executes the tool
func (t *BaseTool) InvokableRun(ctx context.Context, argumentsInJSON string, opts ...tool.Option) (string, error) {
	if !t.IsEnabled() {
		return "", fmt.Errorf("tool %s is disabled", t.name)
	}
	return t.handler(ctx, argumentsInJSON)
}

// Name returns the tool name
func (t *BaseTool) Name() string {
	return t.name
}

// Category returns the tool category
func (t *BaseTool) Category() strixschema.ToolCategory {
	return t.category
}

// RequiresSandbox returns true if the tool requires sandbox execution
func (t *BaseTool) RequiresSandbox() bool {
	return t.requiresSandbox
}

// SetRequiresSandbox sets whether the tool requires sandbox execution
func (t *BaseTool) SetRequiresSandbox(requires bool) {
	t.requiresSandbox = requires
}

// IsEnabled returns true if the tool is enabled
func (t *BaseTool) IsEnabled() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.enabled
}

// Enable enables the tool
func (t *BaseTool) Enable() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.enabled = true
}

// Disable disables the tool
func (t *BaseTool) Disable() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.enabled = false
}

// Registry manages tool registration and discovery
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

// NewRegistry creates a new tool registry
func NewRegistry() *Registry {
	return &Registry{
		tools: make(map[string]Tool),
	}
}

// Register registers a tool
func (r *Registry) Register(t Tool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := t.Name()
	if _, exists := r.tools[name]; exists {
		return fmt.Errorf("tool %s already registered", name)
	}

	r.tools[name] = t
	return nil
}

// Unregister unregisters a tool
func (r *Registry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tools[name]; !exists {
		return fmt.Errorf("tool %s not found", name)
	}

	delete(r.tools, name)
	return nil
}

// Get returns a tool by name
func (r *Registry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// GetAll returns all registered tools
func (r *Registry) GetAll() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tools := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		tools = append(tools, t)
	}
	return tools
}

// GetEnabled returns all enabled tools
func (r *Registry) GetEnabled() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tools := make([]Tool, 0)
	for _, t := range r.tools {
		if t.IsEnabled() {
			tools = append(tools, t)
		}
	}
	return tools
}

// GetByCategory returns all tools in a category
func (r *Registry) GetByCategory(category strixschema.ToolCategory) []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tools := make([]Tool, 0)
	for _, t := range r.tools {
		if t.Category() == category {
			tools = append(tools, t)
		}
	}
	return tools
}

// GetToolInfos returns tool info for all enabled tools
func (r *Registry) GetToolInfos(ctx context.Context) ([]*schema.ToolInfo, error) {
	tools := r.GetEnabled()
	infos := make([]*schema.ToolInfo, 0, len(tools))

	for _, t := range tools {
		info, err := t.Info(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get info for tool %s: %w", t.Name(), err)
		}
		infos = append(infos, info)
	}

	return infos, nil
}

// EnableTool enables a tool by name
func (r *Registry) EnableTool(name string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, ok := r.tools[name]
	if !ok {
		return fmt.Errorf("tool %s not found", name)
	}

	t.Enable()
	return nil
}

// DisableTool disables a tool by name
func (r *Registry) DisableTool(name string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, ok := r.tools[name]
	if !ok {
		return fmt.Errorf("tool %s not found", name)
	}

	t.Disable()
	return nil
}

// EnableCategory enables all tools in a category
func (r *Registry) EnableCategory(category strixschema.ToolCategory) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, t := range r.tools {
		if t.Category() == category {
			t.Enable()
		}
	}
}

// DisableCategory disables all tools in a category
func (r *Registry) DisableCategory(category strixschema.ToolCategory) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, t := range r.tools {
		if t.Category() == category {
			t.Disable()
		}
	}
}

// Count returns the number of registered tools
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tools)
}

// List returns a list of tool names
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.tools))
	for name := range r.tools {
		names = append(names, name)
	}
	return names
}
