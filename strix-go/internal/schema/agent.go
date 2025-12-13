// Package schema provides core types for the Strix application
package schema

import (
	"sync"
	"time"
)

// AgentStatus represents the status of an agent
type AgentStatus string

const (
	AgentStatusPending   AgentStatus = "pending"
	AgentStatusRunning   AgentStatus = "running"
	AgentStatusWaiting   AgentStatus = "waiting"
	AgentStatusCompleted AgentStatus = "completed"
	AgentStatusError     AgentStatus = "error"
	AgentStatusStopped   AgentStatus = "stopped"
)

// AgentType represents the type of agent
type AgentType string

const (
	AgentTypeRoot   AgentType = "root"
	AgentTypeChild  AgentType = "child"
	AgentTypeHelper AgentType = "helper"
)

// AgentConfig holds the configuration for an agent
type AgentConfig struct {
	Name            string            `json:"name"`
	Type            AgentType         `json:"type"`
	SystemPrompt    string            `json:"system_prompt"`
	Modules         []string          `json:"modules,omitempty"`
	MaxIterations   int               `json:"max_iterations"`
	ParentID        string            `json:"parent_id,omitempty"`
	Workspace       string            `json:"workspace,omitempty"`
	ExtraContext    map[string]string `json:"extra_context,omitempty"`
	EnabledTools    []string          `json:"enabled_tools,omitempty"`
	DisabledTools   []string          `json:"disabled_tools,omitempty"`
}

// DefaultAgentConfig returns the default agent configuration
func DefaultAgentConfig(name string) *AgentConfig {
	return &AgentConfig{
		Name:          name,
		Type:          AgentTypeRoot,
		MaxIterations: 300,
		Modules:       make([]string, 0),
		ExtraContext:  make(map[string]string),
		EnabledTools:  make([]string, 0),
		DisabledTools: make([]string, 0),
	}
}

// AgentState represents the current state of an agent
type AgentState struct {
	mu sync.RWMutex

	ID              string                   `json:"id"`
	Name            string                   `json:"name"`
	Type            AgentType                `json:"type"`
	Status          AgentStatus              `json:"status"`
	ParentID        string                   `json:"parent_id,omitempty"`
	ChildIDs        []string                 `json:"child_ids,omitempty"`
	History         *ConversationHistory     `json:"history"`
	CurrentIteration int                     `json:"current_iteration"`
	MaxIterations   int                      `json:"max_iterations"`
	StartedAt       time.Time                `json:"started_at"`
	CompletedAt     *time.Time               `json:"completed_at,omitempty"`
	LastError       string                   `json:"last_error,omitempty"`
	ErrorCount      int                      `json:"error_count"`
	Context         map[string]interface{}   `json:"context,omitempty"`
	Vulnerabilities []*VulnerabilityReport   `json:"vulnerabilities,omitempty"`
	Notes           []string                 `json:"notes,omitempty"`
}

// NewAgentState creates a new agent state
func NewAgentState(id, name string, agentType AgentType, maxIterations int) *AgentState {
	return &AgentState{
		ID:               id,
		Name:             name,
		Type:             agentType,
		Status:           AgentStatusPending,
		History:          NewConversationHistory(100000, 15, 3),
		MaxIterations:    maxIterations,
		ChildIDs:         make([]string, 0),
		Context:          make(map[string]interface{}),
		Vulnerabilities:  make([]*VulnerabilityReport, 0),
		Notes:            make([]string, 0),
	}
}

// SetStatus safely sets the agent status
func (s *AgentState) SetStatus(status AgentStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Status = status
	if status == AgentStatusCompleted || status == AgentStatusError || status == AgentStatusStopped {
		now := time.Now()
		s.CompletedAt = &now
	}
}

// GetStatus safely gets the agent status
func (s *AgentState) GetStatus() AgentStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Status
}

// IncrementIteration safely increments the iteration counter
func (s *AgentState) IncrementIteration() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurrentIteration++
	return s.CurrentIteration
}

// GetIteration safely gets the current iteration
func (s *AgentState) GetIteration() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CurrentIteration
}

// AddChild adds a child agent ID
func (s *AgentState) AddChild(childID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ChildIDs = append(s.ChildIDs, childID)
}

// AddVulnerability adds a vulnerability report
func (s *AgentState) AddVulnerability(vuln *VulnerabilityReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Vulnerabilities = append(s.Vulnerabilities, vuln)
}

// AddNote adds a note
func (s *AgentState) AddNote(note string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Notes = append(s.Notes, note)
}

// SetError sets the last error
func (s *AgentState) SetError(err string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastError = err
	s.ErrorCount++
}

// IsNearIterationLimit checks if the agent is near the iteration limit
func (s *AgentState) IsNearIterationLimit(threshold float64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return float64(s.CurrentIteration) >= float64(s.MaxIterations)*threshold
}

// AgentNode represents a node in the agents graph
type AgentNode struct {
	ID       string       `json:"id"`
	State    *AgentState  `json:"state"`
	ParentID string       `json:"parent_id,omitempty"`
	Children []*AgentNode `json:"children,omitempty"`
}

// AgentMessage represents a message between agents
type AgentMessage struct {
	FromAgentID string    `json:"from_agent_id"`
	ToAgentID   string    `json:"to_agent_id"`
	Content     string    `json:"content"`
	Type        string    `json:"type"` // "task", "result", "status", "error"
	Timestamp   time.Time `json:"timestamp"`
}

// Target represents a scan target
type Target struct {
	Type        string            `json:"type"` // "url", "domain", "ip", "repository", "local"
	Value       string            `json:"value"`
	Name        string            `json:"name,omitempty"`
	Credentials map[string]string `json:"credentials,omitempty"`
	Scope       []string          `json:"scope,omitempty"`
	ExtraInfo   map[string]string `json:"extra_info,omitempty"`
}

// ScanConfig represents the configuration for a security scan
type ScanConfig struct {
	ID           string    `json:"id"`
	Targets      []*Target `json:"targets"`
	Instructions string    `json:"instructions,omitempty"`
	OutputDir    string    `json:"output_dir,omitempty"`
	Verbose      bool      `json:"verbose"`
	NonInteractive bool    `json:"non_interactive"`
}

// NewScanConfig creates a new scan configuration
func NewScanConfig() *ScanConfig {
	return &ScanConfig{
		ID:      time.Now().Format("20060102-150405"),
		Targets: make([]*Target, 0),
	}
}
