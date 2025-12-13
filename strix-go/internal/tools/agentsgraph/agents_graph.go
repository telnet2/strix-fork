// Package agentsgraph provides multi-agent orchestration tools
package agentsgraph

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

// AgentNode represents a node in the agents graph
type AgentNode struct {
	ID          string                   `json:"id"`
	Name        string                   `json:"name"`
	Status      strixschema.AgentStatus  `json:"status"`
	ParentID    string                   `json:"parent_id,omitempty"`
	ChildrenIDs []string                 `json:"children_ids,omitempty"`
	Task        string                   `json:"task,omitempty"`
	Result      string                   `json:"result,omitempty"`
	Error       string                   `json:"error,omitempty"`
	StartedAt   *time.Time               `json:"started_at,omitempty"`
	CompletedAt *time.Time               `json:"completed_at,omitempty"`
	Metadata    map[string]interface{}   `json:"metadata,omitempty"`
}

// AgentMessage represents a message between agents
type AgentMessage struct {
	ID          string    `json:"id"`
	FromAgentID string    `json:"from_agent_id"`
	ToAgentID   string    `json:"to_agent_id"`
	Content     string    `json:"content"`
	Type        string    `json:"type"` // "task", "result", "status", "error", "info"
	Timestamp   time.Time `json:"timestamp"`
	Read        bool      `json:"read"`
}

// AgentsGraph manages the multi-agent orchestration
type AgentsGraph struct {
	mu sync.RWMutex

	nodes     map[string]*AgentNode
	edges     map[string][]string // parent -> children
	messages  map[string][]*AgentMessage // to_agent_id -> messages
	msgCounter int
}

// NewAgentsGraph creates a new agents graph
func NewAgentsGraph() *AgentsGraph {
	return &AgentsGraph{
		nodes:    make(map[string]*AgentNode),
		edges:    make(map[string][]string),
		messages: make(map[string][]*AgentMessage),
	}
}

// AddNode adds a node to the graph
func (g *AgentsGraph) AddNode(node *AgentNode) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.nodes[node.ID]; exists {
		return fmt.Errorf("node %s already exists", node.ID)
	}

	g.nodes[node.ID] = node

	if node.ParentID != "" {
		g.edges[node.ParentID] = append(g.edges[node.ParentID], node.ID)
	}

	return nil
}

// UpdateNode updates a node in the graph
func (g *AgentsGraph) UpdateNode(id string, update func(*AgentNode)) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	node, exists := g.nodes[id]
	if !exists {
		return fmt.Errorf("node %s not found", id)
	}

	update(node)
	return nil
}

// GetNode returns a node by ID
func (g *AgentsGraph) GetNode(id string) (*AgentNode, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	node, ok := g.nodes[id]
	return node, ok
}

// GetAllNodes returns all nodes
func (g *AgentsGraph) GetAllNodes() []*AgentNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]*AgentNode, 0, len(g.nodes))
	for _, node := range g.nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// GetChildren returns the children of a node
func (g *AgentsGraph) GetChildren(parentID string) []*AgentNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	childIDs := g.edges[parentID]
	children := make([]*AgentNode, 0, len(childIDs))

	for _, id := range childIDs {
		if node, ok := g.nodes[id]; ok {
			children = append(children, node)
		}
	}

	return children
}

// SendMessage sends a message between agents
func (g *AgentsGraph) SendMessage(msg *AgentMessage) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.msgCounter++
	msg.ID = fmt.Sprintf("msg-%d", g.msgCounter)
	msg.Timestamp = time.Now()
	msg.Read = false

	g.messages[msg.ToAgentID] = append(g.messages[msg.ToAgentID], msg)
	return nil
}

// GetMessages returns unread messages for an agent
func (g *AgentsGraph) GetMessages(agentID string, markRead bool) []*AgentMessage {
	g.mu.Lock()
	defer g.mu.Unlock()

	messages := g.messages[agentID]
	unread := make([]*AgentMessage, 0)

	for _, msg := range messages {
		if !msg.Read {
			unread = append(unread, msg)
			if markRead {
				msg.Read = true
			}
		}
	}

	return unread
}

// GetAllMessages returns all messages for an agent
func (g *AgentsGraph) GetAllMessages(agentID string) []*AgentMessage {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.messages[agentID]
}

// AgentsGraphManager provides tools for multi-agent orchestration
type AgentsGraphManager struct {
	mu sync.RWMutex

	graph      *AgentsGraph
	agentSpawner func(ctx context.Context, name, task string) (string, error)
}

// NewAgentsGraphManager creates a new agents graph manager
func NewAgentsGraphManager(graph *AgentsGraph) *AgentsGraphManager {
	return &AgentsGraphManager{
		graph: graph,
	}
}

// SetAgentSpawner sets the function to spawn new agents
func (m *AgentsGraphManager) SetAgentSpawner(spawner func(ctx context.Context, name, task string) (string, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.agentSpawner = spawner
}

// GetTools returns all agents graph tools
func (m *AgentsGraphManager) GetTools() []registry.Tool {
	return []registry.Tool{
		m.createSpawnAgentTool(),
		m.createListAgentsTool(),
		m.createGetAgentStatusTool(),
		m.createSendMessageTool(),
		m.createReceiveMessagesTool(),
		m.createAgentFinishTool(),
	}
}

// createSpawnAgentTool creates the spawn agent tool
func (m *AgentsGraphManager) createSpawnAgentTool() registry.Tool {
	return registry.NewBaseTool(
		"spawn_agent",
		"Spawn a new sub-agent to handle a specific task. The sub-agent will run independently and report back when complete.",
		strixschema.ToolCategoryAgents,
		map[string]*schema.ParameterInfo{
			"name": {
				Type:     schema.String,
				Desc:     "Name/identifier for the sub-agent",
				Required: true,
			},
			"task": {
				Type:     schema.String,
				Desc:     "Detailed task description for the sub-agent",
				Required: true,
			},
			"context": {
				Type: schema.String,
				Desc: "Additional context to provide to the sub-agent",
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				Name    string `json:"name"`
				Task    string `json:"task"`
				Context string `json:"context"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			m.mu.RLock()
			spawner := m.agentSpawner
			m.mu.RUnlock()

			if spawner == nil {
				return "", fmt.Errorf("agent spawner not configured")
			}

			// Combine task and context
			fullTask := params.Task
			if params.Context != "" {
				fullTask = fmt.Sprintf("%s\n\nContext: %s", params.Task, params.Context)
			}

			agentID, err := spawner(ctx, params.Name, fullTask)
			if err != nil {
				return "", fmt.Errorf("failed to spawn agent: %w", err)
			}

			// Add to graph
			now := time.Now()
			node := &AgentNode{
				ID:        agentID,
				Name:      params.Name,
				Status:    strixschema.AgentStatusRunning,
				Task:      params.Task,
				StartedAt: &now,
				Metadata:  make(map[string]interface{}),
			}
			m.graph.AddNode(node)

			return fmt.Sprintf("Spawned sub-agent '%s' with ID: %s", params.Name, agentID), nil
		},
	)
}

// createListAgentsTool creates the list agents tool
func (m *AgentsGraphManager) createListAgentsTool() registry.Tool {
	return registry.NewBaseTool(
		"list_agents",
		"List all agents in the current session",
		strixschema.ToolCategoryAgents,
		map[string]*schema.ParameterInfo{
			"status_filter": {
				Type: schema.String,
				Desc: "Filter by status: 'running', 'completed', 'error', 'all'",
				Enum: []string{"running", "completed", "error", "all"},
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				StatusFilter string `json:"status_filter"`
			}
			if args != "" {
				if err := json.Unmarshal([]byte(args), &params); err != nil {
					return "", err
				}
			}
			if params.StatusFilter == "" {
				params.StatusFilter = "all"
			}

			nodes := m.graph.GetAllNodes()

			var output string
			output += fmt.Sprintf("Agents (%d total):\n\n", len(nodes))

			for _, node := range nodes {
				if params.StatusFilter != "all" && string(node.Status) != params.StatusFilter {
					continue
				}

				status := string(node.Status)
				output += fmt.Sprintf("[%s] %s (%s)\n", node.ID, node.Name, status)
				if node.Task != "" {
					taskPreview := node.Task
					if len(taskPreview) > 100 {
						taskPreview = taskPreview[:100] + "..."
					}
					output += fmt.Sprintf("  Task: %s\n", taskPreview)
				}
				if node.Error != "" {
					output += fmt.Sprintf("  Error: %s\n", node.Error)
				}
			}

			return output, nil
		},
	)
}

// createGetAgentStatusTool creates the get agent status tool
func (m *AgentsGraphManager) createGetAgentStatusTool() registry.Tool {
	return registry.NewBaseTool(
		"get_agent_status",
		"Get detailed status of a specific agent",
		strixschema.ToolCategoryAgents,
		map[string]*schema.ParameterInfo{
			"agent_id": {
				Type:     schema.String,
				Desc:     "ID of the agent to check",
				Required: true,
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				AgentID string `json:"agent_id"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			node, ok := m.graph.GetNode(params.AgentID)
			if !ok {
				return "", fmt.Errorf("agent %s not found", params.AgentID)
			}

			result, _ := json.MarshalIndent(node, "", "  ")
			return string(result), nil
		},
	)
}

// createSendMessageTool creates the send message tool
func (m *AgentsGraphManager) createSendMessageTool() registry.Tool {
	return registry.NewBaseTool(
		"send_agent_message",
		"Send a message to another agent",
		strixschema.ToolCategoryAgents,
		map[string]*schema.ParameterInfo{
			"to_agent_id": {
				Type:     schema.String,
				Desc:     "ID of the agent to send the message to",
				Required: true,
			},
			"message": {
				Type:     schema.String,
				Desc:     "Message content",
				Required: true,
			},
			"type": {
				Type: schema.String,
				Desc: "Message type: 'task', 'result', 'info', 'error'",
				Enum: []string{"task", "result", "info", "error"},
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				ToAgentID string `json:"to_agent_id"`
				Message   string `json:"message"`
				Type      string `json:"type"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			if params.Type == "" {
				params.Type = "info"
			}

			// Get current agent ID from context (simplified for now)
			fromAgentID := "current-agent"

			msg := &AgentMessage{
				FromAgentID: fromAgentID,
				ToAgentID:   params.ToAgentID,
				Content:     params.Message,
				Type:        params.Type,
			}

			if err := m.graph.SendMessage(msg); err != nil {
				return "", err
			}

			return fmt.Sprintf("Message sent to agent %s", params.ToAgentID), nil
		},
	)
}

// createReceiveMessagesTool creates the receive messages tool
func (m *AgentsGraphManager) createReceiveMessagesTool() registry.Tool {
	return registry.NewBaseTool(
		"receive_agent_messages",
		"Receive messages from other agents",
		strixschema.ToolCategoryAgents,
		map[string]*schema.ParameterInfo{
			"mark_read": {
				Type: schema.Boolean,
				Desc: "Mark messages as read after receiving (default: true)",
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				MarkRead *bool `json:"mark_read"`
			}
			if args != "" {
				if err := json.Unmarshal([]byte(args), &params); err != nil {
					return "", err
				}
			}

			markRead := true
			if params.MarkRead != nil {
				markRead = *params.MarkRead
			}

			// Get current agent ID from context
			agentID := "current-agent"

			messages := m.graph.GetMessages(agentID, markRead)

			if len(messages) == 0 {
				return "No new messages", nil
			}

			var output string
			output += fmt.Sprintf("Received %d messages:\n\n", len(messages))

			for _, msg := range messages {
				output += fmt.Sprintf("[%s] From: %s (Type: %s)\n", msg.Timestamp.Format("15:04:05"), msg.FromAgentID, msg.Type)
				output += fmt.Sprintf("  %s\n\n", msg.Content)
			}

			return output, nil
		},
	)
}

// createAgentFinishTool creates the agent finish tool
func (m *AgentsGraphManager) createAgentFinishTool() registry.Tool {
	return registry.NewBaseTool(
		"agent_finish",
		"Signal that the current agent has completed its task. Include a summary of findings and any final results.",
		strixschema.ToolCategoryAgents,
		map[string]*schema.ParameterInfo{
			"summary": {
				Type:     schema.String,
				Desc:     "Summary of what was accomplished",
				Required: true,
			},
			"findings": {
				Type: schema.String,
				Desc: "Any important findings or vulnerabilities discovered",
			},
			"recommendations": {
				Type: schema.String,
				Desc: "Recommendations for next steps or follow-up tasks",
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				Summary         string `json:"summary"`
				Findings        string `json:"findings"`
				Recommendations string `json:"recommendations"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			result := fmt.Sprintf("Agent completed.\n\nSummary: %s", params.Summary)
			if params.Findings != "" {
				result += fmt.Sprintf("\n\nFindings: %s", params.Findings)
			}
			if params.Recommendations != "" {
				result += fmt.Sprintf("\n\nRecommendations: %s", params.Recommendations)
			}

			return result, nil
		},
	)
}
