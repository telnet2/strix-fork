// Package schema provides core types for the Strix application
package schema

import (
	"encoding/json"
	"time"

	einoschema "github.com/cloudwego/eino/schema"
)

// ToolCategory represents the category of a tool
type ToolCategory string

const (
	ToolCategoryBrowser   ToolCategory = "browser"
	ToolCategoryTerminal  ToolCategory = "terminal"
	ToolCategoryProxy     ToolCategory = "proxy"
	ToolCategoryPython    ToolCategory = "python"
	ToolCategoryFile      ToolCategory = "file"
	ToolCategoryReporting ToolCategory = "reporting"
	ToolCategoryAgents    ToolCategory = "agents"
	ToolCategoryNotes     ToolCategory = "notes"
	ToolCategorySearch    ToolCategory = "search"
)

// ToolResult represents the result of a tool execution
type ToolResult struct {
	ToolCallID string                 `json:"tool_call_id"`
	Name       string                 `json:"name"`
	Output     string                 `json:"output"`
	Error      string                 `json:"error,omitempty"`
	Success    bool                   `json:"success"`
	Duration   time.Duration          `json:"duration"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ToolInfo extends eino's ToolInfo with additional metadata
type ToolInfo struct {
	*einoschema.ToolInfo
	Category    ToolCategory `json:"category"`
	Enabled     bool         `json:"enabled"`
	RequiresSandbox bool     `json:"requires_sandbox"`
}

// NewToolInfo creates a new ToolInfo
func NewToolInfo(name, desc string, category ToolCategory, params map[string]*einoschema.ParameterInfo) *ToolInfo {
	return &ToolInfo{
		ToolInfo: &einoschema.ToolInfo{
			Name:        name,
			Desc:        desc,
			ParamsOneOf: einoschema.NewParamsOneOfByParams(params),
		},
		Category: category,
		Enabled:  true,
	}
}

// ToolCallRequest represents a request to execute a tool
type ToolCallRequest struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	AgentID   string          `json:"agent_id,omitempty"`
}

// ToolCallResponse represents the response from a tool execution
type ToolCallResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Result  string `json:"result"`
	Error   string `json:"error,omitempty"`
	Success bool   `json:"success"`
}

// Severity levels for vulnerabilities
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// VulnerabilityReport represents a security vulnerability finding
type VulnerabilityReport struct {
	ID              string                 `json:"id"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Severity        Severity               `json:"severity"`
	CVSS            float64                `json:"cvss,omitempty"`
	Category        string                 `json:"category"`
	AffectedAsset   string                 `json:"affected_asset"`
	ProofOfConcept  string                 `json:"proof_of_concept"`
	Remediation     string                 `json:"remediation"`
	References      []string               `json:"references,omitempty"`
	AgentID         string                 `json:"agent_id"`
	Timestamp       time.Time              `json:"timestamp"`
	Validated       bool                   `json:"validated"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// NewVulnerabilityReport creates a new vulnerability report
func NewVulnerabilityReport(title, description string, severity Severity) *VulnerabilityReport {
	return &VulnerabilityReport{
		ID:          generateID(),
		Title:       title,
		Description: description,
		Severity:    severity,
		Timestamp:   time.Now(),
		Validated:   false,
		Metadata:    make(map[string]interface{}),
		References:  make([]string, 0),
	}
}

// generateID generates a unique ID for vulnerability reports
func generateID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

// randomString generates a random string of the given length
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}
