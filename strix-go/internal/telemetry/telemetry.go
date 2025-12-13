// Package telemetry provides telemetry and reporting functionality
package telemetry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	strixschema "github.com/strix-go/internal/schema"
)

// ScanTracer tracks scan progress and results
type ScanTracer struct {
	mu sync.RWMutex

	scanID          string
	startTime       time.Time
	endTime         *time.Time
	status          string
	targets         []*strixschema.Target
	vulnerabilities []*strixschema.VulnerabilityReport
	agents          []*AgentTrace
	toolCalls       []*ToolCallTrace
	errors          []ErrorTrace
	outputDir       string
}

// AgentTrace represents a trace of agent execution
type AgentTrace struct {
	ID         string                    `json:"id"`
	Name       string                    `json:"name"`
	Status     strixschema.AgentStatus   `json:"status"`
	StartTime  time.Time                 `json:"start_time"`
	EndTime    *time.Time                `json:"end_time,omitempty"`
	Iterations int                       `json:"iterations"`
	Errors     int                       `json:"errors"`
	ParentID   string                    `json:"parent_id,omitempty"`
}

// ToolCallTrace represents a trace of a tool call
type ToolCallTrace struct {
	ID        string        `json:"id"`
	ToolName  string        `json:"tool_name"`
	AgentID   string        `json:"agent_id"`
	Arguments string        `json:"arguments,omitempty"`
	Result    string        `json:"result,omitempty"`
	Error     string        `json:"error,omitempty"`
	Success   bool          `json:"success"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time     `json:"timestamp"`
}

// ErrorTrace represents an error trace
type ErrorTrace struct {
	AgentID   string    `json:"agent_id"`
	Error     string    `json:"error"`
	Timestamp time.Time `json:"timestamp"`
}

// ScanReport represents a complete scan report
type ScanReport struct {
	ScanID          string                         `json:"scan_id"`
	StartTime       time.Time                      `json:"start_time"`
	EndTime         *time.Time                     `json:"end_time,omitempty"`
	Duration        string                         `json:"duration,omitempty"`
	Status          string                         `json:"status"`
	Targets         []*strixschema.Target          `json:"targets"`
	Vulnerabilities []*strixschema.VulnerabilityReport `json:"vulnerabilities"`
	Summary         *ScanSummary                   `json:"summary"`
}

// ScanSummary provides a summary of the scan
type ScanSummary struct {
	TotalVulnerabilities int            `json:"total_vulnerabilities"`
	BySeverity           map[string]int `json:"by_severity"`
	TotalToolCalls       int            `json:"total_tool_calls"`
	SuccessfulCalls      int            `json:"successful_calls"`
	FailedCalls          int            `json:"failed_calls"`
	TotalAgents          int            `json:"total_agents"`
	TotalErrors          int            `json:"total_errors"`
}

// NewScanTracer creates a new scan tracer
func NewScanTracer(scanID, outputDir string) *ScanTracer {
	if outputDir == "" {
		outputDir = filepath.Join(".", "strix-output")
	}

	return &ScanTracer{
		scanID:          scanID,
		startTime:       time.Now(),
		status:          "running",
		targets:         make([]*strixschema.Target, 0),
		vulnerabilities: make([]*strixschema.VulnerabilityReport, 0),
		agents:          make([]*AgentTrace, 0),
		toolCalls:       make([]*ToolCallTrace, 0),
		errors:          make([]ErrorTrace, 0),
		outputDir:       outputDir,
	}
}

// AddTarget adds a target to the scan
func (t *ScanTracer) AddTarget(target *strixschema.Target) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.targets = append(t.targets, target)
}

// AddVulnerability adds a vulnerability to the scan
func (t *ScanTracer) AddVulnerability(vuln *strixschema.VulnerabilityReport) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.vulnerabilities = append(t.vulnerabilities, vuln)
}

// AddAgent adds an agent trace
func (t *ScanTracer) AddAgent(agent *AgentTrace) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.agents = append(t.agents, agent)
}

// UpdateAgent updates an agent trace
func (t *ScanTracer) UpdateAgent(id string, update func(*AgentTrace)) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, agent := range t.agents {
		if agent.ID == id {
			update(agent)
			return
		}
	}
}

// AddToolCall adds a tool call trace
func (t *ScanTracer) AddToolCall(trace *ToolCallTrace) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.toolCalls = append(t.toolCalls, trace)
}

// AddError adds an error trace
func (t *ScanTracer) AddError(agentID string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.errors = append(t.errors, ErrorTrace{
		AgentID:   agentID,
		Error:     err.Error(),
		Timestamp: time.Now(),
	})
}

// Complete marks the scan as complete
func (t *ScanTracer) Complete(status string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.endTime = &now
	t.status = status
}

// GetReport generates a scan report
func (t *ScanTracer) GetReport() *ScanReport {
	t.mu.RLock()
	defer t.mu.RUnlock()

	report := &ScanReport{
		ScanID:          t.scanID,
		StartTime:       t.startTime,
		EndTime:         t.endTime,
		Status:          t.status,
		Targets:         t.targets,
		Vulnerabilities: t.vulnerabilities,
		Summary:         t.getSummary(),
	}

	if t.endTime != nil {
		duration := t.endTime.Sub(t.startTime)
		report.Duration = duration.Round(time.Second).String()
	}

	return report
}

// getSummary generates a scan summary
func (t *ScanTracer) getSummary() *ScanSummary {
	summary := &ScanSummary{
		TotalVulnerabilities: len(t.vulnerabilities),
		BySeverity:           make(map[string]int),
		TotalToolCalls:       len(t.toolCalls),
		TotalAgents:          len(t.agents),
		TotalErrors:          len(t.errors),
	}

	for _, vuln := range t.vulnerabilities {
		summary.BySeverity[string(vuln.Severity)]++
	}

	for _, call := range t.toolCalls {
		if call.Success {
			summary.SuccessfulCalls++
		} else {
			summary.FailedCalls++
		}
	}

	return summary
}

// SaveReport saves the report to a file
func (t *ScanTracer) SaveReport() error {
	report := t.GetReport()

	// Create output directory
	if err := os.MkdirAll(t.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Save JSON report
	jsonPath := filepath.Join(t.outputDir, fmt.Sprintf("report-%s.json", t.scanID))
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	// Save Markdown report
	mdPath := filepath.Join(t.outputDir, fmt.Sprintf("report-%s.md", t.scanID))
	mdContent := t.generateMarkdownReport(report)
	if err := os.WriteFile(mdPath, []byte(mdContent), 0644); err != nil {
		return fmt.Errorf("failed to write Markdown report: %w", err)
	}

	return nil
}

// generateMarkdownReport generates a Markdown report
func (t *ScanTracer) generateMarkdownReport(report *ScanReport) string {
	var sb strings.Builder

	sb.WriteString("# Strix Security Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("**Scan ID:** %s\n", report.ScanID))
	sb.WriteString(fmt.Sprintf("**Start Time:** %s\n", report.StartTime.Format(time.RFC3339)))
	if report.EndTime != nil {
		sb.WriteString(fmt.Sprintf("**End Time:** %s\n", report.EndTime.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("**Duration:** %s\n", report.Duration))
	}
	sb.WriteString(fmt.Sprintf("**Status:** %s\n\n", report.Status))

	// Targets
	sb.WriteString("## Targets\n\n")
	for _, target := range report.Targets {
		sb.WriteString(fmt.Sprintf("- **%s**: %s\n", target.Type, target.Value))
	}
	sb.WriteString("\n")

	// Summary
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Total Vulnerabilities:** %d\n", report.Summary.TotalVulnerabilities))
	for sev, count := range report.Summary.BySeverity {
		sb.WriteString(fmt.Sprintf("  - %s: %d\n", sev, count))
	}
	sb.WriteString(fmt.Sprintf("- **Tool Calls:** %d (Success: %d, Failed: %d)\n",
		report.Summary.TotalToolCalls, report.Summary.SuccessfulCalls, report.Summary.FailedCalls))
	sb.WriteString(fmt.Sprintf("- **Agents Used:** %d\n", report.Summary.TotalAgents))
	sb.WriteString(fmt.Sprintf("- **Errors:** %d\n\n", report.Summary.TotalErrors))

	// Vulnerabilities
	if len(report.Vulnerabilities) > 0 {
		sb.WriteString("## Vulnerabilities\n\n")
		for i, vuln := range report.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("### %d. [%s] %s\n\n", i+1, vuln.Severity, vuln.Title))
			sb.WriteString(fmt.Sprintf("**Category:** %s\n", vuln.Category))
			sb.WriteString(fmt.Sprintf("**Affected Asset:** %s\n\n", vuln.AffectedAsset))
			sb.WriteString(fmt.Sprintf("**Description:**\n%s\n\n", vuln.Description))
			if vuln.ProofOfConcept != "" {
				sb.WriteString(fmt.Sprintf("**Proof of Concept:**\n```\n%s\n```\n\n", vuln.ProofOfConcept))
			}
			if vuln.Remediation != "" {
				sb.WriteString(fmt.Sprintf("**Remediation:**\n%s\n\n", vuln.Remediation))
			}
			if len(vuln.References) > 0 {
				sb.WriteString("**References:**\n")
				for _, ref := range vuln.References {
					sb.WriteString(fmt.Sprintf("- %s\n", ref))
				}
				sb.WriteString("\n")
			}
			sb.WriteString("---\n\n")
		}
	}

	return sb.String()
}

// GetVulnerabilities returns all vulnerabilities
func (t *ScanTracer) GetVulnerabilities() []*strixschema.VulnerabilityReport {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]*strixschema.VulnerabilityReport{}, t.vulnerabilities...)
}

// GetToolCalls returns all tool calls
func (t *ScanTracer) GetToolCalls() []*ToolCallTrace {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]*ToolCallTrace{}, t.toolCalls...)
}

// GetErrors returns all errors
func (t *ScanTracer) GetErrors() []ErrorTrace {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]ErrorTrace{}, t.errors...)
}

