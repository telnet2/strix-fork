// Package tui provides the terminal user interface
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cloudwego/eino/schema"
	strixschema "github.com/strix-go/internal/schema"
)

// Colors
var (
	colorCritical = lipgloss.Color("#FF0000")
	colorHigh     = lipgloss.Color("#FF6600")
	colorMedium   = lipgloss.Color("#FFCC00")
	colorLow      = lipgloss.Color("#00CC00")
	colorInfo     = lipgloss.Color("#0099FF")
	colorPrimary  = lipgloss.Color("#7D56F4")
	colorSecondary = lipgloss.Color("#5E5E5E")
	colorSuccess  = lipgloss.Color("#00FF00")
	colorError    = lipgloss.Color("#FF0000")
	colorMuted    = lipgloss.Color("#666666")
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(colorPrimary).
		MarginBottom(1)

	headerStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(colorPrimary).
		Padding(0, 1)

	statusRunningStyle = lipgloss.NewStyle().
		Foreground(colorSuccess).
		Bold(true)

	statusCompletedStyle = lipgloss.NewStyle().
		Foreground(colorInfo).
		Bold(true)

	statusErrorStyle = lipgloss.NewStyle().
		Foreground(colorError).
		Bold(true)

	toolCallStyle = lipgloss.NewStyle().
		Foreground(colorSecondary).
		Italic(true)

	assistantStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF"))

	userStyle = lipgloss.NewStyle().
		Foreground(colorPrimary)

	vulnCriticalStyle = lipgloss.NewStyle().
		Foreground(colorCritical).
		Bold(true)

	vulnHighStyle = lipgloss.NewStyle().
		Foreground(colorHigh).
		Bold(true)

	vulnMediumStyle = lipgloss.NewStyle().
		Foreground(colorMedium).
		Bold(true)

	vulnLowStyle = lipgloss.NewStyle().
		Foreground(colorLow)

	vulnInfoStyle = lipgloss.NewStyle().
		Foreground(colorInfo)

	helpStyle = lipgloss.NewStyle().
		Foreground(colorMuted)

	borderStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorSecondary).
		Padding(0, 1)
)

// Messages
type (
	TickMsg        time.Time
	AgentMessageMsg struct {
		Message *schema.Message
	}
	ToolCallMsg struct {
		ToolCall schema.ToolCall
	}
	ToolResultMsg struct {
		Result *strixschema.ToolResult
	}
	VulnerabilityMsg struct {
		Vulnerability *strixschema.VulnerabilityReport
	}
	StatusChangeMsg struct {
		Status strixschema.AgentStatus
	}
	ErrorMsg struct {
		Error error
	}
)

// Model represents the TUI model
type Model struct {
	// Viewport for scrolling
	viewport viewport.Model
	spinner  spinner.Model

	// State
	width       int
	height      int
	ready       bool
	agentStatus strixschema.AgentStatus
	messages    []string
	vulnerabilities []*strixschema.VulnerabilityReport
	currentTool string
	startTime   time.Time

	// Counters
	totalToolCalls int
	successfulCalls int
	failedCalls    int
	iterations     int
}

// NewModel creates a new TUI model
func NewModel() Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(colorPrimary)

	return Model{
		spinner:         s,
		agentStatus:     strixschema.AgentStatusPending,
		messages:        make([]string, 0),
		vulnerabilities: make([]*strixschema.VulnerabilityReport, 0),
		startTime:       time.Now(),
	}
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		tea.EnterAltScreen,
	)
}

// Update updates the model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "up", "k":
			m.viewport.LineUp(1)
		case "down", "j":
			m.viewport.LineDown(1)
		case "pgup":
			m.viewport.HalfViewUp()
		case "pgdown":
			m.viewport.HalfViewDown()
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		headerHeight := 4
		footerHeight := 3

		if !m.ready {
			m.viewport = viewport.New(msg.Width, msg.Height-headerHeight-footerHeight)
			m.viewport.YPosition = headerHeight
			m.ready = true
		} else {
			m.viewport.Width = msg.Width
			m.viewport.Height = msg.Height - headerHeight - footerHeight
		}

	case spinner.TickMsg:
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)

	case AgentMessageMsg:
		content := formatMessage(msg.Message)
		m.messages = append(m.messages, content)
		m.updateViewport()

	case ToolCallMsg:
		m.currentTool = msg.ToolCall.Function.Name
		m.totalToolCalls++
		content := toolCallStyle.Render(fmt.Sprintf("🔧 Calling tool: %s", msg.ToolCall.Function.Name))
		m.messages = append(m.messages, content)
		m.updateViewport()

	case ToolResultMsg:
		if msg.Result.Success {
			m.successfulCalls++
		} else {
			m.failedCalls++
		}
		m.currentTool = ""
		content := formatToolResult(msg.Result)
		m.messages = append(m.messages, content)
		m.updateViewport()

	case VulnerabilityMsg:
		m.vulnerabilities = append(m.vulnerabilities, msg.Vulnerability)
		content := formatVulnerability(msg.Vulnerability)
		m.messages = append(m.messages, content)
		m.updateViewport()

	case StatusChangeMsg:
		m.agentStatus = msg.Status
		if msg.Status == strixschema.AgentStatusRunning {
			m.iterations++
		}

	case ErrorMsg:
		content := statusErrorStyle.Render(fmt.Sprintf("❌ Error: %v", msg.Error))
		m.messages = append(m.messages, content)
		m.updateViewport()

	case TickMsg:
		// Update elapsed time display
	}

	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

// View renders the TUI
func (m Model) View() string {
	if !m.ready {
		return "Initializing..."
	}

	var b strings.Builder

	// Header
	b.WriteString(m.renderHeader())
	b.WriteString("\n")

	// Main content
	b.WriteString(m.viewport.View())
	b.WriteString("\n")

	// Footer
	b.WriteString(m.renderFooter())

	return b.String()
}

// renderHeader renders the header section
func (m Model) renderHeader() string {
	// Title
	title := titleStyle.Render("🦉 STRIX - AI Penetration Testing")

	// Status
	status := m.renderStatus()

	// Stats
	elapsed := time.Since(m.startTime).Round(time.Second)
	stats := fmt.Sprintf("Time: %s | Tools: %d (✓%d ✗%d) | Vulns: %d",
		elapsed, m.totalToolCalls, m.successfulCalls, m.failedCalls, len(m.vulnerabilities))

	return fmt.Sprintf("%s\n%s | %s", title, status, stats)
}

// renderStatus renders the agent status
func (m Model) renderStatus() string {
	var statusStr string
	switch m.agentStatus {
	case strixschema.AgentStatusRunning:
		if m.currentTool != "" {
			statusStr = fmt.Sprintf("%s Running: %s", m.spinner.View(), m.currentTool)
		} else {
			statusStr = fmt.Sprintf("%s Running", m.spinner.View())
		}
		return statusRunningStyle.Render(statusStr)
	case strixschema.AgentStatusCompleted:
		return statusCompletedStyle.Render("✓ Completed")
	case strixschema.AgentStatusError:
		return statusErrorStyle.Render("✗ Error")
	case strixschema.AgentStatusStopped:
		return lipgloss.NewStyle().Foreground(colorMuted).Render("⏹ Stopped")
	default:
		return lipgloss.NewStyle().Foreground(colorMuted).Render("○ Pending")
	}
}

// renderFooter renders the footer section
func (m Model) renderFooter() string {
	// Vulnerability summary
	vulnSummary := m.renderVulnSummary()

	// Help
	help := helpStyle.Render("↑/↓ scroll | q quit")

	return fmt.Sprintf("%s\n%s", vulnSummary, help)
}

// renderVulnSummary renders the vulnerability summary
func (m Model) renderVulnSummary() string {
	if len(m.vulnerabilities) == 0 {
		return lipgloss.NewStyle().Foreground(colorMuted).Render("No vulnerabilities found yet")
	}

	critical, high, medium, low, info := 0, 0, 0, 0, 0
	for _, v := range m.vulnerabilities {
		switch v.Severity {
		case strixschema.SeverityCritical:
			critical++
		case strixschema.SeverityHigh:
			high++
		case strixschema.SeverityMedium:
			medium++
		case strixschema.SeverityLow:
			low++
		case strixschema.SeverityInfo:
			info++
		}
	}

	parts := make([]string, 0)
	if critical > 0 {
		parts = append(parts, vulnCriticalStyle.Render(fmt.Sprintf("C:%d", critical)))
	}
	if high > 0 {
		parts = append(parts, vulnHighStyle.Render(fmt.Sprintf("H:%d", high)))
	}
	if medium > 0 {
		parts = append(parts, vulnMediumStyle.Render(fmt.Sprintf("M:%d", medium)))
	}
	if low > 0 {
		parts = append(parts, vulnLowStyle.Render(fmt.Sprintf("L:%d", low)))
	}
	if info > 0 {
		parts = append(parts, vulnInfoStyle.Render(fmt.Sprintf("I:%d", info)))
	}

	return "Vulnerabilities: " + strings.Join(parts, " ")
}

// updateViewport updates the viewport content
func (m *Model) updateViewport() {
	content := strings.Join(m.messages, "\n\n")
	m.viewport.SetContent(content)
	m.viewport.GotoBottom()
}

// Helper functions for formatting

func formatMessage(msg *schema.Message) string {
	switch msg.Role {
	case schema.User:
		return userStyle.Render(fmt.Sprintf("👤 User: %s", msg.Content))
	case schema.Assistant:
		if msg.Content != "" {
			return assistantStyle.Render(fmt.Sprintf("🤖 Assistant: %s", msg.Content))
		}
		return ""
	case schema.System:
		return lipgloss.NewStyle().Foreground(colorMuted).Render(fmt.Sprintf("⚙️ System: %s", truncate(msg.Content, 200)))
	default:
		return msg.Content
	}
}

func formatToolResult(result *strixschema.ToolResult) string {
	if result.Success {
		output := truncate(result.Output, 500)
		return lipgloss.NewStyle().Foreground(colorSuccess).Render(fmt.Sprintf("✓ %s: %s", result.Name, output))
	}
	return lipgloss.NewStyle().Foreground(colorError).Render(fmt.Sprintf("✗ %s: %s", result.Name, result.Error))
}

func formatVulnerability(vuln *strixschema.VulnerabilityReport) string {
	var style lipgloss.Style
	var icon string

	switch vuln.Severity {
	case strixschema.SeverityCritical:
		style = vulnCriticalStyle
		icon = "🔴"
	case strixschema.SeverityHigh:
		style = vulnHighStyle
		icon = "🟠"
	case strixschema.SeverityMedium:
		style = vulnMediumStyle
		icon = "🟡"
	case strixschema.SeverityLow:
		style = vulnLowStyle
		icon = "🟢"
	default:
		style = vulnInfoStyle
		icon = "🔵"
	}

	return style.Render(fmt.Sprintf("%s [%s] %s\n   %s", icon, vuln.Severity, vuln.Title, truncate(vuln.Description, 200)))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// Run starts the TUI
func Run() error {
	p := tea.NewProgram(NewModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// Program wraps the tea.Program for external control
type Program struct {
	program *tea.Program
}

// NewProgram creates a new TUI program
func NewProgram() *Program {
	model := NewModel()
	p := tea.NewProgram(model, tea.WithAltScreen())
	return &Program{program: p}
}

// Start starts the TUI program
func (p *Program) Start() error {
	_, err := p.program.Run()
	return err
}

// Send sends a message to the TUI
func (p *Program) Send(msg tea.Msg) {
	p.program.Send(msg)
}

// SendAgentMessage sends an agent message to the TUI
func (p *Program) SendAgentMessage(msg *schema.Message) {
	p.Send(AgentMessageMsg{Message: msg})
}

// SendToolCall sends a tool call to the TUI
func (p *Program) SendToolCall(toolCall schema.ToolCall) {
	p.Send(ToolCallMsg{ToolCall: toolCall})
}

// SendToolResult sends a tool result to the TUI
func (p *Program) SendToolResult(result *strixschema.ToolResult) {
	p.Send(ToolResultMsg{Result: result})
}

// SendVulnerability sends a vulnerability to the TUI
func (p *Program) SendVulnerability(vuln *strixschema.VulnerabilityReport) {
	p.Send(VulnerabilityMsg{Vulnerability: vuln})
}

// SendStatusChange sends a status change to the TUI
func (p *Program) SendStatusChange(status strixschema.AgentStatus) {
	p.Send(StatusChangeMsg{Status: status})
}

// SendError sends an error to the TUI
func (p *Program) SendError(err error) {
	p.Send(ErrorMsg{Error: err})
}

// Quit quits the TUI program
func (p *Program) Quit() {
	p.program.Quit()
}
