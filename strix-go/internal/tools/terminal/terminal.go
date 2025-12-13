// Package terminal provides terminal/shell execution tools
package terminal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/eino/schema"
	strixschema "github.com/strix-go/internal/schema"
	"github.com/strix-go/internal/tools/registry"
)

// TerminalConfig holds the configuration for terminal sessions
type TerminalConfig struct {
	Shell           string
	WorkingDir      string
	Environment     map[string]string
	Timeout         time.Duration
	MaxOutputSize   int
	AllowedCommands []string
	BlockedCommands []string
}

// DefaultTerminalConfig returns the default terminal configuration
func DefaultTerminalConfig() *TerminalConfig {
	return &TerminalConfig{
		Shell:         "/bin/bash",
		Timeout:       120 * time.Second,
		MaxOutputSize: 100000,
		BlockedCommands: []string{
			"rm -rf /",
			"dd if=",
			"mkfs",
			":(){ :|:& };:",
		},
	}
}

// TerminalSession represents a terminal session
type TerminalSession struct {
	mu sync.RWMutex

	id          string
	config      *TerminalConfig
	history     []CommandExecution
	workingDir  string
	environment map[string]string
}

// CommandExecution represents a command execution
type CommandExecution struct {
	Command   string        `json:"command"`
	Output    string        `json:"output"`
	Error     string        `json:"error,omitempty"`
	ExitCode  int           `json:"exit_code"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time     `json:"timestamp"`
}

// NewTerminalSession creates a new terminal session
func NewTerminalSession(id string, config *TerminalConfig) *TerminalSession {
	if config == nil {
		config = DefaultTerminalConfig()
	}

	env := make(map[string]string)
	for k, v := range config.Environment {
		env[k] = v
	}

	return &TerminalSession{
		id:          id,
		config:      config,
		history:     make([]CommandExecution, 0),
		workingDir:  config.WorkingDir,
		environment: env,
	}
}

// Execute executes a command in the terminal session
func (s *TerminalSession) Execute(ctx context.Context, command string) (*CommandExecution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for blocked commands
	if s.isBlocked(command) {
		return nil, fmt.Errorf("command blocked for security reasons")
	}

	// Create command with timeout
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.config.Shell, "-c", command)

	// Set working directory
	if s.workingDir != "" {
		cmd.Dir = s.workingDir
	}

	// Set environment
	for k, v := range s.environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	execution := &CommandExecution{
		Command:   command,
		Duration:  duration,
		Timestamp: startTime,
	}

	// Get output
	output := stdout.String()
	if len(output) > s.config.MaxOutputSize {
		output = output[:s.config.MaxOutputSize] + "\n... (output truncated)"
	}
	execution.Output = output

	// Get error output
	errOutput := stderr.String()
	if len(errOutput) > s.config.MaxOutputSize {
		errOutput = errOutput[:s.config.MaxOutputSize] + "\n... (error output truncated)"
	}
	execution.Error = errOutput

	// Get exit code
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			execution.ExitCode = exitErr.ExitCode()
		} else {
			execution.ExitCode = -1
		}
	} else {
		execution.ExitCode = 0
	}

	// Add to history
	s.history = append(s.history, *execution)

	return execution, nil
}

// isBlocked checks if a command is blocked
func (s *TerminalSession) isBlocked(command string) bool {
	cmdLower := strings.ToLower(command)
	for _, blocked := range s.config.BlockedCommands {
		if strings.Contains(cmdLower, strings.ToLower(blocked)) {
			return true
		}
	}
	return false
}

// GetHistory returns the command history
func (s *TerminalSession) GetHistory() []CommandExecution {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]CommandExecution{}, s.history...)
}

// SetWorkingDir sets the working directory
func (s *TerminalSession) SetWorkingDir(dir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workingDir = dir
}

// SetEnvironment sets an environment variable
func (s *TerminalSession) SetEnvironment(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.environment[key] = value
}

// TerminalManager manages terminal sessions and provides tools
type TerminalManager struct {
	mu sync.RWMutex

	config   *TerminalConfig
	sessions map[string]*TerminalSession
	counter  int
}

// NewTerminalManager creates a new terminal manager
func NewTerminalManager(config *TerminalConfig) *TerminalManager {
	return &TerminalManager{
		config:   config,
		sessions: make(map[string]*TerminalSession),
	}
}

// GetTools returns all terminal tools
func (m *TerminalManager) GetTools() []registry.Tool {
	return []registry.Tool{
		m.createExecuteTool(),
	}
}

// createExecuteTool creates the terminal execute tool
func (m *TerminalManager) createExecuteTool() registry.Tool {
	tool := registry.NewBaseTool(
		"terminal_execute",
		"Execute a shell command in the terminal. Returns the command output, error output, and exit code.",
		strixschema.ToolCategoryTerminal,
		map[string]*schema.ParameterInfo{
			"command": {
				Type:     schema.String,
				Desc:     "The shell command to execute",
				Required: true,
			},
			"working_dir": {
				Type: schema.String,
				Desc: "Working directory for the command (optional)",
			},
			"timeout": {
				Type: schema.Integer,
				Desc: "Timeout in seconds (optional, default: 120)",
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				Command    string `json:"command"`
				WorkingDir string `json:"working_dir"`
				Timeout    int    `json:"timeout"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			// Get or create session
			session := m.getOrCreateSession()

			// Set working directory if provided
			if params.WorkingDir != "" {
				session.SetWorkingDir(params.WorkingDir)
			}

			// Execute command
			result, err := session.Execute(ctx, params.Command)
			if err != nil {
				return "", err
			}

			// Format output
			var output strings.Builder
			output.WriteString(fmt.Sprintf("Exit Code: %d\n", result.ExitCode))
			output.WriteString(fmt.Sprintf("Duration: %v\n", result.Duration))
			output.WriteString("\n--- STDOUT ---\n")
			output.WriteString(result.Output)
			if result.Error != "" {
				output.WriteString("\n--- STDERR ---\n")
				output.WriteString(result.Error)
			}

			return output.String(), nil
		},
	)
	tool.SetRequiresSandbox(true)
	return tool
}

// getOrCreateSession gets or creates a terminal session
func (m *TerminalManager) getOrCreateSession() *TerminalSession {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Use a single session for simplicity
	const defaultSessionID = "default"

	if session, ok := m.sessions[defaultSessionID]; ok {
		return session
	}

	m.counter++
	session := NewTerminalSession(defaultSessionID, m.config)
	m.sessions[defaultSessionID] = session

	return session
}

// StreamingExecute executes a command and streams the output
func (s *TerminalSession) StreamingExecute(ctx context.Context, command string, stdout, stderr io.Writer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isBlocked(command) {
		return fmt.Errorf("command blocked for security reasons")
	}

	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.config.Shell, "-c", command)

	if s.workingDir != "" {
		cmd.Dir = s.workingDir
	}

	for k, v := range s.environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	cmd.Stdout = stdout
	cmd.Stderr = stderr

	return cmd.Run()
}
