// Package python provides Python code execution tools
package python

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/eino/schema"
	strixschema "github.com/strix-go/internal/schema"
	"github.com/strix-go/internal/tools/registry"
)

// PythonConfig holds the configuration for Python execution
type PythonConfig struct {
	PythonPath    string
	VirtualEnv    string
	Timeout       time.Duration
	MaxOutputSize int
	WorkingDir    string
	AllowedModules []string
	BlockedModules []string
}

// DefaultPythonConfig returns the default Python configuration
func DefaultPythonConfig() *PythonConfig {
	return &PythonConfig{
		PythonPath:    "python3",
		Timeout:       60 * time.Second,
		MaxOutputSize: 100000,
		BlockedModules: []string{
			"subprocess",
			"os.system",
			"eval",
			"exec",
			"__import__",
		},
	}
}

// PythonSession represents a Python execution session
type PythonSession struct {
	mu sync.RWMutex

	id          string
	config      *PythonConfig
	variables   map[string]interface{}
	history     []PythonExecution
	tempDir     string
}

// PythonExecution represents a Python code execution
type PythonExecution struct {
	Code      string        `json:"code"`
	Output    string        `json:"output"`
	Error     string        `json:"error,omitempty"`
	ExitCode  int           `json:"exit_code"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time     `json:"timestamp"`
}

// NewPythonSession creates a new Python session
func NewPythonSession(id string, config *PythonConfig) (*PythonSession, error) {
	if config == nil {
		config = DefaultPythonConfig()
	}

	// Create temp directory for the session
	tempDir, err := os.MkdirTemp("", "python-session-"+id)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	return &PythonSession{
		id:        id,
		config:    config,
		variables: make(map[string]interface{}),
		history:   make([]PythonExecution, 0),
		tempDir:   tempDir,
	}, nil
}

// Execute executes Python code
func (s *PythonSession) Execute(ctx context.Context, code string) (*PythonExecution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for blocked modules
	if blocked := s.checkBlockedModules(code); blocked != "" {
		return nil, fmt.Errorf("blocked module detected: %s", blocked)
	}

	// Create temporary file for the code
	tempFile := filepath.Join(s.tempDir, fmt.Sprintf("script_%d.py", time.Now().UnixNano()))
	if err := os.WriteFile(tempFile, []byte(code), 0644); err != nil {
		return nil, fmt.Errorf("failed to write script: %w", err)
	}
	defer os.Remove(tempFile)

	// Create command with timeout
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	pythonPath := s.config.PythonPath
	if s.config.VirtualEnv != "" {
		pythonPath = filepath.Join(s.config.VirtualEnv, "bin", "python")
	}

	cmd := exec.CommandContext(ctx, pythonPath, tempFile)

	// Set working directory
	if s.config.WorkingDir != "" {
		cmd.Dir = s.config.WorkingDir
	} else {
		cmd.Dir = s.tempDir
	}

	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	execution := &PythonExecution{
		Code:      code,
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

// checkBlockedModules checks if code contains blocked modules
func (s *PythonSession) checkBlockedModules(code string) string {
	codeLower := strings.ToLower(code)
	for _, blocked := range s.config.BlockedModules {
		if strings.Contains(codeLower, strings.ToLower(blocked)) {
			return blocked
		}
	}
	return ""
}

// GetHistory returns the execution history
func (s *PythonSession) GetHistory() []PythonExecution {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]PythonExecution{}, s.history...)
}

// Close cleans up the session
func (s *PythonSession) Close() error {
	if s.tempDir != "" {
		return os.RemoveAll(s.tempDir)
	}
	return nil
}

// PythonManager manages Python sessions and provides tools
type PythonManager struct {
	mu sync.RWMutex

	config   *PythonConfig
	sessions map[string]*PythonSession
	counter  int
}

// NewPythonManager creates a new Python manager
func NewPythonManager(config *PythonConfig) *PythonManager {
	return &PythonManager{
		config:   config,
		sessions: make(map[string]*PythonSession),
	}
}

// GetTools returns all Python tools
func (m *PythonManager) GetTools() []registry.Tool {
	return []registry.Tool{
		m.createNewSessionTool(),
		m.createExecuteTool(),
		m.createListSessionsTool(),
		m.createCloseSessionTool(),
	}
}

// createNewSessionTool creates the new session tool
func (m *PythonManager) createNewSessionTool() registry.Tool {
	return registry.NewBaseTool(
		"python_new_session",
		"Create a new Python execution session",
		strixschema.ToolCategoryPython,
		map[string]*schema.ParameterInfo{
			"working_dir": {
				Type: schema.String,
				Desc: "Working directory for the session",
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				WorkingDir string `json:"working_dir"`
			}
			if args != "" {
				if err := json.Unmarshal([]byte(args), &params); err != nil {
					return "", err
				}
			}

			m.mu.Lock()
			defer m.mu.Unlock()

			m.counter++
			sessionID := fmt.Sprintf("py-session-%d", m.counter)

			config := m.config
			if config == nil {
				config = DefaultPythonConfig()
			}
			if params.WorkingDir != "" {
				config = &PythonConfig{
					PythonPath:     config.PythonPath,
					VirtualEnv:     config.VirtualEnv,
					Timeout:        config.Timeout,
					MaxOutputSize:  config.MaxOutputSize,
					WorkingDir:     params.WorkingDir,
					AllowedModules: config.AllowedModules,
					BlockedModules: config.BlockedModules,
				}
			}

			session, err := NewPythonSession(sessionID, config)
			if err != nil {
				return "", err
			}

			m.sessions[sessionID] = session

			return fmt.Sprintf("Created Python session: %s", sessionID), nil
		},
	)
}

// createExecuteTool creates the execute tool
func (m *PythonManager) createExecuteTool() registry.Tool {
	tool := registry.NewBaseTool(
		"python_execute",
		"Execute Python code in a session. If no session exists, creates a new one automatically.",
		strixschema.ToolCategoryPython,
		map[string]*schema.ParameterInfo{
			"code": {
				Type:     schema.String,
				Desc:     "Python code to execute",
				Required: true,
			},
			"session_id": {
				Type: schema.String,
				Desc: "Session ID to use (optional, uses default if not specified)",
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				Code      string `json:"code"`
				SessionID string `json:"session_id"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			session := m.getOrCreateSession(params.SessionID)

			result, err := session.Execute(ctx, params.Code)
			if err != nil {
				return "", err
			}

			// Format output
			var output strings.Builder
			output.WriteString(fmt.Sprintf("Exit Code: %d\n", result.ExitCode))
			output.WriteString(fmt.Sprintf("Duration: %v\n", result.Duration))

			if result.Output != "" {
				output.WriteString("\n--- OUTPUT ---\n")
				output.WriteString(result.Output)
			}

			if result.Error != "" {
				output.WriteString("\n--- ERRORS ---\n")
				output.WriteString(result.Error)
			}

			return output.String(), nil
		},
	)
	tool.SetRequiresSandbox(true)
	return tool
}

// createListSessionsTool creates the list sessions tool
func (m *PythonManager) createListSessionsTool() registry.Tool {
	return registry.NewBaseTool(
		"python_list_sessions",
		"List all active Python sessions",
		strixschema.ToolCategoryPython,
		map[string]*schema.ParameterInfo{},
		func(ctx context.Context, args string) (string, error) {
			m.mu.RLock()
			defer m.mu.RUnlock()

			if len(m.sessions) == 0 {
				return "No active Python sessions", nil
			}

			var output strings.Builder
			output.WriteString(fmt.Sprintf("Active Python Sessions (%d):\n", len(m.sessions)))

			for id, session := range m.sessions {
				history := session.GetHistory()
				output.WriteString(fmt.Sprintf("  - %s (executions: %d)\n", id, len(history)))
			}

			return output.String(), nil
		},
	)
}

// createCloseSessionTool creates the close session tool
func (m *PythonManager) createCloseSessionTool() registry.Tool {
	return registry.NewBaseTool(
		"python_close_session",
		"Close a Python session",
		strixschema.ToolCategoryPython,
		map[string]*schema.ParameterInfo{
			"session_id": {
				Type:     schema.String,
				Desc:     "Session ID to close",
				Required: true,
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				SessionID string `json:"session_id"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			m.mu.Lock()
			defer m.mu.Unlock()

			session, ok := m.sessions[params.SessionID]
			if !ok {
				return "", fmt.Errorf("session %s not found", params.SessionID)
			}

			if err := session.Close(); err != nil {
				return "", fmt.Errorf("failed to close session: %w", err)
			}

			delete(m.sessions, params.SessionID)

			return fmt.Sprintf("Closed Python session: %s", params.SessionID), nil
		},
	)
}

// getOrCreateSession gets or creates a Python session
func (m *PythonManager) getOrCreateSession(sessionID string) *PythonSession {
	m.mu.Lock()
	defer m.mu.Unlock()

	if sessionID == "" {
		sessionID = "default"
	}

	if session, ok := m.sessions[sessionID]; ok {
		return session
	}

	session, _ := NewPythonSession(sessionID, m.config)
	m.sessions[sessionID] = session

	return session
}

// Close closes all sessions
func (m *PythonManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error
	for id, session := range m.sessions {
		if err := session.Close(); err != nil {
			lastErr = err
		}
		delete(m.sessions, id)
	}

	return lastErr
}
