// Package runtime provides Docker runtime and tool server for sandbox execution
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/strix-go/internal/tools/registry"
)

// ToolServer is an HTTP server that executes tools inside the sandbox
type ToolServer struct {
	mu sync.RWMutex

	port       int
	authToken  string
	registry   *registry.Registry
	server     *http.Server
	running    bool
}

// ToolServerConfig holds the configuration for the tool server
type ToolServerConfig struct {
	Port      int
	AuthToken string
}

// NewToolServer creates a new tool server
func NewToolServer(config *ToolServerConfig, reg *registry.Registry) *ToolServer {
	if config.Port == 0 {
		config.Port = 8000
	}

	return &ToolServer{
		port:      config.Port,
		authToken: config.AuthToken,
		registry:  reg,
	}
}

// Start starts the tool server
func (s *ToolServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("server already running")
	}

	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", s.handleHealth)

	// Tool execution endpoint
	mux.HandleFunc("/execute", s.withAuth(s.handleExecute))

	// List tools endpoint
	mux.HandleFunc("/tools", s.withAuth(s.handleListTools))

	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
	}

	s.running = true

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Tool server error: %v\n", err)
		}
	}()

	return nil
}

// Stop stops the tool server
func (s *ToolServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.running = false
	return s.server.Shutdown(ctx)
}

// GetPort returns the server port
func (s *ToolServer) GetPort() int {
	return s.port
}

// GetAuthToken returns the auth token
func (s *ToolServer) GetAuthToken() string {
	return s.authToken
}

// withAuth wraps a handler with authentication
func (s *ToolServer) withAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authToken != "" {
			auth := r.Header.Get("Authorization")
			expected := "Bearer " + s.authToken
			if auth != expected {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		handler(w, r)
	}
}

// handleHealth handles health check requests
func (s *ToolServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
	})
}

// ToolExecuteRequest represents a tool execution request
type ToolExecuteRequest struct {
	ToolName  string `json:"tool_name"`
	Arguments string `json:"arguments"`
}

// ToolExecuteResponse represents a tool execution response
type ToolExecuteResponse struct {
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
	Success bool   `json:"success"`
}

// handleExecute handles tool execution requests
func (s *ToolServer) handleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ToolExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendResponse(w, ToolExecuteResponse{
			Error:   fmt.Sprintf("Invalid request: %v", err),
			Success: false,
		})
		return
	}

	// Get the tool
	tool, ok := s.registry.Get(req.ToolName)
	if !ok {
		s.sendResponse(w, ToolExecuteResponse{
			Error:   fmt.Sprintf("Tool not found: %s", req.ToolName),
			Success: false,
		})
		return
	}

	// Execute the tool
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	output, err := tool.InvokableRun(ctx, req.Arguments)
	if err != nil {
		s.sendResponse(w, ToolExecuteResponse{
			Error:   err.Error(),
			Success: false,
		})
		return
	}

	s.sendResponse(w, ToolExecuteResponse{
		Output:  output,
		Success: true,
	})
}

// handleListTools handles list tools requests
func (s *ToolServer) handleListTools(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tools := s.registry.GetEnabled()
	toolInfos := make([]map[string]interface{}, 0, len(tools))

	for _, t := range tools {
		info, err := t.Info(r.Context())
		if err != nil {
			continue
		}
		toolInfos = append(toolInfos, map[string]interface{}{
			"name":        info.Name,
			"description": info.Desc,
			"category":    t.Category(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tools": toolInfos,
		"count": len(toolInfos),
	})
}

// sendResponse sends a JSON response
func (s *ToolServer) sendResponse(w http.ResponseWriter, resp ToolExecuteResponse) {
	w.Header().Set("Content-Type", "application/json")
	if !resp.Success {
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(resp)
}

// LocalToolServer runs a tool server locally (for testing without Docker)
type LocalToolServer struct {
	*ToolServer
}

// NewLocalToolServer creates a local tool server for testing
func NewLocalToolServer(port int, reg *registry.Registry) *LocalToolServer {
	token := generateToken()
	return &LocalToolServer{
		ToolServer: NewToolServer(&ToolServerConfig{
			Port:      port,
			AuthToken: token,
		}, reg),
	}
}

// GetURL returns the server URL
func (s *LocalToolServer) GetURL() string {
	return fmt.Sprintf("http://localhost:%d", s.port)
}
