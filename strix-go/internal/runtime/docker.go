// Package runtime provides Docker runtime and sandbox management
package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DockerConfig holds the configuration for Docker runtime
type DockerConfig struct {
	Image           string
	ContainerName   string
	WorkspaceDir    string
	ToolServerPort  int
	Timeout         time.Duration
	PullPolicy      string // "always", "never", "if-not-present"
	NetworkMode     string
	MemoryLimit     string
	CPULimit        string
	Environment     map[string]string
}

// DefaultDockerConfig returns the default Docker configuration
func DefaultDockerConfig() *DockerConfig {
	return &DockerConfig{
		Image:          "ghcr.io/usestrix/strix-sandbox:0.1.10",
		ContainerName:  "strix-sandbox",
		WorkspaceDir:   "/workspace",
		ToolServerPort: 8000,
		Timeout:        5 * time.Minute,
		PullPolicy:     "if-not-present",
		NetworkMode:    "bridge",
		MemoryLimit:    "4g",
		CPULimit:       "2",
		Environment:    make(map[string]string),
	}
}

// DockerRuntime manages Docker containers for sandboxed execution
type DockerRuntime struct {
	mu sync.RWMutex

	config        *DockerConfig
	containerID   string
	running       bool
	toolServerURL string
	authToken     string
	httpClient    *http.Client
}

// NewDockerRuntime creates a new Docker runtime
func NewDockerRuntime(config *DockerConfig) *DockerRuntime {
	if config == nil {
		config = DefaultDockerConfig()
	}

	return &DockerRuntime{
		config: config,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// Start starts the Docker container
func (r *DockerRuntime) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return fmt.Errorf("container already running")
	}

	// In a real implementation, this would:
	// 1. Pull the image if needed
	// 2. Create and start the container
	// 3. Wait for the tool server to be ready
	// 4. Generate and store the auth token

	// For now, we'll simulate the container startup
	r.containerID = fmt.Sprintf("strix-%d", time.Now().UnixNano())
	r.toolServerURL = fmt.Sprintf("http://localhost:%d", r.config.ToolServerPort)
	r.authToken = generateToken()
	r.running = true

	return nil
}

// Stop stops the Docker container
func (r *DockerRuntime) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}

	// In a real implementation, this would stop and remove the container
	r.containerID = ""
	r.running = false

	return nil
}

// IsRunning returns true if the container is running
func (r *DockerRuntime) IsRunning() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.running
}

// GetContainerID returns the container ID
func (r *DockerRuntime) GetContainerID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.containerID
}

// Execute executes a tool in the sandbox
func (r *DockerRuntime) Execute(ctx context.Context, toolName, arguments string) (string, error) {
	r.mu.RLock()
	if !r.running {
		r.mu.RUnlock()
		return "", fmt.Errorf("container not running")
	}
	url := r.toolServerURL
	token := r.authToken
	r.mu.RUnlock()

	// Make request to tool server
	reqBody, _ := json.Marshal(map[string]interface{}{
		"tool_name": toolName,
		"arguments": arguments,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", url+"/execute", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("tool server request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("tool server error: %s", string(body))
	}

	var result struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return string(body), nil
	}

	if result.Error != "" {
		return "", fmt.Errorf("%s", result.Error)
	}

	return result.Output, nil
}

// IsHealthy checks if the sandbox is healthy
func (r *DockerRuntime) IsHealthy(ctx context.Context) bool {
	r.mu.RLock()
	if !r.running {
		r.mu.RUnlock()
		return false
	}
	url := r.toolServerURL
	r.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, "GET", url+"/health", nil)
	if err != nil {
		return false
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// Close closes the runtime
func (r *DockerRuntime) Close() error {
	return r.Stop(context.Background())
}

// CopyToContainer copies a file to the container
func (r *DockerRuntime) CopyToContainer(ctx context.Context, srcPath, destPath string) error {
	r.mu.RLock()
	if !r.running {
		r.mu.RUnlock()
		return fmt.Errorf("container not running")
	}
	r.mu.RUnlock()

	// In a real implementation, this would copy the file to the container
	// using docker cp or the Docker API

	return nil
}

// CopyFromContainer copies a file from the container
func (r *DockerRuntime) CopyFromContainer(ctx context.Context, srcPath, destPath string) error {
	r.mu.RLock()
	if !r.running {
		r.mu.RUnlock()
		return fmt.Errorf("container not running")
	}
	r.mu.RUnlock()

	// In a real implementation, this would copy the file from the container

	return nil
}

// ExecCommand executes a command directly in the container
func (r *DockerRuntime) ExecCommand(ctx context.Context, cmd string) (string, error) {
	r.mu.RLock()
	if !r.running {
		r.mu.RUnlock()
		return "", fmt.Errorf("container not running")
	}
	r.mu.RUnlock()

	// In a real implementation, this would execute the command in the container
	// using docker exec or the Docker API

	return "", nil
}

// SandboxClient implements the executor.SandboxClient interface
type SandboxClient struct {
	runtime *DockerRuntime
}

// NewSandboxClient creates a new sandbox client
func NewSandboxClient(runtime *DockerRuntime) *SandboxClient {
	return &SandboxClient{runtime: runtime}
}

// Execute executes a tool in the sandbox
func (c *SandboxClient) Execute(ctx context.Context, toolName, arguments string) (string, error) {
	return c.runtime.Execute(ctx, toolName, arguments)
}

// IsHealthy checks if the sandbox is healthy
func (c *SandboxClient) IsHealthy(ctx context.Context) bool {
	return c.runtime.IsHealthy(ctx)
}

// Close closes the sandbox client
func (c *SandboxClient) Close() error {
	return c.runtime.Close()
}

// Helper functions

func generateToken() string {
	// Generate a random token
	return fmt.Sprintf("strix-token-%d", time.Now().UnixNano())
}

// ImageManager manages Docker images
type ImageManager struct {
	config *DockerConfig
}

// NewImageManager creates a new image manager
func NewImageManager(config *DockerConfig) *ImageManager {
	return &ImageManager{config: config}
}

// EnsureImage ensures the Docker image is available
func (m *ImageManager) EnsureImage(ctx context.Context) error {
	// In a real implementation, this would:
	// 1. Check if image exists locally
	// 2. Pull if needed based on pull policy

	return nil
}

// GetImageInfo returns information about the Docker image
func (m *ImageManager) GetImageInfo(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"image":  m.config.Image,
		"status": "available",
	}, nil
}

// WorkspaceManager manages workspace directories
type WorkspaceManager struct {
	baseDir string
}

// NewWorkspaceManager creates a new workspace manager
func NewWorkspaceManager(baseDir string) (*WorkspaceManager, error) {
	if baseDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		baseDir = filepath.Join(homeDir, ".strix", "workspaces")
	}

	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, err
	}

	return &WorkspaceManager{baseDir: baseDir}, nil
}

// CreateWorkspace creates a new workspace
func (m *WorkspaceManager) CreateWorkspace(name string) (string, error) {
	workspaceDir := filepath.Join(m.baseDir, name)
	if err := os.MkdirAll(workspaceDir, 0755); err != nil {
		return "", err
	}
	return workspaceDir, nil
}

// GetWorkspace returns the path to a workspace
func (m *WorkspaceManager) GetWorkspace(name string) string {
	return filepath.Join(m.baseDir, name)
}

// CleanupWorkspace removes a workspace
func (m *WorkspaceManager) CleanupWorkspace(name string) error {
	workspaceDir := filepath.Join(m.baseDir, name)
	return os.RemoveAll(workspaceDir)
}
