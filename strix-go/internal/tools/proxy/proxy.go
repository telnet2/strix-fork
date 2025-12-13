// Package proxy provides HTTP proxy tools for request interception and modification
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/eino/schema"
	strixschema "github.com/strix-go/internal/schema"
	"github.com/strix-go/internal/tools/registry"
)

// HTTPRequest represents a captured HTTP request
type HTTPRequest struct {
	ID          string              `json:"id"`
	Method      string              `json:"method"`
	URL         string              `json:"url"`
	Headers     map[string][]string `json:"headers"`
	Body        string              `json:"body,omitempty"`
	Timestamp   time.Time           `json:"timestamp"`
	ContentType string              `json:"content_type,omitempty"`
}

// HTTPResponse represents a captured HTTP response
type HTTPResponse struct {
	StatusCode  int                 `json:"status_code"`
	Status      string              `json:"status"`
	Headers     map[string][]string `json:"headers"`
	Body        string              `json:"body,omitempty"`
	ContentType string              `json:"content_type,omitempty"`
	Duration    time.Duration       `json:"duration"`
}

// RequestResponsePair represents a captured request/response pair
type RequestResponsePair struct {
	Request  *HTTPRequest  `json:"request"`
	Response *HTTPResponse `json:"response,omitempty"`
	Error    string        `json:"error,omitempty"`
}

// ScopeRule defines a rule for filtering requests
type ScopeRule struct {
	Type    string `json:"type"`    // "include" or "exclude"
	Pattern string `json:"pattern"` // URL pattern (supports wildcards)
}

// ProxyConfig holds the configuration for the HTTP proxy
type ProxyConfig struct {
	Port            int
	CertFile        string
	KeyFile         string
	Timeout         time.Duration
	MaxBodySize     int64
	EnableHTTPS     bool
	ScopeRules      []ScopeRule
}

// DefaultProxyConfig returns the default proxy configuration
func DefaultProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		Port:        8080,
		Timeout:     30 * time.Second,
		MaxBodySize: 10 * 1024 * 1024, // 10MB
		EnableHTTPS: true,
	}
}

// ProxyManager manages the HTTP proxy and provides tools
type ProxyManager struct {
	mu sync.RWMutex

	config     *ProxyConfig
	requests   map[string]*RequestResponsePair
	counter    int
	httpClient *http.Client
	scopeRules []ScopeRule
}

// NewProxyManager creates a new proxy manager
func NewProxyManager(config *ProxyConfig) *ProxyManager {
	if config == nil {
		config = DefaultProxyConfig()
	}

	return &ProxyManager{
		config:   config,
		requests: make(map[string]*RequestResponsePair),
		httpClient: &http.Client{
			Timeout: config.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		scopeRules: config.ScopeRules,
	}
}

// GetTools returns all proxy tools
func (m *ProxyManager) GetTools() []registry.Tool {
	return []registry.Tool{
		m.createSendRequestTool(),
		m.createListRequestsTool(),
		m.createViewRequestTool(),
		m.createRepeatRequestTool(),
		m.createScopeRulesTool(),
	}
}

// createSendRequestTool creates the send request tool
func (m *ProxyManager) createSendRequestTool() registry.Tool {
	return registry.NewBaseTool(
		"http_send_request",
		"Send an HTTP request and return the response. Supports all HTTP methods.",
		strixschema.ToolCategoryProxy,
		map[string]*schema.ParameterInfo{
			"method": {
				Type:     schema.String,
				Desc:     "HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)",
				Required: true,
				Enum:     []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
			},
			"url": {
				Type:     schema.String,
				Desc:     "The URL to send the request to",
				Required: true,
			},
			"headers": {
				Type: schema.Object,
				Desc: "Request headers as key-value pairs",
			},
			"body": {
				Type: schema.String,
				Desc: "Request body (for POST, PUT, PATCH)",
			},
			"follow_redirects": {
				Type: schema.Boolean,
				Desc: "Whether to follow redirects (default: false)",
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				Method          string            `json:"method"`
				URL             string            `json:"url"`
				Headers         map[string]string `json:"headers"`
				Body            string            `json:"body"`
				FollowRedirects bool              `json:"follow_redirects"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			// Create request
			var bodyReader io.Reader
			if params.Body != "" {
				bodyReader = strings.NewReader(params.Body)
			}

			req, err := http.NewRequestWithContext(ctx, params.Method, params.URL, bodyReader)
			if err != nil {
				return "", fmt.Errorf("failed to create request: %w", err)
			}

			// Set headers
			for k, v := range params.Headers {
				req.Header.Set(k, v)
			}

			// Store request
			httpReq := &HTTPRequest{
				ID:        m.generateID(),
				Method:    params.Method,
				URL:       params.URL,
				Headers:   req.Header,
				Body:      params.Body,
				Timestamp: time.Now(),
			}
			if ct := req.Header.Get("Content-Type"); ct != "" {
				httpReq.ContentType = ct
			}

			// Send request
			startTime := time.Now()
			resp, err := m.httpClient.Do(req)
			duration := time.Since(startTime)

			pair := &RequestResponsePair{Request: httpReq}

			if err != nil {
				pair.Error = err.Error()
				m.storeRequest(pair)
				return "", fmt.Errorf("request failed: %w", err)
			}
			defer resp.Body.Close()

			// Read response body
			body, err := io.ReadAll(io.LimitReader(resp.Body, m.config.MaxBodySize))
			if err != nil {
				pair.Error = err.Error()
				m.storeRequest(pair)
				return "", fmt.Errorf("failed to read response: %w", err)
			}

			// Store response
			httpResp := &HTTPResponse{
				StatusCode:  resp.StatusCode,
				Status:      resp.Status,
				Headers:     resp.Header,
				Body:        string(body),
				ContentType: resp.Header.Get("Content-Type"),
				Duration:    duration,
			}
			pair.Response = httpResp

			m.storeRequest(pair)

			// Format output
			return m.formatResponse(pair), nil
		},
	)
}

// createListRequestsTool creates the list requests tool
func (m *ProxyManager) createListRequestsTool() registry.Tool {
	return registry.NewBaseTool(
		"http_list_requests",
		"List all captured HTTP requests",
		strixschema.ToolCategoryProxy,
		map[string]*schema.ParameterInfo{
			"limit": {
				Type: schema.Integer,
				Desc: "Maximum number of requests to return (default: 20)",
			},
			"filter_url": {
				Type: schema.String,
				Desc: "Filter requests by URL pattern",
			},
			"filter_method": {
				Type: schema.String,
				Desc: "Filter requests by HTTP method",
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				Limit        int    `json:"limit"`
				FilterURL    string `json:"filter_url"`
				FilterMethod string `json:"filter_method"`
			}
			if args != "" {
				if err := json.Unmarshal([]byte(args), &params); err != nil {
					return "", err
				}
			}

			if params.Limit == 0 {
				params.Limit = 20
			}

			m.mu.RLock()
			defer m.mu.RUnlock()

			requests := make([]*RequestResponsePair, 0)
			for _, pair := range m.requests {
				// Apply filters
				if params.FilterURL != "" && !strings.Contains(pair.Request.URL, params.FilterURL) {
					continue
				}
				if params.FilterMethod != "" && pair.Request.Method != params.FilterMethod {
					continue
				}
				requests = append(requests, pair)
				if len(requests) >= params.Limit {
					break
				}
			}

			// Format output
			var output strings.Builder
			output.WriteString(fmt.Sprintf("Found %d requests:\n\n", len(requests)))

			for _, pair := range requests {
				output.WriteString(fmt.Sprintf("[%s] %s %s", pair.Request.ID, pair.Request.Method, pair.Request.URL))
				if pair.Response != nil {
					output.WriteString(fmt.Sprintf(" -> %d", pair.Response.StatusCode))
				}
				output.WriteString("\n")
			}

			return output.String(), nil
		},
	)
}

// createViewRequestTool creates the view request tool
func (m *ProxyManager) createViewRequestTool() registry.Tool {
	return registry.NewBaseTool(
		"http_view_request",
		"View details of a captured HTTP request/response",
		strixschema.ToolCategoryProxy,
		map[string]*schema.ParameterInfo{
			"request_id": {
				Type:     schema.String,
				Desc:     "The ID of the request to view",
				Required: true,
			},
			"show_headers": {
				Type: schema.Boolean,
				Desc: "Whether to show headers (default: true)",
			},
			"show_body": {
				Type: schema.Boolean,
				Desc: "Whether to show body (default: true)",
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				RequestID   string `json:"request_id"`
				ShowHeaders *bool  `json:"show_headers"`
				ShowBody    *bool  `json:"show_body"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			showHeaders := true
			showBody := true
			if params.ShowHeaders != nil {
				showHeaders = *params.ShowHeaders
			}
			if params.ShowBody != nil {
				showBody = *params.ShowBody
			}

			m.mu.RLock()
			pair, ok := m.requests[params.RequestID]
			m.mu.RUnlock()

			if !ok {
				return "", fmt.Errorf("request %s not found", params.RequestID)
			}

			return m.formatDetailedResponse(pair, showHeaders, showBody), nil
		},
	)
}

// createRepeatRequestTool creates the repeat request tool
func (m *ProxyManager) createRepeatRequestTool() registry.Tool {
	return registry.NewBaseTool(
		"http_repeat_request",
		"Repeat a previously captured HTTP request, optionally with modifications",
		strixschema.ToolCategoryProxy,
		map[string]*schema.ParameterInfo{
			"request_id": {
				Type:     schema.String,
				Desc:     "The ID of the request to repeat",
				Required: true,
			},
			"modify_headers": {
				Type: schema.Object,
				Desc: "Headers to add or modify",
			},
			"modify_body": {
				Type: schema.String,
				Desc: "New request body (replaces original)",
			},
			"modify_url": {
				Type: schema.String,
				Desc: "New URL (replaces original)",
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				RequestID     string            `json:"request_id"`
				ModifyHeaders map[string]string `json:"modify_headers"`
				ModifyBody    string            `json:"modify_body"`
				ModifyURL     string            `json:"modify_url"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			m.mu.RLock()
			originalPair, ok := m.requests[params.RequestID]
			m.mu.RUnlock()

			if !ok {
				return "", fmt.Errorf("request %s not found", params.RequestID)
			}

			// Build new request
			reqURL := originalPair.Request.URL
			if params.ModifyURL != "" {
				reqURL = params.ModifyURL
			}

			body := originalPair.Request.Body
			if params.ModifyBody != "" {
				body = params.ModifyBody
			}

			var bodyReader io.Reader
			if body != "" {
				bodyReader = strings.NewReader(body)
			}

			req, err := http.NewRequestWithContext(ctx, originalPair.Request.Method, reqURL, bodyReader)
			if err != nil {
				return "", fmt.Errorf("failed to create request: %w", err)
			}

			// Copy original headers
			for k, v := range originalPair.Request.Headers {
				req.Header[k] = v
			}

			// Apply modified headers
			for k, v := range params.ModifyHeaders {
				req.Header.Set(k, v)
			}

			// Send request
			startTime := time.Now()
			resp, err := m.httpClient.Do(req)
			duration := time.Since(startTime)

			httpReq := &HTTPRequest{
				ID:          m.generateID(),
				Method:      originalPair.Request.Method,
				URL:         reqURL,
				Headers:     req.Header,
				Body:        body,
				Timestamp:   time.Now(),
				ContentType: req.Header.Get("Content-Type"),
			}

			pair := &RequestResponsePair{Request: httpReq}

			if err != nil {
				pair.Error = err.Error()
				m.storeRequest(pair)
				return "", fmt.Errorf("request failed: %w", err)
			}
			defer resp.Body.Close()

			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, m.config.MaxBodySize))

			httpResp := &HTTPResponse{
				StatusCode:  resp.StatusCode,
				Status:      resp.Status,
				Headers:     resp.Header,
				Body:        string(respBody),
				ContentType: resp.Header.Get("Content-Type"),
				Duration:    duration,
			}
			pair.Response = httpResp

			m.storeRequest(pair)

			return m.formatResponse(pair), nil
		},
	)
}

// createScopeRulesTool creates the scope rules tool
func (m *ProxyManager) createScopeRulesTool() registry.Tool {
	return registry.NewBaseTool(
		"http_scope_rules",
		"Manage scope rules for filtering requests",
		strixschema.ToolCategoryProxy,
		map[string]*schema.ParameterInfo{
			"action": {
				Type:     schema.String,
				Desc:     "Action to perform: 'list', 'add', 'remove', 'clear'",
				Required: true,
				Enum:     []string{"list", "add", "remove", "clear"},
			},
			"type": {
				Type: schema.String,
				Desc: "Rule type: 'include' or 'exclude' (for add action)",
				Enum: []string{"include", "exclude"},
			},
			"pattern": {
				Type: schema.String,
				Desc: "URL pattern (for add/remove actions)",
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				Action  string `json:"action"`
				Type    string `json:"type"`
				Pattern string `json:"pattern"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			m.mu.Lock()
			defer m.mu.Unlock()

			switch params.Action {
			case "list":
				if len(m.scopeRules) == 0 {
					return "No scope rules defined", nil
				}
				var output strings.Builder
				output.WriteString("Scope Rules:\n")
				for i, rule := range m.scopeRules {
					output.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, rule.Type, rule.Pattern))
				}
				return output.String(), nil

			case "add":
				if params.Pattern == "" {
					return "", fmt.Errorf("pattern is required for add action")
				}
				if params.Type == "" {
					params.Type = "include"
				}
				m.scopeRules = append(m.scopeRules, ScopeRule{
					Type:    params.Type,
					Pattern: params.Pattern,
				})
				return fmt.Sprintf("Added scope rule: [%s] %s", params.Type, params.Pattern), nil

			case "remove":
				if params.Pattern == "" {
					return "", fmt.Errorf("pattern is required for remove action")
				}
				for i, rule := range m.scopeRules {
					if rule.Pattern == params.Pattern {
						m.scopeRules = append(m.scopeRules[:i], m.scopeRules[i+1:]...)
						return fmt.Sprintf("Removed scope rule: %s", params.Pattern), nil
					}
				}
				return "", fmt.Errorf("scope rule not found: %s", params.Pattern)

			case "clear":
				m.scopeRules = nil
				return "Cleared all scope rules", nil

			default:
				return "", fmt.Errorf("unknown action: %s", params.Action)
			}
		},
	)
}

// generateID generates a unique request ID
func (m *ProxyManager) generateID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counter++
	return fmt.Sprintf("req-%d", m.counter)
}

// storeRequest stores a request/response pair
func (m *ProxyManager) storeRequest(pair *RequestResponsePair) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[pair.Request.ID] = pair
}

// formatResponse formats a response for output
func (m *ProxyManager) formatResponse(pair *RequestResponsePair) string {
	var output bytes.Buffer

	output.WriteString(fmt.Sprintf("Request ID: %s\n", pair.Request.ID))
	output.WriteString(fmt.Sprintf("Method: %s\n", pair.Request.Method))
	output.WriteString(fmt.Sprintf("URL: %s\n", pair.Request.URL))

	if pair.Response != nil {
		output.WriteString(fmt.Sprintf("\nStatus: %s\n", pair.Response.Status))
		output.WriteString(fmt.Sprintf("Duration: %v\n", pair.Response.Duration))
		output.WriteString(fmt.Sprintf("Content-Type: %s\n", pair.Response.ContentType))
		output.WriteString(fmt.Sprintf("Body Length: %d bytes\n", len(pair.Response.Body)))

		// Show truncated body
		body := pair.Response.Body
		if len(body) > 2000 {
			body = body[:2000] + "\n... (truncated)"
		}
		output.WriteString(fmt.Sprintf("\nResponse Body:\n%s\n", body))
	}

	if pair.Error != "" {
		output.WriteString(fmt.Sprintf("\nError: %s\n", pair.Error))
	}

	return output.String()
}

// formatDetailedResponse formats a detailed response for output
func (m *ProxyManager) formatDetailedResponse(pair *RequestResponsePair, showHeaders, showBody bool) string {
	var output bytes.Buffer

	output.WriteString("=== REQUEST ===\n")
	output.WriteString(fmt.Sprintf("%s %s\n", pair.Request.Method, pair.Request.URL))

	if showHeaders {
		output.WriteString("\nHeaders:\n")
		for k, v := range pair.Request.Headers {
			output.WriteString(fmt.Sprintf("  %s: %s\n", k, strings.Join(v, ", ")))
		}
	}

	if showBody && pair.Request.Body != "" {
		output.WriteString(fmt.Sprintf("\nBody:\n%s\n", pair.Request.Body))
	}

	if pair.Response != nil {
		output.WriteString("\n=== RESPONSE ===\n")
		output.WriteString(fmt.Sprintf("%s\n", pair.Response.Status))
		output.WriteString(fmt.Sprintf("Duration: %v\n", pair.Response.Duration))

		if showHeaders {
			output.WriteString("\nHeaders:\n")
			for k, v := range pair.Response.Headers {
				output.WriteString(fmt.Sprintf("  %s: %s\n", k, strings.Join(v, ", ")))
			}
		}

		if showBody && pair.Response.Body != "" {
			body := pair.Response.Body
			if len(body) > 5000 {
				body = body[:5000] + "\n... (truncated)"
			}
			output.WriteString(fmt.Sprintf("\nBody:\n%s\n", body))
		}
	}

	if pair.Error != "" {
		output.WriteString(fmt.Sprintf("\n=== ERROR ===\n%s\n", pair.Error))
	}

	return output.String()
}

// GetRequest returns a captured request by ID
func (m *ProxyManager) GetRequest(id string) (*RequestResponsePair, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	pair, ok := m.requests[id]
	return pair, ok
}

// ClearRequests clears all captured requests
func (m *ProxyManager) ClearRequests() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = make(map[string]*RequestResponsePair)
}

// BuildURL builds a URL from components
func BuildURL(scheme, host, path string, params url.Values) string {
	u := &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     path,
		RawQuery: params.Encode(),
	}
	return u.String()
}
