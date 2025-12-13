// Package browser provides browser automation tools
package browser

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

// BrowserConfig holds the configuration for the browser
type BrowserConfig struct {
	Headless        bool
	Timeout         time.Duration
	ProxyURL        string
	UserAgent       string
	ViewportWidth   int
	ViewportHeight  int
	IgnoreHTTPSErrors bool
	ExtraArgs       []string
}

// DefaultBrowserConfig returns the default browser configuration
func DefaultBrowserConfig() *BrowserConfig {
	return &BrowserConfig{
		Headless:        true,
		Timeout:         30 * time.Second,
		ViewportWidth:   1280,
		ViewportHeight:  720,
		IgnoreHTTPSErrors: true,
	}
}

// BrowserInstance represents a browser instance
type BrowserInstance struct {
	mu sync.RWMutex

	config     *BrowserConfig
	tabs       map[string]*Tab
	activeTab  string
	tabCounter int
	running    bool
}

// Tab represents a browser tab
type Tab struct {
	ID       string    `json:"id"`
	URL      string    `json:"url"`
	Title    string    `json:"title"`
	Content  string    `json:"content"`
	Elements []Element `json:"elements,omitempty"`
}

// Element represents a page element
type Element struct {
	Index       int               `json:"index"`
	Tag         string            `json:"tag"`
	Text        string            `json:"text,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	IsVisible   bool              `json:"is_visible"`
	IsClickable bool              `json:"is_clickable"`
}

// NewBrowserInstance creates a new browser instance
func NewBrowserInstance(config *BrowserConfig) *BrowserInstance {
	if config == nil {
		config = DefaultBrowserConfig()
	}

	return &BrowserInstance{
		config: config,
		tabs:   make(map[string]*Tab),
	}
}

// Launch launches the browser
func (b *BrowserInstance) Launch(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.running {
		return fmt.Errorf("browser already running")
	}

	// Create initial tab
	b.tabCounter++
	tabID := fmt.Sprintf("tab-%d", b.tabCounter)
	b.tabs[tabID] = &Tab{
		ID:    tabID,
		URL:   "about:blank",
		Title: "New Tab",
	}
	b.activeTab = tabID
	b.running = true

	return nil
}

// Close closes the browser
func (b *BrowserInstance) Close(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.running {
		return nil
	}

	b.tabs = make(map[string]*Tab)
	b.activeTab = ""
	b.running = false

	return nil
}

// GoTo navigates to a URL
func (b *BrowserInstance) GoTo(ctx context.Context, url string) (*Tab, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.running {
		return nil, fmt.Errorf("browser not running")
	}

	tab, ok := b.tabs[b.activeTab]
	if !ok {
		return nil, fmt.Errorf("no active tab")
	}

	tab.URL = url
	tab.Title = fmt.Sprintf("Page at %s", url)
	// In real implementation, this would load the page and parse elements

	return tab, nil
}

// Click clicks on an element
func (b *BrowserInstance) Click(ctx context.Context, elementIndex int) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.running {
		return fmt.Errorf("browser not running")
	}

	// In real implementation, this would click the element
	return nil
}

// Type types text into an element
func (b *BrowserInstance) Type(ctx context.Context, elementIndex int, text string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.running {
		return fmt.Errorf("browser not running")
	}

	// In real implementation, this would type into the element
	return nil
}

// GetActiveTab returns the active tab
func (b *BrowserInstance) GetActiveTab() (*Tab, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.running {
		return nil, fmt.Errorf("browser not running")
	}

	tab, ok := b.tabs[b.activeTab]
	if !ok {
		return nil, fmt.Errorf("no active tab")
	}

	return tab, nil
}

// ListTabs returns all tabs
func (b *BrowserInstance) ListTabs() []*Tab {
	b.mu.RLock()
	defer b.mu.RUnlock()

	tabs := make([]*Tab, 0, len(b.tabs))
	for _, tab := range b.tabs {
		tabs = append(tabs, tab)
	}
	return tabs
}

// NewTab creates a new tab
func (b *BrowserInstance) NewTab(ctx context.Context) (*Tab, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.running {
		return nil, fmt.Errorf("browser not running")
	}

	b.tabCounter++
	tabID := fmt.Sprintf("tab-%d", b.tabCounter)
	tab := &Tab{
		ID:    tabID,
		URL:   "about:blank",
		Title: "New Tab",
	}
	b.tabs[tabID] = tab
	b.activeTab = tabID

	return tab, nil
}

// SwitchTab switches to a tab
func (b *BrowserInstance) SwitchTab(ctx context.Context, tabID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.running {
		return fmt.Errorf("browser not running")
	}

	if _, ok := b.tabs[tabID]; !ok {
		return fmt.Errorf("tab %s not found", tabID)
	}

	b.activeTab = tabID
	return nil
}

// CloseTab closes a tab
func (b *BrowserInstance) CloseTab(ctx context.Context, tabID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.running {
		return fmt.Errorf("browser not running")
	}

	if _, ok := b.tabs[tabID]; !ok {
		return fmt.Errorf("tab %s not found", tabID)
	}

	delete(b.tabs, tabID)

	// If we closed the active tab, switch to another
	if b.activeTab == tabID {
		for id := range b.tabs {
			b.activeTab = id
			break
		}
		if len(b.tabs) == 0 {
			b.activeTab = ""
		}
	}

	return nil
}

// BrowserManager manages browser instances and provides tools
type BrowserManager struct {
	mu sync.RWMutex

	browser *BrowserInstance
	config  *BrowserConfig
}

// NewBrowserManager creates a new browser manager
func NewBrowserManager(config *BrowserConfig) *BrowserManager {
	return &BrowserManager{
		config: config,
	}
}

// GetTools returns all browser tools
func (m *BrowserManager) GetTools() []registry.Tool {
	return []registry.Tool{
		m.createLaunchTool(),
		m.createGoToTool(),
		m.createClickTool(),
		m.createTypeTool(),
		m.createScrollTool(),
		m.createNewTabTool(),
		m.createSwitchTabTool(),
		m.createCloseTabTool(),
		m.createListTabsTool(),
		m.createViewSourceTool(),
		m.createExecuteJSTool(),
		m.createWaitTool(),
		m.createCloseTool(),
	}
}

// createLaunchTool creates the browser launch tool
func (m *BrowserManager) createLaunchTool() registry.Tool {
	return registry.NewBaseTool(
		"browser_launch",
		"Launch a new browser instance. Must be called before using other browser tools.",
		strixschema.ToolCategoryBrowser,
		map[string]*schema.ParameterInfo{
			"headless": {
				Type: schema.Boolean,
				Desc: "Run browser in headless mode (default: true)",
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				Headless *bool `json:"headless"`
			}
			if args != "" {
				if err := json.Unmarshal([]byte(args), &params); err != nil {
					return "", err
				}
			}

			m.mu.Lock()
			defer m.mu.Unlock()

			config := m.config
			if config == nil {
				config = DefaultBrowserConfig()
			}
			if params.Headless != nil {
				config.Headless = *params.Headless
			}

			m.browser = NewBrowserInstance(config)
			if err := m.browser.Launch(ctx); err != nil {
				return "", err
			}

			return "Browser launched successfully", nil
		},
	)
}

// createGoToTool creates the goto tool
func (m *BrowserManager) createGoToTool() registry.Tool {
	return registry.NewBaseTool(
		"browser_goto",
		"Navigate to a URL in the current tab",
		strixschema.ToolCategoryBrowser,
		map[string]*schema.ParameterInfo{
			"url": {
				Type:     schema.String,
				Desc:     "The URL to navigate to",
				Required: true,
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			m.mu.RLock()
			browser := m.browser
			m.mu.RUnlock()

			if browser == nil {
				return "", fmt.Errorf("browser not launched")
			}

			tab, err := browser.GoTo(ctx, params.URL)
			if err != nil {
				return "", err
			}

			return fmt.Sprintf("Navigated to %s\nTitle: %s", tab.URL, tab.Title), nil
		},
	)
}

// createClickTool creates the click tool
func (m *BrowserManager) createClickTool() registry.Tool {
	return registry.NewBaseTool(
		"browser_click",
		"Click on an element by its index",
		strixschema.ToolCategoryBrowser,
		map[string]*schema.ParameterInfo{
			"element_index": {
				Type:     schema.Integer,
				Desc:     "The index of the element to click",
				Required: true,
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				ElementIndex int `json:"element_index"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			m.mu.RLock()
			browser := m.browser
			m.mu.RUnlock()

			if browser == nil {
				return "", fmt.Errorf("browser not launched")
			}

			if err := browser.Click(ctx, params.ElementIndex); err != nil {
				return "", err
			}

			return fmt.Sprintf("Clicked element at index %d", params.ElementIndex), nil
		},
	)
}

// createTypeTool creates the type tool
func (m *BrowserManager) createTypeTool() registry.Tool {
	return registry.NewBaseTool(
		"browser_type",
		"Type text into an input element",
		strixschema.ToolCategoryBrowser,
		map[string]*schema.ParameterInfo{
			"element_index": {
				Type:     schema.Integer,
				Desc:     "The index of the input element",
				Required: true,
			},
			"text": {
				Type:     schema.String,
				Desc:     "The text to type",
				Required: true,
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				ElementIndex int    `json:"element_index"`
				Text         string `json:"text"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			m.mu.RLock()
			browser := m.browser
			m.mu.RUnlock()

			if browser == nil {
				return "", fmt.Errorf("browser not launched")
			}

			if err := browser.Type(ctx, params.ElementIndex, params.Text); err != nil {
				return "", err
			}

			return fmt.Sprintf("Typed text into element at index %d", params.ElementIndex), nil
		},
	)
}

// createScrollTool creates the scroll tool
func (m *BrowserManager) createScrollTool() registry.Tool {
	return registry.NewBaseTool(
		"browser_scroll",
		"Scroll the page up or down",
		strixschema.ToolCategoryBrowser,
		map[string]*schema.ParameterInfo{
			"direction": {
				Type:     schema.String,
				Desc:     "Direction to scroll: 'up' or 'down'",
				Required: true,
				Enum:     []string{"up", "down"},
			},
			"amount": {
				Type: schema.Integer,
				Desc: "Amount to scroll in pixels (default: 500)",
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				Direction string `json:"direction"`
				Amount    int    `json:"amount"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			m.mu.RLock()
			browser := m.browser
			m.mu.RUnlock()

			if browser == nil {
				return "", fmt.Errorf("browser not launched")
			}

			amount := params.Amount
			if amount == 0 {
				amount = 500
			}

			return fmt.Sprintf("Scrolled %s by %d pixels", params.Direction, amount), nil
		},
	)
}

// createNewTabTool creates the new tab tool
func (m *BrowserManager) createNewTabTool() registry.Tool {
	return registry.NewBaseTool(
		"browser_new_tab",
		"Open a new browser tab",
		strixschema.ToolCategoryBrowser,
		map[string]*schema.ParameterInfo{},
		func(ctx context.Context, args string) (string, error) {
			m.mu.RLock()
			browser := m.browser
			m.mu.RUnlock()

			if browser == nil {
				return "", fmt.Errorf("browser not launched")
			}

			tab, err := browser.NewTab(ctx)
			if err != nil {
				return "", err
			}

			return fmt.Sprintf("Opened new tab: %s", tab.ID), nil
		},
	)
}

// createSwitchTabTool creates the switch tab tool
func (m *BrowserManager) createSwitchTabTool() registry.Tool {
	return registry.NewBaseTool(
		"browser_switch_tab",
		"Switch to a different browser tab",
		strixschema.ToolCategoryBrowser,
		map[string]*schema.ParameterInfo{
			"tab_id": {
				Type:     schema.String,
				Desc:     "The ID of the tab to switch to",
				Required: true,
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				TabID string `json:"tab_id"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			m.mu.RLock()
			browser := m.browser
			m.mu.RUnlock()

			if browser == nil {
				return "", fmt.Errorf("browser not launched")
			}

			if err := browser.SwitchTab(ctx, params.TabID); err != nil {
				return "", err
			}

			return fmt.Sprintf("Switched to tab: %s", params.TabID), nil
		},
	)
}

// createCloseTabTool creates the close tab tool
func (m *BrowserManager) createCloseTabTool() registry.Tool {
	return registry.NewBaseTool(
		"browser_close_tab",
		"Close a browser tab",
		strixschema.ToolCategoryBrowser,
		map[string]*schema.ParameterInfo{
			"tab_id": {
				Type: schema.String,
				Desc: "The ID of the tab to close (default: active tab)",
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				TabID string `json:"tab_id"`
			}
			if args != "" {
				if err := json.Unmarshal([]byte(args), &params); err != nil {
					return "", err
				}
			}

			m.mu.RLock()
			browser := m.browser
			m.mu.RUnlock()

			if browser == nil {
				return "", fmt.Errorf("browser not launched")
			}

			tabID := params.TabID
			if tabID == "" {
				tab, err := browser.GetActiveTab()
				if err != nil {
					return "", err
				}
				tabID = tab.ID
			}

			if err := browser.CloseTab(ctx, tabID); err != nil {
				return "", err
			}

			return fmt.Sprintf("Closed tab: %s", tabID), nil
		},
	)
}

// createListTabsTool creates the list tabs tool
func (m *BrowserManager) createListTabsTool() registry.Tool {
	return registry.NewBaseTool(
		"browser_list_tabs",
		"List all open browser tabs",
		strixschema.ToolCategoryBrowser,
		map[string]*schema.ParameterInfo{},
		func(ctx context.Context, args string) (string, error) {
			m.mu.RLock()
			browser := m.browser
			m.mu.RUnlock()

			if browser == nil {
				return "", fmt.Errorf("browser not launched")
			}

			tabs := browser.ListTabs()
			result, _ := json.MarshalIndent(tabs, "", "  ")
			return string(result), nil
		},
	)
}

// createViewSourceTool creates the view source tool
func (m *BrowserManager) createViewSourceTool() registry.Tool {
	return registry.NewBaseTool(
		"browser_view_source",
		"View the HTML source of the current page",
		strixschema.ToolCategoryBrowser,
		map[string]*schema.ParameterInfo{},
		func(ctx context.Context, args string) (string, error) {
			m.mu.RLock()
			browser := m.browser
			m.mu.RUnlock()

			if browser == nil {
				return "", fmt.Errorf("browser not launched")
			}

			tab, err := browser.GetActiveTab()
			if err != nil {
				return "", err
			}

			return fmt.Sprintf("Page source for %s:\n%s", tab.URL, tab.Content), nil
		},
	)
}

// createExecuteJSTool creates the execute JS tool
func (m *BrowserManager) createExecuteJSTool() registry.Tool {
	return registry.NewBaseTool(
		"browser_execute_js",
		"Execute JavaScript code in the current page",
		strixschema.ToolCategoryBrowser,
		map[string]*schema.ParameterInfo{
			"code": {
				Type:     schema.String,
				Desc:     "JavaScript code to execute",
				Required: true,
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			m.mu.RLock()
			browser := m.browser
			m.mu.RUnlock()

			if browser == nil {
				return "", fmt.Errorf("browser not launched")
			}

			// In real implementation, this would execute JS
			return fmt.Sprintf("Executed JavaScript: %s", params.Code), nil
		},
	)
}

// createWaitTool creates the wait tool
func (m *BrowserManager) createWaitTool() registry.Tool {
	return registry.NewBaseTool(
		"browser_wait",
		"Wait for a specified amount of time",
		strixschema.ToolCategoryBrowser,
		map[string]*schema.ParameterInfo{
			"seconds": {
				Type:     schema.Number,
				Desc:     "Number of seconds to wait",
				Required: true,
			},
		},
		func(ctx context.Context, args string) (string, error) {
			var params struct {
				Seconds float64 `json:"seconds"`
			}
			if err := json.Unmarshal([]byte(args), &params); err != nil {
				return "", err
			}

			duration := time.Duration(params.Seconds * float64(time.Second))
			select {
			case <-time.After(duration):
				return fmt.Sprintf("Waited for %.1f seconds", params.Seconds), nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		},
	)
}

// createCloseTool creates the browser close tool
func (m *BrowserManager) createCloseTool() registry.Tool {
	return registry.NewBaseTool(
		"browser_close",
		"Close the browser instance",
		strixschema.ToolCategoryBrowser,
		map[string]*schema.ParameterInfo{},
		func(ctx context.Context, args string) (string, error) {
			m.mu.Lock()
			defer m.mu.Unlock()

			if m.browser == nil {
				return "Browser already closed", nil
			}

			if err := m.browser.Close(ctx); err != nil {
				return "", err
			}

			m.browser = nil
			return "Browser closed", nil
		},
	)
}
