// Package main provides the CLI entry point for Strix
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cloudwego/eino/schema"
	"github.com/spf13/cobra"
	"github.com/strix-go/internal/agent"
	"github.com/strix-go/internal/config"
	"github.com/strix-go/internal/llm"
	"github.com/strix-go/internal/runtime"
	strixschema "github.com/strix-go/internal/schema"
	"github.com/strix-go/internal/telemetry"
	"github.com/strix-go/internal/tools/agentsgraph"
	"github.com/strix-go/internal/tools/browser"
	"github.com/strix-go/internal/tools/executor"
	"github.com/strix-go/internal/tools/proxy"
	"github.com/strix-go/internal/tools/python"
	"github.com/strix-go/internal/tools/registry"
	"github.com/strix-go/internal/tools/terminal"
	"github.com/strix-go/internal/tui"
)

var (
	version = "0.1.0"

	// CLI flags
	targets         []string
	instruction     string
	instructionFile string
	outputDir       string
	verbose         bool
	nonInteractive  bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "strix",
		Short: "Strix - AI-Powered Penetration Testing",
		Long: `Strix is an AI-powered penetration testing tool that autonomously
discovers security vulnerabilities in your applications.

Powered by cloudwego/eino LLM framework.`,
		Version: version,
		RunE:    runScan,
	}

	// Flags
	rootCmd.Flags().StringArrayVarP(&targets, "target", "t", nil, "Target to scan (URL, domain, IP, or local path)")
	rootCmd.Flags().StringVarP(&instruction, "instruction", "i", "", "Custom instruction for the scan")
	rootCmd.Flags().StringVarP(&instructionFile, "instruction-file", "f", "", "File containing custom instructions")
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory for reports")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.Flags().BoolVarP(&nonInteractive, "non-interactive", "n", false, "Run in non-interactive mode")

	// Add subcommands
	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(modelsCmd())
	rootCmd.AddCommand(toolsCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	// Check for targets
	if len(targets) == 0 && len(args) > 0 {
		targets = args
	}

	if len(targets) == 0 {
		return fmt.Errorf("at least one target is required. Use --target or provide as argument")
	}

	// Load configuration
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	if verbose {
		cfg.Verbose = true
	}
	if outputDir != "" {
		cfg.OutputDir = outputDir
	}
	cfg.Interactive = !nonInteractive

	// Print banner
	printBanner()

	fmt.Printf("Configuration: %s\n", cfg)
	fmt.Printf("Targets: %v\n\n", targets)

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal, shutting down...")
		cancel()
	}()

	// Initialize components
	fmt.Println("Initializing LLM client...")
	llmClient, err := llm.NewClient(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize LLM client: %w", err)
	}
	defer llmClient.Close()

	// Test LLM connection
	fmt.Println("Testing LLM connection...")
	if err := llmClient.Test(ctx); err != nil {
		return fmt.Errorf("LLM connection test failed: %w", err)
	}
	fmt.Println("LLM connection successful!")

	// Initialize tool registry first (needed for local tool server)
	fmt.Println("Initializing tools...")
	reg := registry.NewRegistry()

	// Register all tools
	browserManager := browser.NewBrowserManager(nil)
	for _, tool := range browserManager.GetTools() {
		reg.Register(tool)
	}

	terminalManager := terminal.NewTerminalManager(nil)
	for _, tool := range terminalManager.GetTools() {
		reg.Register(tool)
	}

	proxyManager := proxy.NewProxyManager(nil)
	for _, tool := range proxyManager.GetTools() {
		reg.Register(tool)
	}

	pythonManager := python.NewPythonManager(nil)
	for _, tool := range pythonManager.GetTools() {
		reg.Register(tool)
	}

	agentsGraph := agentsgraph.NewAgentsGraph()
	graphManager := agentsgraph.NewAgentsGraphManager(agentsGraph)
	for _, tool := range graphManager.GetTools() {
		reg.Register(tool)
	}

	registerVulnerabilityTool(reg)
	fmt.Printf("Registered %d tools\n", reg.Count())

	// Initialize Docker runtime or local tool server
	var dockerRuntime *runtime.DockerRuntime
	var localToolServer *runtime.LocalToolServer

	if !cfg.UseLocalTools {
		fmt.Println("Initializing Docker runtime...")
		dockerConfig := runtime.DefaultDockerConfig()
		dockerConfig.Image = cfg.DockerImage
		dockerRuntime = runtime.NewDockerRuntime(dockerConfig)

		if err := dockerRuntime.Start(ctx); err != nil {
			fmt.Printf("Warning: Failed to start Docker runtime: %v\n", err)
			fmt.Println("Starting local tool server instead...")
			cfg.UseLocalTools = true
		} else {
			defer dockerRuntime.Close()
			fmt.Println("Docker runtime started!")
		}
	}

	// Start local tool server if needed
	if cfg.UseLocalTools {
		fmt.Println("Starting local tool server...")
		localToolServer = runtime.NewLocalToolServer(8000, reg)
		if err := localToolServer.Start(ctx); err != nil {
			fmt.Printf("Warning: Failed to start local tool server: %v\n", err)
		} else {
			defer localToolServer.Stop(ctx)
			fmt.Printf("Local tool server running at %s\n", localToolServer.GetURL())
		}
	}

	// Initialize executor
	execConfig := executor.DefaultExecutorConfig()
	exec := executor.NewExecutor(execConfig, reg)

	// Set sandbox client if Docker is running
	if !cfg.UseLocalTools && dockerRuntime.IsRunning() {
		sandboxClient := runtime.NewSandboxClient(dockerRuntime)
		exec.SetSandboxClient(sandboxClient)
	}

	// Initialize telemetry
	scanID := time.Now().Format("20060102-150405")
	tracer := telemetry.NewScanTracer(scanID, cfg.OutputDir)

	// Parse targets
	scanTargets := make([]*strixschema.Target, 0)
	for _, t := range targets {
		target := parseTarget(t)
		scanTargets = append(scanTargets, target)
		tracer.AddTarget(target)
	}

	// Build initial message
	initialMessage := buildInitialMessage(scanTargets, instruction)

	// Create the main agent
	strixAgent, err := agent.NewStrixAgent(cfg, llmClient, reg, exec, scanTargets[0])
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	// Setup TUI or CLI callbacks
	if cfg.Interactive {
		tuiProgram := tui.NewProgram()

		// Set callbacks
		strixAgent.SetCallbacks(
			func(msg *schema.Message) { tuiProgram.SendAgentMessage(msg) },
			func(tc schema.ToolCall) { tuiProgram.SendToolCall(tc) },
			func(result *strixschema.ToolResult) { tuiProgram.SendToolResult(result) },
			func(vuln *strixschema.VulnerabilityReport) {
				tracer.AddVulnerability(vuln)
				tuiProgram.SendVulnerability(vuln)
			},
			func(status strixschema.AgentStatus) { tuiProgram.SendStatusChange(status) },
			func(err error) {
				tracer.AddError(strixAgent.GetID(), err)
				tuiProgram.SendError(err)
			},
		)

		// Run TUI in background
		go func() {
			if err := tuiProgram.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
			}
		}()

		// Run agent
		if err := strixAgent.Run(ctx, initialMessage); err != nil {
			tuiProgram.Quit()
			return err
		}

		tuiProgram.Quit()
	} else {
		// Non-interactive mode with CLI output
		strixAgent.SetCallbacks(
			func(msg *schema.Message) {
				if msg.Content != "" {
					fmt.Printf("[%s] %s\n", msg.Role, truncate(msg.Content, 200))
				}
			},
			func(tc schema.ToolCall) {
				fmt.Printf("  → Calling tool: %s\n", tc.Function.Name)
			},
			func(result *strixschema.ToolResult) {
				if result.Success {
					fmt.Printf("  ✓ %s completed\n", result.Name)
				} else {
					fmt.Printf("  ✗ %s failed: %s\n", result.Name, result.Error)
				}
			},
			func(vuln *strixschema.VulnerabilityReport) {
				tracer.AddVulnerability(vuln)
				fmt.Printf("\n🔴 [%s] %s\n   %s\n\n", vuln.Severity, vuln.Title, vuln.Description)
			},
			func(status strixschema.AgentStatus) {
				fmt.Printf("Agent status: %s\n", status)
			},
			func(err error) {
				tracer.AddError(strixAgent.GetID(), err)
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			},
		)

		// Run agent
		if err := strixAgent.Run(ctx, initialMessage); err != nil {
			fmt.Fprintf(os.Stderr, "Agent error: %v\n", err)
		}
	}

	// Complete scan and save report
	tracer.Complete("completed")
	if err := tracer.SaveReport(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save report: %v\n", err)
	} else {
		fmt.Printf("\nReport saved to: %s\n", cfg.OutputDir)
	}

	// Print summary
	report := tracer.GetReport()
	printSummary(report)

	// Return exit code based on findings
	if report.Summary.TotalVulnerabilities > 0 {
		// Exit with code 1 if vulnerabilities found (useful for CI/CD)
		os.Exit(1)
	}

	return nil
}

func printBanner() {
	banner := `
   _____ _        _
  / ____| |      (_)
 | (___ | |_ _ __ ___  __
  \___ \| __| '__| \ \/ /
  ____) | |_| |  | |>  <
 |_____/ \__|_|  |_/_/\_\

  AI-Powered Penetration Testing
  Powered by cloudwego/eino
`
	fmt.Println(banner)
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Strix version %s\n", version)
			fmt.Println("Powered by cloudwego/eino")
		},
	}
}

func modelsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "models",
		Short: "List supported LLM models",
		Run: func(cmd *cobra.Command, args []string) {
			providers := llm.GetSupportedProviders()
			fmt.Println("Supported LLM Providers and Models:\n")
			for _, p := range providers {
				fmt.Printf("%s (%s):\n", p.DisplayName, p.Name)
				for _, m := range p.Models {
					fmt.Printf("  - %s\n", m)
				}
				fmt.Printf("  Features: %v\n\n", p.Features)
			}
		},
	}
}

func toolsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tools",
		Short: "List available tools",
		Run: func(cmd *cobra.Command, args []string) {
			reg := registry.NewRegistry()

			// Register all tools
			browserManager := browser.NewBrowserManager(nil)
			for _, tool := range browserManager.GetTools() {
				reg.Register(tool)
			}

			terminalManager := terminal.NewTerminalManager(nil)
			for _, tool := range terminalManager.GetTools() {
				reg.Register(tool)
			}

			proxyManager := proxy.NewProxyManager(nil)
			for _, tool := range proxyManager.GetTools() {
				reg.Register(tool)
			}

			pythonManager := python.NewPythonManager(nil)
			for _, tool := range pythonManager.GetTools() {
				reg.Register(tool)
			}

			graphManager := agentsgraph.NewAgentsGraphManager(agentsgraph.NewAgentsGraph())
			for _, tool := range graphManager.GetTools() {
				reg.Register(tool)
			}

			fmt.Printf("Available Tools (%d):\n\n", reg.Count())

			tools := reg.GetAll()
			categories := make(map[strixschema.ToolCategory][]registry.Tool)
			for _, t := range tools {
				categories[t.Category()] = append(categories[t.Category()], t)
			}

			for cat, catTools := range categories {
				fmt.Printf("[%s]\n", cat)
				for _, t := range catTools {
					fmt.Printf("  - %s\n", t.Name())
				}
				fmt.Println()
			}
		},
	}
}

func parseTarget(target string) *strixschema.Target {
	t := &strixschema.Target{
		Value: target,
	}

	// Infer target type
	switch {
	case isURL(target):
		t.Type = "url"
	case isDomain(target):
		t.Type = "domain"
	case isIP(target):
		t.Type = "ip"
	case isPath(target):
		t.Type = "local"
	default:
		t.Type = "url"
	}

	return t
}

func isURL(s string) bool {
	return len(s) > 4 && (s[:4] == "http" || s[:5] == "https")
}

func isDomain(s string) bool {
	return !isURL(s) && !isIP(s) && !isPath(s) && len(s) > 0
}

func isIP(s string) bool {
	// Simple check for IP-like strings
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func isPath(s string) bool {
	_, err := os.Stat(s)
	return err == nil
}

func buildInitialMessage(targets []*strixschema.Target, instruction string) string {
	var msg string

	msg = fmt.Sprintf("Please perform a security assessment on the following targets:\n\n")
	for _, t := range targets {
		msg += fmt.Sprintf("- %s (%s)\n", t.Value, t.Type)
	}

	if instruction != "" {
		msg += fmt.Sprintf("\nAdditional instructions:\n%s\n", instruction)
	}

	msg += "\nStart by performing reconnaissance to understand the attack surface, then systematically test for vulnerabilities."

	return msg
}

func registerVulnerabilityTool(reg *registry.Registry) {
	tool := registry.NewBaseTool(
		"create_vulnerability_report",
		"Create a vulnerability report for a discovered security issue. Use this when you have validated a vulnerability with a proof of concept.",
		strixschema.ToolCategoryReporting,
		map[string]*schema.ParameterInfo{
			"title": {
				Type:     schema.String,
				Desc:     "Title of the vulnerability",
				Required: true,
			},
			"description": {
				Type:     schema.String,
				Desc:     "Detailed description of the vulnerability",
				Required: true,
			},
			"severity": {
				Type:     schema.String,
				Desc:     "Severity level: critical, high, medium, low, info",
				Required: true,
				Enum:     []string{"critical", "high", "medium", "low", "info"},
			},
			"category": {
				Type:     schema.String,
				Desc:     "Vulnerability category (e.g., XSS, SQLi, IDOR)",
				Required: true,
			},
			"affected_asset": {
				Type:     schema.String,
				Desc:     "The affected URL, endpoint, or component",
				Required: true,
			},
			"proof_of_concept": {
				Type:     schema.String,
				Desc:     "Steps or code to reproduce the vulnerability",
				Required: true,
			},
			"remediation": {
				Type: schema.String,
				Desc: "Recommended fix for the vulnerability",
			},
		},
		func(ctx context.Context, args string) (string, error) {
			// This is handled by the agent's callback
			return "Vulnerability report created successfully", nil
		},
	)

	reg.Register(tool)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func printSummary(report *telemetry.ScanReport) {
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("SCAN SUMMARY")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Scan ID: %s\n", report.ScanID)
	fmt.Printf("Duration: %s\n", report.Duration)
	fmt.Printf("Status: %s\n\n", report.Status)

	fmt.Printf("Vulnerabilities Found: %d\n", report.Summary.TotalVulnerabilities)
	for sev, count := range report.Summary.BySeverity {
		fmt.Printf("  - %s: %d\n", sev, count)
	}

	fmt.Printf("\nTool Calls: %d (Success: %d, Failed: %d)\n",
		report.Summary.TotalToolCalls, report.Summary.SuccessfulCalls, report.Summary.FailedCalls)
	fmt.Printf("Agents Used: %d\n", report.Summary.TotalAgents)
	fmt.Printf("Errors: %d\n", report.Summary.TotalErrors)
	fmt.Println(strings.Repeat("=", 50))
}
