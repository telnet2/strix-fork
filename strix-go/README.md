# Strix-Go

AI-Powered Penetration Testing Tool - Go Implementation

This is a Go implementation of [Strix](https://github.com/usestrix/strix), powered by [cloudwego/eino](https://github.com/cloudwego/eino) LLM framework.

## Features

- **Multi-Provider LLM Support**: OpenAI, Claude, Ollama, DeepSeek, Gemini, Azure OpenAI, AWS Bedrock
- **Autonomous Security Testing**: AI-driven vulnerability discovery
- **Rich Tool Suite**:
  - Browser automation (Chromium-based)
  - Terminal/shell command execution
  - HTTP proxy for request interception
  - Python code execution
- **Multi-Agent Orchestration**: Spawn and coordinate specialized sub-agents
- **Interactive TUI**: Real-time terminal UI with vulnerability tracking
- **Docker Sandbox**: Isolated execution environment with security tools
- **Comprehensive Reporting**: JSON and Markdown vulnerability reports

## Architecture

```
strix-go/
├── cmd/strix/          # CLI entry point
├── internal/
│   ├── agent/          # Agent system with ReAct pattern
│   ├── config/         # Configuration management
│   ├── llm/            # LLM client with multi-provider support
│   ├── runtime/        # Docker runtime and sandbox
│   ├── schema/         # Core data types
│   ├── telemetry/      # Telemetry and reporting
│   ├── tools/          # Tool implementations
│   │   ├── browser/    # Browser automation
│   │   ├── terminal/   # Shell execution
│   │   ├── proxy/      # HTTP proxy
│   │   ├── python/     # Python execution
│   │   ├── registry/   # Tool registry
│   │   ├── executor/   # Tool executor
│   │   └── agentsgraph/# Multi-agent orchestration
│   └── tui/            # Terminal UI (bubbletea)
└── go.mod
```

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/strix-go.git
cd strix-go

# Build
go build -o strix ./cmd/strix

# Or install directly
go install ./cmd/strix
```

## Configuration

Set the following environment variables:

```bash
# Required: LLM Configuration
export STRIX_LLM="openai/gpt-4"  # Format: provider/model
export LLM_API_KEY="your-api-key"

# Optional: Custom API endpoint (for local models)
export LLM_API_BASE="http://localhost:11434"

# Optional: Perplexity for web search
export PERPLEXITY_API_KEY="your-perplexity-key"

# Optional: Docker image
export STRIX_DOCKER_IMAGE="ghcr.io/usestrix/strix-sandbox:0.1.10"
```

### Supported Providers

| Provider | STRIX_LLM Format | API Key Variable |
|----------|------------------|------------------|
| OpenAI | `openai/gpt-4` | `LLM_API_KEY` or `OPENAI_API_KEY` |
| Claude | `claude/claude-3-5-sonnet-20241022` | `LLM_API_KEY` or `ANTHROPIC_API_KEY` |
| Ollama | `ollama/llama3.2` | Not required |
| DeepSeek | `deepseek/deepseek-chat` | `LLM_API_KEY` |
| Gemini | `gemini/gemini-2.0-flash-exp` | `LLM_API_KEY` |
| Azure | `azure/gpt-4` | `LLM_API_KEY` + `LLM_API_BASE` |
| Bedrock | `bedrock/claude-3-sonnet` | AWS credentials |

## Usage

```bash
# Basic scan
strix --target https://example.com

# Multiple targets
strix -t https://app.example.com -t https://api.example.com

# With custom instructions
strix -t https://example.com -i "Focus on authentication vulnerabilities"

# Non-interactive mode (for CI/CD)
strix -t https://example.com -n

# Specify output directory
strix -t https://example.com -o ./reports

# List supported models
strix models

# List available tools
strix tools
```

## Example Output

```
   _____ _        _
  / ____| |      (_)
 | (___ | |_ _ __ ___  __
  \___ \| __| '__| \ \/ /
  ____) | |_| |  | |>  <
 |_____/ \__|_|  |_/_/\_\

  AI-Powered Penetration Testing
  Powered by cloudwego/eino

Configuration: Config{Provider: openai, Model: gpt-4, APIKey: ***, MaxIterations: 300}
Targets: [https://example.com]

Initializing LLM client...
Testing LLM connection...
LLM connection successful!
Initializing Docker runtime...
Docker runtime started!
Initializing tools...
Registered 26 tools

[Running scan...]

🔴 [critical] SQL Injection in Login Form
   The login form at /api/login is vulnerable to SQL injection...

==================================================
SCAN SUMMARY
==================================================
Scan ID: 20241213-143052
Duration: 15m30s
Status: completed

Vulnerabilities Found: 3
  - critical: 1
  - high: 2

Tool Calls: 45 (Success: 42, Failed: 3)
Agents Used: 2
Errors: 1
==================================================

Report saved to: ./strix-output
```

## Development

### Building

```bash
# Build for current platform
go build -o strix ./cmd/strix

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o strix-linux ./cmd/strix

# Build for macOS
GOOS=darwin GOARCH=amd64 go build -o strix-macos ./cmd/strix
```

### Testing

```bash
go test ./...
```

### Adding New Tools

1. Create a new package under `internal/tools/`
2. Implement the `registry.Tool` interface
3. Register tools in `cmd/strix/main.go`

Example:

```go
type MyTool struct {
    *registry.BaseTool
}

func NewMyTool() *MyTool {
    return &MyTool{
        BaseTool: registry.NewBaseTool(
            "my_tool",
            "Description of my tool",
            strixschema.ToolCategoryCustom,
            map[string]*schema.ParameterInfo{
                "param1": {Type: schema.String, Desc: "Parameter 1", Required: true},
            },
            func(ctx context.Context, args string) (string, error) {
                // Tool implementation
                return "result", nil
            },
        ),
    }
}
```

## Dependencies

- [cloudwego/eino](https://github.com/cloudwego/eino) - LLM application framework
- [charmbracelet/bubbletea](https://github.com/charmbracelet/bubbletea) - TUI framework
- [spf13/cobra](https://github.com/spf13/cobra) - CLI framework

## License

See the main Strix repository for license information.

## Acknowledgments

- Original [Strix](https://github.com/usestrix/strix) Python implementation
- [cloudwego/eino](https://github.com/cloudwego/eino) and [eino-ext](https://github.com/cloudwego/eino-ext) teams
