# gomcp

`gomcp` is a Go implementation of the Model Context Protocol (MCP) for building
servers and clients over stdio and Streamable HTTP.

The current API targets protocol version `2025-11-25` while retaining version
negotiation for `2025-06-18`, `2025-03-26`, and `2024-11-05`.

## Features

- Tools, resources, prompts, and task-augmented tool calls
- Typed tool registration with generated JSON Schema
- Newline-delimited JSON-RPC over stdio
- Streamable HTTP with sessions, protocol headers, notifications, and shutdown
- Request, response, command, and HTTP time limits
- Origin validation and optional API-key authentication
- Local-only dynamic definitions with command and HTTP host allowlists
- Panic recovery around application handlers

## Install

```bash
go get github.com/hawoond/gomcp
```

## Server

```go
package main

import (
	"context"
	"log"
	"os"

	"github.com/hawoond/gomcp/server"
)

type addInput struct {
	A int `json:"a"`
	B int `json:"b"`
}

type addOutput struct {
	Result int `json:"result"`
}

func main() {
	mcpServer := server.NewServer("calculator", "0.1.0", false, "")
	err := server.RegisterTool(
		mcpServer,
		"add",
		"Add two integers",
		func(_ context.Context, input addInput) (addOutput, error) {
			return addOutput{Result: input.A + input.B}, nil
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := mcpServer.RunStdio(os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}
```

For HTTP:

```go
ctx := context.Background()
err := mcpServer.ListenAndServeContext(ctx, "127.0.0.1:8080")
```

`Server.Handler()` can be mounted in an existing HTTP server.

## Client

```go
mcpClient := client.NewClient()
mcpClient.ConnectHTTP("http://127.0.0.1:8080")

var result protocol.CallToolResult
err := mcpClient.Call("tools/call", map[string]interface{}{
	"name": "add",
	"arguments": map[string]interface{}{
		"a": 2,
		"b": 3,
	},
}, &result)
```

The client initializes the MCP session before the first operation. Explicit
initialization is also available through `Initialize` and `InitializeContext`.

## Tasks

Use `RegisterTaskTool` for handlers that support task-augmented execution.
Clients can create, inspect, retrieve, list, and cancel tasks through:

- `tools/call` with a `task` parameter
- `tasks/get`
- `tasks/result`
- `tasks/list`
- `tasks/cancel`

Completed tasks expire according to the server task policy.

## Dynamic definitions

Dynamic command and HTTP definitions are registered through the local Go API:

- `AddDynamicTool`
- `AddDynamicPrompt`
- `AllowCommand`
- `AllowHTTPHost`

Protocol-level register and unregister methods are disabled by default. Enable
them only for controlled compatibility environments with
`EnableExperimentalMethods(true)`. Remote resource mutation is not supported.

Outbound HTTP definitions require an exact host allowlist and reject non-public
addresses. Command definitions require an executable allowlist.

## Security

HTTP mode should bind to loopback unless it is placed behind an authenticated
TLS reverse proxy. When the built-in API key is enabled, clients configure it
with `SetAPIKey`.

See [SECURITY.md](SECURITY.md) for the supported reporting process and
operational recommendations.

## Compatibility changes

The hardened API returns standard MCP result envelopes:

- `tools/call` returns `CallToolResult`
- `resources/read` returns `ReadResourceResult`
- `prompts/get` returns `GetPromptResult`

Legacy `tools/call_async`, `tools/get_result`, and custom streaming methods are
available only in experimental mode. Standard task methods should be preferred.

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
```

## 한국어 요약

`gomcp`는 stdio와 Streamable HTTP를 지원하는 Go MCP 서버·클라이언트
라이브러리입니다. 기본 프로토콜은 `2025-11-25`이며 typed tool, 표준
tool/resource/prompt 결과, task lifecycle, 세션, Origin 검증, 크기·시간
제한을 제공합니다.

원격 command·HTTP 정의는 기본적으로 비활성화됩니다. 필요한 경우에도
로컬 API로 등록한 뒤 실행 파일과 HTTP host를 명시적으로 허용해야 합니다.

## License

MIT
