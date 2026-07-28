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

# gomcp 한국어 문서

`gomcp`는 stdio와 Streamable HTTP 전송 방식을 지원하는 Go 기반 Model
Context Protocol(MCP) 서버·클라이언트 라이브러리입니다.

기본 프로토콜 버전은 `2025-11-25`이며 `2025-06-18`, `2025-03-26`,
`2024-11-05` 클라이언트와의 버전 협상도 지원합니다.

## 주요 기능

- Tool, Resource, Prompt 및 task 기반 Tool 호출
- JSON Schema를 자동 생성하는 타입 기반 Tool 등록
- stdio를 통한 줄 단위 JSON-RPC 통신
- 세션, 프로토콜 헤더, 알림 및 종료 처리를 포함한 Streamable HTTP
- 요청, 응답, 명령 및 외부 HTTP 호출의 크기·시간 제한
- Origin 검증과 선택적 API 키 인증
- 명령 및 HTTP 호스트 허용 목록을 사용하는 로컬 동적 정의
- 애플리케이션 핸들러 panic 복구
- 서버 상태 확인을 위한 `/health` 엔드포인트

## 설치

```bash
go get github.com/hawoond/gomcp
```

## 서버

타입 기반 Tool은 입력·출력 구조체에서 JSON Schema를 생성합니다.

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
		"두 정수를 더합니다",
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

HTTP 서버는 다음과 같이 실행합니다.

```go
ctx := context.Background()
err := mcpServer.ListenAndServeContext(ctx, "127.0.0.1:8080")
```

기존 HTTP 서버에 통합하려면 `Server.Handler()`를 사용할 수 있습니다.
`Server.AddMiddleware()`를 사용하면 HTTP 요청 처리 과정에 사용자 정의
미들웨어를 추가할 수 있습니다.

## 클라이언트

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

클라이언트는 첫 작업을 실행하기 전에 MCP 세션을 자동으로 초기화합니다.
명시적으로 초기화해야 하는 경우 `Initialize` 또는 `InitializeContext`를
사용할 수 있습니다.

## 작업

장시간 실행되는 Tool은 `RegisterTaskTool`로 등록합니다. 클라이언트는
다음 표준 메서드로 작업을 생성·조회·수신·목록화·취소할 수 있습니다.

- `task` 매개변수를 포함한 `tools/call`
- `tasks/get`
- `tasks/result`
- `tasks/list`
- `tasks/cancel`

완료된 작업은 서버의 task 정책에 설정된 보존 기간이 지나면 제거됩니다.
작업 상태 변경은 `notifications/tasks/status` 알림으로 전달됩니다.

## 동적 정의

동적 Tool과 Prompt는 다음 로컬 Go API로 등록합니다.

- `AddDynamicTool`
- `AddDynamicPrompt`
- `AllowCommand`
- `AllowHTTPHost`

프로토콜을 통한 등록·해제 메서드는 기본적으로 비활성화됩니다. 통제된
호환 환경에서만 `EnableExperimentalMethods(true)`로 활성화해야 합니다.
Resource를 원격으로 변경하는 기능은 지원하지 않습니다.

외부 HTTP 정의는 정확한 호스트 허용 목록이 필요하며 공개 주소가 아닌
대상은 거부합니다. 명령 정의는 실행 파일 허용 목록이 필요합니다.

## 스트리밍과 알림

Streamable HTTP 클라이언트는 `Accept: text/event-stream`을 사용해 서버
알림을 수신할 수 있습니다. 서버는 `PublishNotification`으로 알림을
전송하며 연결 종료와 요청 취소를 함께 처리합니다.

기존 `tools/call_stream`, `prompts/get_stream` 메서드는 호환성을 위한
실험 기능입니다. 필요한 경우에만 `EnableExperimentalMethods(true)`로
활성화하고, 일반적인 작업 상태 전달에는 표준 task 메서드와 알림을
사용하는 것이 좋습니다.

## 보안

HTTP 모드는 기본적으로 loopback 주소에 바인딩해야 합니다. 외부에
노출해야 한다면 인증과 TLS가 적용된 reverse proxy 뒤에 배치하십시오.
내장 API 키 인증을 사용하는 클라이언트는 `SetAPIKey`로 키를 설정합니다.

동적 명령과 외부 HTTP 호출에는 반드시 허용 목록을 설정하십시오. 서버는
요청·응답 크기, 실행 시간, 비공개 네트워크 접근 및 redirect를 제한합니다.

취약점 제보 절차와 운영 권장 사항은 [SECURITY.md](SECURITY.md)를
참고하십시오.

## 호환성 변경

강화된 API는 다음 MCP 표준 결과 구조를 반환합니다.

- `tools/call`: `CallToolResult`
- `resources/read`: `ReadResourceResult`
- `prompts/get`: `GetPromptResult`

기존 `tools/call_async`, `tools/get_result`와 사용자 정의 스트리밍 메서드는
실험 모드에서만 사용할 수 있습니다. 신규 구현은 표준 task 메서드를
사용해야 합니다.

## 개발 및 검증

```bash
go test ./...
go test -race ./...
go vet ./...
```

## License

MIT
