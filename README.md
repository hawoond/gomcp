# gomcp

`gomcp` is a Go implementation of the Model Context Protocol (MCP) for building
servers and clients over stdio and Streamable HTTP.

The current API targets protocol version `2025-11-25` while retaining version
negotiation for `2025-06-18`, `2025-03-26`, and `2024-11-05`.

## Features

- Tools, resources, prompts, and task-augmented tool calls
- Paginated discovery, resource templates, subscriptions, and completions
- Typed tool registration with generated input/output JSON Schema and validation
- Concurrent newline-delimited JSON-RPC and server requests over stdio
- Typed roots, sampling, elicitation, and logging hooks
- Isolated Streamable HTTP sessions with event replay and stateless mode
- Request, response, command, and HTTP time limits
- Origin validation, bearer-token verification, OAuth metadata, and API keys
- Optional dynamic execution package with command and HTTP host allowlists
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
Discovery helpers follow `nextCursor` automatically. `HandleRequests` handles
server-to-client stdio requests, and `HandleElicitation` provides a typed
elicitation callback. `HandleRoots` and `HandleSampling` expose the remaining
client-side request capabilities.

## HTTP sessions and authentication

Stateful HTTP sessions keep subscriptions, task ownership, and notification
queues separate. Bounded event history is replayed when a client reconnects
with `Last-Event-ID`. Configure retention with `SetSessionPolicy`, or use
`SetStatelessHTTP(true)` when server-to-client notifications are unnecessary.

Bearer authentication accepts an application-defined `auth.TokenVerifier`.
`SetProtectedResourceMetadata` exposes discovery metadata at
`/.well-known/oauth-protected-resource`. The API-key mode remains available for
closed compatibility deployments.

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

Protocol-level register and unregister methods use the `x-gomcp/` namespace and
are disabled by default. Legacy unnamespaced aliases remain temporarily
available. Enable them only for controlled compatibility environments with
`EnableExperimentalMethods(true)`. Remote resource mutation is not supported.

Outbound HTTP definitions require an exact host allowlist and reject non-public
addresses. Command definitions require an executable allowlist. Their runtime
implementation lives in the optional `executor` package rather than the core
protocol types.

## Security

HTTP mode should bind to loopback unless it is placed behind an authenticated
TLS reverse proxy. Bearer-token clients use `SetBearerToken` or a refreshable
`SetTokenSource`. When the built-in API key is enabled, clients use `SetAPIKey`.

See [SECURITY.md](SECURITY.md) for the supported reporting process and
operational recommendations.

## Compatibility changes

The hardened API returns standard MCP result envelopes:

- `tools/call` returns `CallToolResult`
- `resources/read` returns `ReadResourceResult`
- `prompts/get` returns `GetPromptResult`

The stable contract includes initialize, ping, tools, fixed resources, resource
templates and subscriptions, prompts, completion, cancellation, progress, and
logging. Client-side roots, sampling, and elicitation requests are available on
stdio. Task methods remain available as an isolated extension of the stable
base contract.

Legacy `tools/call_async`, `tools/get_result`, and custom streaming methods are
available only in experimental mode. Standard task methods should be preferred.
`2026-07-28` is exposed as an explicit opt-in protocol constant while the
default remains the published stable `2025-11-25` contract.

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
- 페이지네이션 목록, Resource template·구독 및 자동 완성
- 입력·출력 JSON Schema를 생성하고 검증하는 타입 기반 Tool 등록
- 다중 요청과 서버 요청을 동시에 처리하는 stdio JSON-RPC
- Roots, sampling, elicitation 및 logging 타입 기반 hook
- 이벤트 재전송과 stateless 모드를 지원하는 세션 격리 Streamable HTTP
- 요청, 응답, 명령 및 외부 HTTP 호출의 크기·시간 제한
- Origin 검증, Bearer token 검증, OAuth metadata 및 API 키 인증
- 명령 및 HTTP 호스트 허용 목록을 사용하는 선택적 동적 실행기
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
목록 조회 API는 `nextCursor`를 자동으로 따라갑니다. stdio 서버 요청은
`HandleRequests`로 처리하며 elicitation은 `HandleElicitation`에서 타입
기반으로 처리할 수 있습니다. `HandleRoots`와 `HandleSampling`은 나머지
클라이언트 요청 capability를 제공합니다.

## HTTP 세션과 인증

Stateful HTTP 세션은 구독, task 소유권 및 알림 큐를 세션마다 분리합니다.
클라이언트가 `Last-Event-ID`로 다시 연결하면 제한된 이벤트 이력을
재전송합니다. 보존 정책은 `SetSessionPolicy`로 설정하며 서버 알림이
필요하지 않은 환경은 `SetStatelessHTTP(true)`를 사용할 수 있습니다.

Bearer 인증은 애플리케이션이 제공한 `auth.TokenVerifier`로 검증합니다.
`SetProtectedResourceMetadata`를 설정하면
`/.well-known/oauth-protected-resource`에서 discovery metadata를
제공합니다. 클라이언트는 `SetBearerToken` 또는 갱신 가능한
`SetTokenSource`를 사용합니다.

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

프로토콜을 통한 등록·해제 메서드는 `x-gomcp/` namespace를 사용하며
기본적으로 비활성화됩니다. 기존 namespace 없는 이름은 전환을 위해
임시로 유지됩니다. 통제된 호환 환경에서만
`EnableExperimentalMethods(true)`로 활성화해야 합니다. Resource를
원격으로 변경하는 기능은 지원하지 않습니다.

외부 HTTP 정의는 정확한 호스트 허용 목록이 필요하며 공개 주소가 아닌
대상은 거부합니다. 명령 정의는 실행 파일 허용 목록이 필요합니다. 실행
기능은 핵심 프로토콜 타입과 분리된 `executor` 패키지에 있습니다.

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

Stable 계약은 initialize, ping, Tool, 고정 Resource, Resource template·구독,
Prompt, completion, cancellation, progress 및 logging을 포함합니다. stdio
클라이언트는 roots, sampling, elicitation 서버 요청을 처리할 수 있습니다.
Task 메서드는 stable 기본 계약과 격리된 확장 기능으로 유지합니다.

기존 `tools/call_async`, `tools/get_result`와 사용자 정의 스트리밍 메서드는
실험 모드에서만 사용할 수 있습니다. 신규 구현은 표준 task 메서드를
사용해야 합니다.
`2026-07-28` 상수는 명시적 opt-in 용도로만 제공하며 기본 계약은 공개
stable 버전인 `2025-11-25`로 유지합니다.

## 개발 및 검증

```bash
go test ./...
go test -race ./...
go vet ./...
```

## License

MIT
