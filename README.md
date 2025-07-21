# gomcp

**A Go-based implementation of the Model Context Protocol (MCP).**  
This package provides a standardized way to connect Large Language Models (LLMs) with external tools and data sources, making it easy to register and manage Resources, Tools, and Prompts.  
It uses JSON-RPC 2.0 and supports both STDIO and HTTP(SSE) transports.

## Key Features

- **Resource**: Data sources exposed via URI
- **Tool**: Functions/actions invocable by an LLM
- **Prompt**: Templates for conversational messages
- **JSON-RPC 2.0**: A standardized RPC protocol
- **Transport**: Supports STDIO and HTTP(SSE)
- **Go**: High-performance concurrency via goroutines
- **Health Check**: `/health` endpoint for server status monitoring.

## Installation

```bash
go get github.com/hawoond/gomcp
```

## Usage Example

```go
package main

import (
    "log"
    "mcp/server"
)

func main() {
    // Initialize a new MCP server.
    // NewServer(name, version, enableAuth, apiKey, supportedVersions...)
    // enableAuth: Set to true to enable API key authentication.
    // apiKey: The API key to use if authentication is enabled.
    // supportedVersions: Optional. List of supported protocol versions. Defaults to ["2024-11-05"].
    srv := server.NewServer("MyApp", "1.0", false, "")

    // Add a tool
    srv.AddTool("add", "Adds two integers", func(a int, b int) int {
        return a + b
    }, nil, "a", "b") // Note: paramStruct and paramNames are now required for AddTool

    // Add a resource
    srv.AddResource("const://hello", "A constant greeting", func() string {
        return "Hello from MCP!"
    })

    // Add a prompt
    srv.AddPrompt("echoPrompt", "Echo the message", func(msg string) string {
        return "Echo: " + msg
    }, nil, "msg") // Note: paramStruct and paramNames are now required for AddPrompt

    // Run in STDIO mode
    log.Fatal(srv.RunStdio(os.Stdin, os.Stdout))
}
```



## Advanced Features

### Dynamic Registration/Unregistration (Placeholder)
`gomcp` supports dynamic registration and unregistration of Tools, Prompts, and Resources via JSON-RPC methods like `tools/register`, `tools/unregister`, `prompts/register`, `prompts/unregister`, `resources/register`, and `resources/unregister`. Note that the `*register` methods are currently placeholders and only log the request, as dynamic Go function registration at runtime is complex and potentially insecure.

### Middleware
You can add custom middleware to the HTTP request handling pipeline using `srv.AddMiddleware(middlewareFunc)`. Middleware functions are `func(next http.HandlerFunc) http.HandlerFunc` and are executed in the order they are added.

```go
package main

import (
	"log"
	"net/http"
	"mcp/server"
	"os"
)

func main() {
	srv := server.NewServer("MyApp", "1.0", false, "")

	// Example Middleware: Logging requests
	loggingMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Request: %s %s", r.Method, r.URL.Path)
			next.ServeHTTP(w, r)
		}
	}
	srv.AddMiddleware(loggingMiddleware)

	// Example Middleware: Adding a custom header
	headerMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Powered-By", "gomcp")
			next.ServeHTTP(w, r)
		}
	}
	srv.AddMiddleware(headerMiddleware)

	// Start HTTP server
	log.Fatal(srv.ListenAndServe(":8080"))
}
```

### Asynchronous Tool Execution
For long-running operations, tools can be called asynchronously. The `tools/call_async` method returns a `taskId` immediately, and the result can be polled later using `tools/get_result`.

**`tools/call_async` Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "async-call-1",
  "method": "tools/call_async",
  "params": {
    "name": "my_long_tool",
    "arguments": {
      "param1": "value1"
    }
  }
}
```

**`tools/call_async` Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "async-call-1",
  "result": {
    "taskId": "a-unique-task-id"
  }
}
```

**`tools/get_result` Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "get-result-1",
  "method": "tools/get_result",
  "params": {
    "taskId": "a-unique-task-id"
  }
}
```

**`tools/get_result` Response (Task Running):**
```json
{
  "jsonrpc": "2.0",
  "id": "get-result-1",
  "result": {
    "id": "a-unique-task-id",
    "status": "running"
  }
}
```

**`tools/get_result` Response (Task Completed):**
```json
{
  "jsonrpc": "2.0",
  "id": "get-result-1",
  "result": {
    "id": "a-unique-task-id",
    "status": "completed",
    "result": "tool_output_here"
  }
}
```

### Streaming Responses (SSE)
`gomcp` supports streaming responses for `tools/call_stream` and `prompts/get_stream` methods over HTTP using Server-Sent Events (SSE). This is useful for real-time data or LLM streaming outputs.

To receive streaming responses, the client must send an `Accept: text/event-stream` header with the request.

**Example `tools/call_stream` Request (HTTP):**
```
POST /mcp HTTP/1.1
Host: localhost:8080
Content-Type: application/json
Accept: text/event-stream

{
  "jsonrpc": "2.0",
  "id": "stream-call-1",
  "method": "tools/call_stream",
  "params": {
    "name": "my_streaming_tool",
    "arguments": {}
  }
}
```

**Example SSE Stream Response:**
```
data: {"jsonrpc":"2.0","id":"stream-call-1","result":"partial_output_1"}

data: {"jsonrpc":"2.0","id":"stream-call-1","result":"partial_output_2"}

...

data: {"jsonrpc":"2.0","id":"stream-call-1","result":"final_output"}

```

### Event System
`gomcp` provides an event system to notify clients of server-side events (e.g., task status changes). Clients connected via SSE (by sending `Accept: text/event-stream` header) will receive notifications as JSON-RPC `Request` objects with a `method` like `events/taskStatusChanged`.

**Example `events/taskStatusChanged` Notification:**
```json
{
  "jsonrpc": "2.0",
  "method": "events/taskStatusChanged",
  "params": {
    "id": "a-unique-task-id",
    "status": "running",
    "error": null,
    "result": null
  }
}
```

---

# gomcp(Korean Documentation)

**Go 언어로 구현된 Model Context Protocol(MCP) 패키지입니다.**  
대규모 언어 모델(LLM)과 외부 도구·데이터 소스를 표준화된 방식으로 연결하고, Resource · Tool · Prompt를 손쉽게 등록·관리할 수 있습니다.  
JSON-RPC 2.0을 기반으로 STDIO와 HTTP(SSE) 전송 방식을 모두 지원합니다.

## 주요 특징

- **Resource**: URI로 노출되는 데이터 소스
- **Tool**: LLM이 호출 가능한 함수/동작
- **Prompt**: 대화형 메시지 템플릿
- **JSON-RPC 2.0**: 표준화된 RPC 프로토콜
- **Transport**: STDIO 및 HTTP(SSE) 지원
- **Go 언어**: 아마 고루틴을 통한 동시성 처리로 높은 성능
- **헬스 체크**: 서버 상태 모니터링을 위한 `/health` 엔드포인트.

## 설치

```bash
go get github.com/hawoond/gomcp
```

## 사용 예시

## 확장 기능

### 동적 등록/해제 (플레이스홀더)
`gomcp`는 `tools/register`, `tools/unregister`, `prompts/register`, `prompts/unregister`, `resources/register`, `resources/unregister`와 같은 JSON-RPC 메서드를 통해 Tool, Prompt, Resource의 동적 등록 및 해제를 지원합니다. `*register` 메서드는 현재 플레이스홀더이며 요청만 로깅합니다. 런타임에 Go 함수를 동적으로 등록하는 것은 복잡하고 잠재적으로 안전하지 않기 때문입니다.

### 미들웨어
`srv.AddMiddleware(middlewareFunc)`를 사용하여 HTTP 요청 처리 파이프라인에 사용자 정의 미들웨어를 추가할 수 있습니다. 미들웨어 함수는 `func(next http.HandlerFunc) http.HandlerFunc` 형태이며, 추가된 순서대로 실행됩니다.

```go
package main

import (
	"log"
	"net/http"
	"mcp/server"
	"os"
)

func main() {
	srv := server.NewServer("MyApp", "1.0", false, "")

	// 예시 미들웨어: 요청 로깅
	loggingMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Request: %s %s", r.Method, r.URL.Path)
			next.ServeHTTP(w, r)
		}
	}
	srv.AddMiddleware(loggingMiddleware)

	// 예시 미들웨어: 사용자 정의 헤더 추가
	headerMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Powered-By", "gomcp")
			next.ServeHTTP(w, r)
		}
	}
	srv.AddMiddleware(headerMiddleware)

	// HTTP 서버 시작
	log.Fatal(srv.ListenAndServe(":8080"))
}
```

### 비동기 도구 실행
장시간 실행되는 작업을 위해 도구를 비동기적으로 호출할 수 있습니다. `tools/call_async` 메서드는 즉시 `taskId`를 반환하며, `tools/get_result`를 사용하여 나중에 결과를 폴링할 수 있습니다.

**`tools/call_async` 요청:**
```json
{
  "jsonrpc": "2.0",
  "id": "async-call-1",
  "method": "tools/call_async",
  "params": {
    "name": "my_long_tool",
    "arguments": {
      "param1": "value1"
    }
  }
}
```

**`tools/call_async` 응답:**
```json
{
  "jsonrpc": "2.0",
  "id": "async-call-1",
  "result": {
    "taskId": "a-unique-task-id"
  }
}
```

**`tools/get_result` 요청:**
```json
{
  "jsonrpc": "2.0",
  "id": "get-result-1",
  "method": "tools/get_result",
  "params": {
    "taskId": "a-unique-task-id"
  }
}
```

**`tools/get_result` 응답 (작업 실행 중):**
```json
{
  "jsonrpc": "2.0",
  "id": "get-result-1",
  "result": {
    "id": "a-unique-task-id",
    "status": "running"
  }
}
```

**`tools/get_result` 응답 (작업 완료):**
```json
{
  "jsonrpc": "2.0",
  "id": "get-result-1",
  "result": {
    "id": "a-unique-task-id",
    "status": "completed",
    "result": "tool_output_here"
  }
}
```

### 스트리밍 응답 (SSE)
`gomcp`는 Server-Sent Events (SSE)를 사용하여 HTTP를 통한 `tools/call_stream` 및 `prompts/get_stream` 메서드에 대한 스트리밍 응답을 지원합니다. 이는 실시간 데이터 또는 LLM 스트리밍 출력에 유용합니다.

스트리밍 응답을 받으려면 클라이언트는 `Accept: text/event-stream` 헤더를 요청과 함께 보내야 합니다.

**`tools/call_stream` 요청 예시 (HTTP):**
```
POST /mcp HTTP/1.1
Host: localhost:8080
Content-Type: application/json
Accept: text/event-stream

{
  "jsonrpc": "2.0",
  "id": "stream-call-1",
  "method": "tools/call_stream",
  "params": {
    "name": "my_streaming_tool",
    "arguments": {}
  }
}
```

**SSE 스트림 응답 예시:**
```
data: {"jsonrpc":"2.0","id":"stream-call-1","result":"partial_output_1"}

data: {"jsonrpc":"2.0","id":"stream-call-1","result":"partial_output_2"}

...

data: {"jsonrpc":"2.0","id":"stream-call-1","result":"final_output"}

```

### 이벤트 시스템
`gomcp`는 서버 측 이벤트(예: 작업 상태 변경)를 클라이언트에 알리기 위한 이벤트 시스템을 제공합니다. SSE를 통해 연결된 클라이언트(`Accept: text/event-stream` 헤더를 보냄)는 `events/taskStatusChanged`와 같은 `method`를 가진 JSON-RPC `Request` 객체로 알림을 받게 됩니다.

**`events/taskStatusChanged` 알림 예시:**
```json
{
  "jsonrpc": "2.0",
  "method": "events/taskStatusChanged",
  "params": {
    "id": "a-unique-task-id",
    "status": "running",
    "error": null,
    "result": null
  }
}
```
