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
    srv := server.NewServer("MyApp", "1.0")

    // Add a tool
    srv.AddTool("add", "Adds two integers", func(a int, b int) int {
        return a + b
    })

    // Add a resource
    srv.AddResource("const://hello", "A constant greeting", func() string {
        return "Hello from MCP!"
    })

    // Add a prompt
    srv.AddPrompt("echoPrompt", "Echo the message", func(msg string) string {
        return "Echo: " + msg
    })

    // Run in STDIO mode
    log.Fatal(srv.RunStdio())
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

## 설치

```bash
go get github.com/hawoond/gomcp
```

## 사용 예시

```go
package main

import (
    "log"
    "mcp/server"
)

func main() {
    srv := server.NewServer("MyApp", "1.0")

    // Tool 등록
    srv.AddTool("add", "Adds two integers", func(a int, b int) int {
        return a + b
    })

    // Resource 등록
    srv.AddResource("const://hello", "A constant greeting", func() string {
        return "Hello from MCP!"
    })

    // Prompt 등록
    srv.AddPrompt("echoPrompt", "Echo the message", func(msg string) string {
        return "Echo: " + msg
    })

    // STDIO 모드 실행
    log.Fatal(srv.RunStdio())
}

```
