## `gomcp` 프로젝트 상세 분석

`gomcp`는 Go 언어로 구현된 Model Context Protocol (MCP) 패키지로, 대규모 언어 모델(LLM)과 외부 도구 및 데이터 소스를 표준화된 방식으로 연결하는 것을 목표로 합니다. JSON-RPC 2.0을 기반으로 하며, STDIO 및 HTTP(SSE) 전송 방식을 모두 지원합니다.

### 1. 주요 기능

`gomcp`는 LLM이 외부 세계와 상호작용할 수 있도록 세 가지 핵심 개념을 중심으로 설계되었습니다.

*   **Resource (리소스):** URI를 통해 노출되는 데이터 소스입니다.
    *   `server.AddResource(uriTemplate, description, handler)`를 통해 등록됩니다.
    *   `resources/read` JSON-RPC 메서드를 통해 URI 템플릿에 일치하는 데이터를 읽을 수 있습니다.
    *   URI 템플릿에 `{}`와 같은 플레이스홀더를 사용하여 동적인 데이터를 처리할 수 있습니다. (예: `greeting://{name}`에서 `name` 추출)
*   **Tool (도구):** LLM이 호출 가능한 함수 또는 동작입니다.
    *   `server.AddTool(name, description, handler)`를 통해 등록됩니다.
    *   `tools/list` JSON-RPC 메서드를 통해 등록된 도구 목록과 입력 스키마를 조회할 수 있습니다.
    *   `tools/call` JSON-RPC 메서드를 통해 도구를 호출하고 결과를 받을 수 있습니다.
*   **Prompt (프롬프트):** 대화형 메시지 템플릿입니다.
    *   `server.AddPrompt(name, description, handler)`를 통해 등록됩니다.
    *   `prompts/list` JSON-RPC 메서드를 통해 등록된 프롬프트 목록을 조회할 수 있습니다.
    *   `prompts/get` JSON-RPC 메서드를 통해 프롬프트를 호출하고, 그 결과를 `types.Message` 또는 `[]types.Message` 형태로 받아 LLM에 전달할 수 있습니다.
*   **JSON-RPC 2.0 통신:**
    *   클라이언트와 서버 간의 통신은 표준 JSON-RPC 2.0 프로토콜을 따릅니다.
    *   요청(`types.Request`)과 응답(`types.Response`) 구조체가 명확하게 정의되어 있습니다.
    *   오류 처리도 JSON-RPC 2.0 사양에 따라 표준화된 오류 코드(`types.ResponseError`)를 사용합니다.
*   **다양한 전송 방식 지원:**
    *   **STDIO (표준 입출력):** `server.RunStdio()`를 통해 서버가 표준 입력에서 요청을 읽고 표준 출력으로 응답을 보냅니다. 이는 CLI 애플리케이션이나 다른 프로세스와의 간단한 통합에 유용합니다.
    *   **HTTP(SSE):** `server.ListenAndServe(addr)`를 통해 HTTP 서버를 시작하고, `/mcp` 엔드포인트를 통해 JSON-RPC 요청을 처리합니다. `Accept` 헤더에 따라 Server-Sent Events (SSE)를 지원하여 스트리밍 응답이 가능합니다.
*   **리플렉션 기반 동적 호출:**
    *   등록된 Resource, Tool, Prompt의 핸들러 함수는 `reflect` 패키지를 사용하여 동적으로 호출됩니다.
    *   `internal/util.util.ConvertType` 함수를 통해 JSON에서 파싱된 `interface{}` 타입의 인수를 Go 함수의 실제 매개변수 타입으로 안전하게 변환합니다.
    *   `internal/util.util.MatchURI` 함수를 통해 URI 템플릿과 실제 URI를 매칭하고 동적 파라미터를 추출합니다.
*   **클라이언트 라이브러리:**
    *   `client/client.go`에 서버와 상호작용하기 위한 클라이언트 라이브러리가 제공됩니다.
    *   서버 프로세스를 시작/중지하거나, HTTP 엔드포인트에 연결할 수 있습니다.
    *   `Initialize`, `ListTools`, `ListPrompts`, `Call`과 같은 메서드를 통해 서버의 기능을 활용할 수 있습니다.

### 2. 개선 사항

현재 `gomcp` 프로젝트는 핵심 기능을 잘 구현하고 있지만, 다음과 같은 개선 사항을 고려할 수 있습니다.

*   **오류 처리의 상세화:**
    *   현재 `server.handleFunctionOutputs`에서 Go `error`를 `types.CodeServerError`로 맵핑하고 있지만, 특정 비즈니스 로직 오류에 대한 더 세분화된 `Code`와 `Data` 필드를 활용하여 클라이언트에게 더 유용한 정보를 제공할 수 있습니다.
    *   `server.newError` 함수를 확장하여 `data` 필드를 더 쉽게 채울 수 있도록 할 수 있습니다.
*   **매개변수 유효성 검사 및 메타데이터 강화:**
    *   현재 도구/프롬프트의 `ParamNames`는 "param1", "param2"와 같이 자동으로 생성됩니다. 실제 매개변수 이름을 반영하거나, 구조체 태그(struct tags)를 사용하여 매개변수의 필수 여부, 기본값, 설명 등을 정의할 수 있다면 `inputSchema`가 더욱 풍부해지고 유효성 검사가 용이해질 것입니다.
    *   `reflect` 기반의 유효성 검사 라이브러리(예: `go-playground/validator`)를 통합하여 `tools/call` 및 `prompts/get` 시 매개변수 유효성 검사를 자동화할 수 있습니다.
*   **동시성 및 스레드 안전성:**
    *   `server.mu` (뮤텍스)는 `nextID` 증가에만 사용되고 있습니다. `AddResource`, `AddTool`, `AddPrompt`와 같은 등록 메서드나 `resources`, `tools`, `prompts` 맵에 대한 접근이 여러 고루틴에서 동시에 발생할 경우 데이터 경쟁 조건(race condition)이 발생할 수 있습니다. 이들에 대한 접근도 뮤텍스로 보호해야 합니다.
    *   HTTP 서버의 `handleMessage` 내에서 `s.resources`, `s.tools`, `s.prompts`에 접근하는 부분도 읽기/쓰기 락(RWMutex)을 사용하여 보호하는 것이 좋습니다.
*   **로깅:**
    *   현재 `log.Printf`를 사용하여 간단한 로깅을 수행합니다. `zap` 또는 `logrus`와 같은 구조화된 로깅 라이브러리를 도입하여 로그 레벨, 필터링, 출력 형식 등을 유연하게 제어할 수 있습니다.
    *   요청 ID를 로그에 포함하여 요청 추적을 용이하게 할 수 있습니다.
*   **테스트 커버리지 확장:**
    *   `server/server_test.go`는 기본적인 기능만 테스트합니다.
    *   오류 경로(잘못된 매개변수, 존재하지 않는 메서드/도구/리소스/프롬프트)에 대한 테스트를 추가해야 합니다.
    *   HTTP 전송 방식에 대한 통합 테스트를 추가해야 합니다.
    *   배치 요청 및 알림에 대한 테스트를 추가해야 합니다.
    *   프롬프트 기능(`prompts/list`, `prompts/get`)에 대한 테스트를 추가해야 합니다.
    *   더 복잡한 데이터 유형(구조체, 배열)을 인수로 받는 도구/프롬프트에 대한 테스트를 추가해야 합니다.
*   **보안:**
    *   HTTP 엔드포인트에 대한 인증 및 권한 부여 메커니즘이 없습니다. 프로덕션 환경에서는 API 키, OAuth2, JWT 등 적절한 보안 계층을 추가해야 합니다.
*   **리소스 관리:**
    *   `RunStdio`에서 `os.Exit(0)`를 호출하는 것은 고루틴에서 안전하지 않을 수 있습니다. 대신 `context.Context`를 사용하여 서버 종료 신호를 전달하고 모든 고루틴이 안전하게 종료되도록 하는 것이 더 견고한 방법입니다.

### 3. 추가 기능 제안

`gomcp`의 현재 아키텍처를 기반으로 다음과 같은 추가 기능을 제안합니다.

*   **비동기 도구 실행 및 상태 관리:**
    *   현재 도구 호출은 동기적으로 처리됩니다. 장시간 실행되는 도구의 경우, 호출 즉시 응답을 반환하고 나중에 결과를 조회할 수 있는 비동기 실행 모델을 도입할 수 있습니다. (예: `tools/call_async` 메서드가 작업 ID를 반환하고, `tools/get_result` 메서드가 작업 ID로 결과를 조회)
    *   이를 위해 작업 큐(예: Redis, Kafka)와 작업자(worker) 풀을 통합할 수 있습니다.
*   **스트리밍 응답 (Tool/Prompt):**
    *   현재 SSE는 JSON-RPC 응답 자체를 스트리밍하는 데 사용되지만, 도구나 프롬프트의 결과가 실시간으로 생성되는 경우(예: LLM 스트리밍 응답)를 위해 `tools/call_stream` 또는 `prompts/get_stream`과 같은 메서드를 추가하여 부분적인 결과를 스트리밍할 수 있습니다.
    *   `types.Content`에 `isPartial`과 같은 필드를 추가하여 부분 응답임을 나타낼 수 있습니다.
*   **이벤트 시스템:**
    *   서버에서 특정 이벤트(예: 도구 실행 완료, 리소스 업데이트)가 발생했을 때 클라이언트에게 알림을 보낼 수 있는 이벤트 구독/발행 시스템을 도입할 수 있습니다.
    *   이는 `notifications` JSON-RPC 메서드를 활용하여 구현할 수 있습니다.
*   **동적 등록/해제:**
    *   현재 Resource, Tool, Prompt는 서버 시작 시 정적으로 등록됩니다. 런타임에 동적으로 등록하거나 해제할 수 있는 JSON-RPC 메서드(예: `tools/register`, `tools/unregister`)를 추가할 수 있습니다.
*   **버전 관리 및 호환성:**
    *   `initialize` 메서드에서 `protocolVersion`을 교환하지만, 더 복잡한 버전 협상 메커니즘을 도입하여 프로토콜 변경 시 하위 호환성을 유지하거나 클라이언트/서버 간의 호환 가능한 버전을 찾을 수 있도록 할 수 있습니다.
*   **미들웨어/인터셉터:**
    *   요청 처리 파이프라인에 미들웨어 또는 인터셉터 계층을 추가하여 로깅, 인증, 성능 모니터링, 오류 변환 등 횡단 관심사(cross-cutting concerns)를 쉽게 적용할 수 있도록 합니다.
*   **플러그인 아키텍처:**
    *   Resource, Tool, Prompt를 외부 모듈이나 플러그인으로 로드할 수 있는 아키텍처를 도입하여 `gomcp` 코어와 비즈니스 로직을 분리하고 확장성을 높일 수 있습니다.
*   **헬스 체크 엔드포인트:**
    *   서버의 상태를 모니터링하기 위한 전용 헬스 체크 엔드포인트(예: `/health`)를 추가하여 컨테이너 오케스트레이션 환경(Kubernetes 등)에서 활용할 수 있습니다.

---