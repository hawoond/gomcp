package types

import (
	"encoding/json"
	"fmt"
)

const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
	CodeServerError    = -32000

	CodeVersionMismatch = -32001
	CodeTaskNotFound    = -32002
)

const (
	ProtocolVersion20241105 = "2024-11-05"
	ProtocolVersion20250326 = "2025-03-26"
	ProtocolVersion20250618 = "2025-06-18"
	ProtocolVersion20251125 = "2025-11-25"
	ProtocolVersion20260728 = "2026-07-28"
	LatestProtocolVersion   = ProtocolVersion20251125
)

type Request struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Result  interface{}      `json:"result,omitempty"`
	Error   *ResponseError   `json:"error,omitempty"`
}

type ResponseError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type Content struct {
	Type        string                 `json:"type"`
	Text        string                 `json:"text,omitempty"`
	Data        string                 `json:"data,omitempty"`
	MimeType    string                 `json:"mimeType,omitempty"`
	URI         string                 `json:"uri,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Title       string                 `json:"title,omitempty"`
	Description string                 `json:"description,omitempty"`
	Size        *int64                 `json:"size,omitempty"`
	Annotations *Annotations           `json:"annotations,omitempty"`
	Meta        map[string]interface{} `json:"_meta,omitempty"`
	IsPartial   bool                   `json:"isPartial,omitempty"`
}

type Message struct {
	Role    string  `json:"role"`
	Content Content `json:"content"`
}

type Annotations struct {
	Audience     []string `json:"audience,omitempty"`
	Priority     *float64 `json:"priority,omitempty"`
	LastModified string   `json:"lastModified,omitempty"`
}

type Icon struct {
	Source   string   `json:"src"`
	MimeType string   `json:"mimeType,omitempty"`
	Sizes    []string `json:"sizes,omitempty"`
	Theme    string   `json:"theme,omitempty"`
}

type ToolAnnotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

type CallToolResult struct {
	Content           []Content              `json:"content"`
	StructuredContent interface{}            `json:"structuredContent,omitempty"`
	IsError           bool                   `json:"isError,omitempty"`
	Meta              map[string]interface{} `json:"_meta,omitempty"`
}

type ReadResourceResult struct {
	Contents []ResourceContents     `json:"contents"`
	Meta     map[string]interface{} `json:"_meta,omitempty"`
}

type GetPromptResult struct {
	Description string                 `json:"description,omitempty"`
	Messages    []Message              `json:"messages"`
	Meta        map[string]interface{} `json:"_meta,omitempty"`
}

type ResourceContents struct {
	URI      string                 `json:"uri"`
	MimeType string                 `json:"mimeType,omitempty"`
	Text     string                 `json:"text,omitempty"`
	Blob     string                 `json:"blob,omitempty"`
	Meta     map[string]interface{} `json:"_meta,omitempty"`
}

type ResourceInfo struct {
	URI         string                 `json:"uri"`
	Name        string                 `json:"name"`
	Title       string                 `json:"title,omitempty"`
	Description string                 `json:"description,omitempty"`
	MimeType    string                 `json:"mimeType,omitempty"`
	Size        *int64                 `json:"size,omitempty"`
	Icons       []Icon                 `json:"icons,omitempty"`
	Annotations *Annotations           `json:"annotations,omitempty"`
	Meta        map[string]interface{} `json:"_meta,omitempty"`
}

type ResourceTemplate struct {
	URITemplate string                 `json:"uriTemplate"`
	Name        string                 `json:"name"`
	Title       string                 `json:"title,omitempty"`
	Description string                 `json:"description,omitempty"`
	MimeType    string                 `json:"mimeType,omitempty"`
	Icons       []Icon                 `json:"icons,omitempty"`
	Annotations *Annotations           `json:"annotations,omitempty"`
	Meta        map[string]interface{} `json:"_meta,omitempty"`
}

type PromptInfo struct {
	Name        string                 `json:"name"`
	Title       string                 `json:"title,omitempty"`
	Description string                 `json:"description,omitempty"`
	Arguments   []PromptArgument       `json:"arguments,omitempty"`
	Icons       []Icon                 `json:"icons,omitempty"`
	Meta        map[string]interface{} `json:"_meta,omitempty"`
}

type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

type ToolInfo struct {
	Name         string                 `json:"name"`
	Title        string                 `json:"title,omitempty"`
	Description  string                 `json:"description,omitempty"`
	InputSchema  interface{}            `json:"inputSchema"`
	OutputSchema interface{}            `json:"outputSchema,omitempty"`
	Annotations  *ToolAnnotations       `json:"annotations,omitempty"`
	Icons        []Icon                 `json:"icons,omitempty"`
	Meta         map[string]interface{} `json:"_meta,omitempty"`
	Execution    map[string]interface{} `json:"execution,omitempty"`
}

type PaginatedParams struct {
	Cursor string `json:"cursor,omitempty"`
}

type ListToolsResult struct {
	Tools      []ToolInfo             `json:"tools"`
	NextCursor string                 `json:"nextCursor,omitempty"`
	Meta       map[string]interface{} `json:"_meta,omitempty"`
}

type ListResourcesResult struct {
	Resources  []ResourceInfo         `json:"resources"`
	NextCursor string                 `json:"nextCursor,omitempty"`
	Meta       map[string]interface{} `json:"_meta,omitempty"`
}

type ListResourceTemplatesResult struct {
	ResourceTemplates []ResourceTemplate     `json:"resourceTemplates"`
	NextCursor        string                 `json:"nextCursor,omitempty"`
	Meta              map[string]interface{} `json:"_meta,omitempty"`
}

type ListPromptsResult struct {
	Prompts    []PromptInfo           `json:"prompts"`
	NextCursor string                 `json:"nextCursor,omitempty"`
	Meta       map[string]interface{} `json:"_meta,omitempty"`
}

type CompleteParams struct {
	Ref      map[string]interface{} `json:"ref"`
	Argument CompleteArgument       `json:"argument"`
	Context  map[string]interface{} `json:"context,omitempty"`
}

type CompleteArgument struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Completion struct {
	Values  []string `json:"values"`
	Total   *int     `json:"total,omitempty"`
	HasMore *bool    `json:"hasMore,omitempty"`
}

type CompleteResult struct {
	Completion Completion             `json:"completion"`
	Meta       map[string]interface{} `json:"_meta,omitempty"`
}

type CancelledParams struct {
	RequestID json.RawMessage        `json:"requestId"`
	Reason    string                 `json:"reason,omitempty"`
	Meta      map[string]interface{} `json:"_meta,omitempty"`
}

type ProgressParams struct {
	ProgressToken interface{}            `json:"progressToken"`
	Progress      float64                `json:"progress"`
	Total         *float64               `json:"total,omitempty"`
	Message       string                 `json:"message,omitempty"`
	Meta          map[string]interface{} `json:"_meta,omitempty"`
}

type ElicitParams struct {
	Mode            string                 `json:"mode"`
	Message         string                 `json:"message"`
	RequestedSchema map[string]interface{} `json:"requestedSchema,omitempty"`
	URL             string                 `json:"url,omitempty"`
	ElicitationID   string                 `json:"elicitationId,omitempty"`
	Meta            map[string]interface{} `json:"_meta,omitempty"`
}

type ElicitResult struct {
	Action  string                 `json:"action"`
	Content map[string]interface{} `json:"content,omitempty"`
	Meta    map[string]interface{} `json:"_meta,omitempty"`
}

type Root struct {
	URI  string `json:"uri"`
	Name string `json:"name,omitempty"`
}

type ListRootsResult struct {
	Roots []Root                 `json:"roots"`
	Meta  map[string]interface{} `json:"_meta,omitempty"`
}

type ModelHint struct {
	Name string `json:"name,omitempty"`
}

type ModelPreferences struct {
	Hints                []ModelHint `json:"hints,omitempty"`
	CostPriority         *float64    `json:"costPriority,omitempty"`
	SpeedPriority        *float64    `json:"speedPriority,omitempty"`
	IntelligencePriority *float64    `json:"intelligencePriority,omitempty"`
}

type SamplingMessage struct {
	Role    string  `json:"role"`
	Content Content `json:"content"`
}

type CreateMessageParams struct {
	Messages         []SamplingMessage      `json:"messages"`
	ModelPreferences *ModelPreferences      `json:"modelPreferences,omitempty"`
	SystemPrompt     string                 `json:"systemPrompt,omitempty"`
	IncludeContext   string                 `json:"includeContext,omitempty"`
	Temperature      *float64               `json:"temperature,omitempty"`
	MaxTokens        int                    `json:"maxTokens"`
	StopSequences    []string               `json:"stopSequences,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	Meta             map[string]interface{} `json:"_meta,omitempty"`
}

type CreateMessageResult struct {
	Role       string                 `json:"role"`
	Content    Content                `json:"content"`
	Model      string                 `json:"model"`
	StopReason string                 `json:"stopReason,omitempty"`
	Meta       map[string]interface{} `json:"_meta,omitempty"`
}

type LoggingMessageParams struct {
	Level  string      `json:"level"`
	Logger string      `json:"logger,omitempty"`
	Data   interface{} `json:"data"`
}

type CustomError struct {
	Code    int
	Message string
	Data    interface{}
}

func (e *CustomError) Error() string {
	return e.Message
}

func NewCustomError(code int, message string, data interface{}) *CustomError {
	return &CustomError{Code: code, Message: message, Data: data}
}

type TaskStatus string

const (
	TaskStatusWorking       TaskStatus = "working"
	TaskStatusInputRequired TaskStatus = "input_required"
	TaskStatusCompleted     TaskStatus = "completed"
	TaskStatusFailed        TaskStatus = "failed"
	TaskStatusCancelled     TaskStatus = "cancelled"

	// TaskStatusRunning is retained for source compatibility.
	TaskStatusRunning = TaskStatusWorking
)

type Task struct {
	ID            string         `json:"taskId"`
	Status        TaskStatus     `json:"status"`
	StatusMessage string         `json:"statusMessage,omitempty"`
	Result        interface{}    `json:"-"`
	Error         *ResponseError `json:"-"`
	CreatedAt     string         `json:"createdAt"`
	LastUpdatedAt string         `json:"lastUpdatedAt"`
	TTL           int64          `json:"ttl"`
	PollInterval  int64          `json:"pollInterval,omitempty"`
}

type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	Type        string          `json:"type"`
	Command     *CommandConfig  `json:"command,omitempty"`
	HTTP        *HTTPConfig     `json:"http,omitempty"`
}

type CommandConfig struct {
	Path          string   `json:"path"`
	Args          []string `json:"args,omitempty"`
	TimeoutMillis int64    `json:"timeoutMillis,omitempty"`
}

type HTTPConfig struct {
	URL              string            `json:"url"`
	Method           string            `json:"method,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	Body             string            `json:"body,omitempty"`
	TimeoutMillis    int64             `json:"timeoutMillis,omitempty"`
	MaxResponseBytes int64             `json:"maxResponseBytes,omitempty"`
}

type PromptDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	Type        string          `json:"type"`
	Command     *CommandConfig  `json:"command,omitempty"`
	HTTP        *HTTPConfig     `json:"http,omitempty"`
}

func ErrorResult(err error) CallToolResult {
	if err == nil {
		err = fmt.Errorf("tool execution failed")
	}
	return CallToolResult{
		Content: []Content{{Type: "text", Text: err.Error()}},
		IsError: true,
	}
}
