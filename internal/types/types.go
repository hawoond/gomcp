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
	Type      string `json:"type"`
	Text      string `json:"text,omitempty"`
	Data      string `json:"data,omitempty"`
	MimeType  string `json:"mimeType,omitempty"`
	URI       string `json:"uri,omitempty"`
	IsPartial bool   `json:"isPartial,omitempty"`
}

type Message struct {
	Role    string  `json:"role"`
	Content Content `json:"content"`
}

type CallToolResult struct {
	Content           []Content              `json:"content"`
	StructuredContent interface{}            `json:"structuredContent,omitempty"`
	IsError           bool                   `json:"isError,omitempty"`
	Meta              map[string]interface{} `json:"_meta,omitempty"`
}

type ReadResourceResult struct {
	Contents []Content `json:"contents"`
}

type GetPromptResult struct {
	Description string    `json:"description,omitempty"`
	Messages    []Message `json:"messages"`
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
