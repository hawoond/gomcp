package types

import (
	"encoding/json"
)

const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
	CodeServerError    = -32000

	// Custom MCP-specific error codes
	CodeVersionMismatch = -32001
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
	IsPartial bool   `json:"isPartial,omitempty"`
}

type Message struct {
	Role    string  `json:"role"`
	Content Content `json:"content"`
}

// CustomError represents a custom error that can be returned by handlers
// to provide more specific JSON-RPC error details.
type CustomError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (e *CustomError) Error() string {
	return e.Message
}

// NewCustomError creates a new CustomError instance.
func NewCustomError(code int, message string, data interface{}) *CustomError {
	return &CustomError{
		Code:    code,
		Message: message,
		Data:    data,
	}
}

type TaskStatus string

const (
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
)

type Task struct {
	ID     string        `json:"id"`
	Status TaskStatus    `json:"status"`
	Result interface{}   `json:"result,omitempty"`
	Error  *ResponseError `json:"error,omitempty"`
}

// ToolDefinition defines the structure for dynamically registering a tool.
type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"` // JSON Schema for input parameters
	Type        string          `json:"type"`                  // "command", "http"
	Command     *CommandConfig  `json:"command,omitempty"`
	HTTP        *HTTPConfig     `json:"http,omitempty"`
}

// CommandConfig defines configuration for executing a shell command.
type CommandConfig struct {
	Path string   `json:"path"` // Path to the executable
	Args []string `json:"args,omitempty"` // Arguments to pass to the command
	// TODO: Add environment variables, working directory, etc.
}

// HTTPConfig defines configuration for making an HTTP request.
type HTTPConfig struct {
	URL    string            `json:"url"`
	Method string            `json:"method,omitempty"` // GET, POST, etc. Defaults to POST.
	Headers map[string]string `json:"headers,omitempty"`
	Body   string            `json:"body,omitempty"` // Template for request body
	// TODO: Add authentication, response parsing, etc.
}

// PromptDefinition defines the structure for dynamically registering a prompt.
type PromptDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"` // JSON Schema for input parameters
	Type        string          `json:"type"`                  // "command", "http"
	Command     *CommandConfig  `json:"command,omitempty"`
	HTTP        *HTTPConfig     `json:"http,omitempty"`
}