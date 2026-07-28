package protocol

import "github.com/hawoond/gomcp/internal/types"

const (
	ProtocolVersion20241105 = types.ProtocolVersion20241105
	ProtocolVersion20250326 = types.ProtocolVersion20250326
	ProtocolVersion20250618 = types.ProtocolVersion20250618
	ProtocolVersion20251125 = types.ProtocolVersion20251125
	LatestProtocolVersion   = types.LatestProtocolVersion
)

type Request = types.Request
type Response = types.Response
type ResponseError = types.ResponseError
type Content = types.Content
type Message = types.Message
type CallToolResult = types.CallToolResult
type ReadResourceResult = types.ReadResourceResult
type GetPromptResult = types.GetPromptResult
type CustomError = types.CustomError
type Task = types.Task
type TaskStatus = types.TaskStatus
type ToolDefinition = types.ToolDefinition
type CommandConfig = types.CommandConfig
type HTTPConfig = types.HTTPConfig
type PromptDefinition = types.PromptDefinition

const (
	TaskStatusWorking       = types.TaskStatusWorking
	TaskStatusInputRequired = types.TaskStatusInputRequired
	TaskStatusCompleted     = types.TaskStatusCompleted
	TaskStatusFailed        = types.TaskStatusFailed
	TaskStatusCancelled     = types.TaskStatusCancelled
	TaskStatusRunning       = types.TaskStatusRunning
)

func NewCustomError(code int, message string, data interface{}) *CustomError {
	return types.NewCustomError(code, message, data)
}
