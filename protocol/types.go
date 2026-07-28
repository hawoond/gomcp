package protocol

import "github.com/hawoond/gomcp/internal/types"

const (
	ProtocolVersion20241105 = types.ProtocolVersion20241105
	ProtocolVersion20250326 = types.ProtocolVersion20250326
	ProtocolVersion20250618 = types.ProtocolVersion20250618
	ProtocolVersion20251125 = types.ProtocolVersion20251125
	ProtocolVersion20260728 = types.ProtocolVersion20260728
	LatestProtocolVersion   = types.LatestProtocolVersion
)

type Request = types.Request
type Response = types.Response
type ResponseError = types.ResponseError
type Content = types.Content
type Message = types.Message
type Annotations = types.Annotations
type Icon = types.Icon
type ToolAnnotations = types.ToolAnnotations
type CallToolResult = types.CallToolResult
type ReadResourceResult = types.ReadResourceResult
type GetPromptResult = types.GetPromptResult
type ResourceContents = types.ResourceContents
type ResourceInfo = types.ResourceInfo
type ResourceTemplate = types.ResourceTemplate
type PromptInfo = types.PromptInfo
type PromptArgument = types.PromptArgument
type ToolInfo = types.ToolInfo
type PaginatedParams = types.PaginatedParams
type ListToolsResult = types.ListToolsResult
type ListResourcesResult = types.ListResourcesResult
type ListResourceTemplatesResult = types.ListResourceTemplatesResult
type ListPromptsResult = types.ListPromptsResult
type CompleteParams = types.CompleteParams
type CompleteArgument = types.CompleteArgument
type Completion = types.Completion
type CompleteResult = types.CompleteResult
type CancelledParams = types.CancelledParams
type ProgressParams = types.ProgressParams
type ElicitParams = types.ElicitParams
type ElicitResult = types.ElicitResult
type Root = types.Root
type ListRootsResult = types.ListRootsResult
type ModelHint = types.ModelHint
type ModelPreferences = types.ModelPreferences
type SamplingMessage = types.SamplingMessage
type CreateMessageParams = types.CreateMessageParams
type CreateMessageResult = types.CreateMessageResult
type LoggingMessageParams = types.LoggingMessageParams
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
