package server

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/hawoond/gomcp/internal/types"
)

func (s *Server) invokeTool(
	ctx context.Context,
	tool Tool,
	arguments map[string]interface{},
) (result interface{}, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = fmt.Errorf("tool handler panicked: %v", recovered)
		}
	}()

	if tool.Handler != nil {
		return tool.Handler(ctx, arguments)
	}
	if tool.ParamStructType != nil {
		paramInstance := reflect.New(tool.ParamStructType).Interface()
		jsonParams, marshalErr := json.Marshal(arguments)
		if marshalErr != nil {
			return nil, fmt.Errorf("encode parameters: %w", marshalErr)
		}
		if unmarshalErr := json.Unmarshal(jsonParams, paramInstance); unmarshalErr != nil {
			return nil, fmt.Errorf("decode parameters: %w", unmarshalErr)
		}
		if validationErr := s.validator.Struct(paramInstance); validationErr != nil {
			return nil, fmt.Errorf("validate parameters: %w", validationErr)
		}
	}

	args, err := s.prepareFuncArgs(tool.ParamTypes, arguments, tool.ParamNames)
	if err != nil {
		return nil, err
	}
	outValues := tool.Func.Call(args)
	var responseError *types.ResponseError
	result, err = s.handleFunctionOutputs(outValues, &responseError)
	if responseError != nil && err == nil {
		err = fmt.Errorf("%s", responseError.Message)
	}
	return result, err
}

func toToolResult(result interface{}, err error) types.CallToolResult {
	if err != nil {
		return types.ErrorResult(err)
	}
	switch value := result.(type) {
	case types.CallToolResult:
		return value
	case *types.CallToolResult:
		if value == nil {
			return types.CallToolResult{Content: []types.Content{}}
		}
		return *value
	case []types.Content:
		return types.CallToolResult{Content: value}
	case types.Content:
		return types.CallToolResult{Content: []types.Content{value}}
	case string:
		return types.CallToolResult{Content: []types.Content{{Type: "text", Text: value}}}
	case nil:
		return types.CallToolResult{Content: []types.Content{}}
	default:
		encoded, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			return types.ErrorResult(fmt.Errorf("encode tool result: %w", marshalErr))
		}
		return types.CallToolResult{
			Content:           []types.Content{{Type: "text", Text: string(encoded)}},
			StructuredContent: value,
		}
	}
}
