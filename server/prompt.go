package server

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/hawoond/gomcp/internal/types"
)

func (s *Server) invokePrompt(prompt Prompt, arguments map[string]interface{}) (result interface{}, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = fmt.Errorf("prompt handler panicked: %v", recovered)
		}
	}()

	if prompt.ParamStructType != nil {
		paramInstance := reflect.New(prompt.ParamStructType).Interface()
		encoded, marshalErr := json.Marshal(arguments)
		if marshalErr != nil {
			return nil, marshalErr
		}
		if unmarshalErr := json.Unmarshal(encoded, paramInstance); unmarshalErr != nil {
			return nil, unmarshalErr
		}
		if validationErr := s.validator.Struct(paramInstance); validationErr != nil {
			return nil, validationErr
		}
	}
	args, err := s.prepareFuncArgs(prompt.ParamTypes, arguments, prompt.ParamNames)
	if err != nil {
		return nil, err
	}
	outValues := prompt.Func.Call(args)
	if len(outValues) == 0 {
		return nil, nil
	}
	if len(outValues) == 2 && !outValues[1].IsNil() {
		return nil, outValues[1].Interface().(error)
	}
	return outValues[0].Interface(), nil
}

func promptResult(description string, value interface{}) types.GetPromptResult {
	switch result := value.(type) {
	case types.GetPromptResult:
		if result.Description == "" {
			result.Description = description
		}
		return result
	case []types.Message:
		return types.GetPromptResult{Description: description, Messages: result}
	case types.Message:
		return types.GetPromptResult{Description: description, Messages: []types.Message{result}}
	case string:
		return types.GetPromptResult{
			Description: description,
			Messages: []types.Message{{
				Role:    "user",
				Content: types.Content{Type: "text", Text: result},
			}},
		}
	case nil:
		return types.GetPromptResult{Description: description, Messages: []types.Message{}}
	default:
		encoded, err := json.Marshal(result)
		if err != nil {
			encoded = []byte(fmt.Sprintf("%v", result))
		}
		return types.GetPromptResult{
			Description: description,
			Messages: []types.Message{{
				Role:    "user",
				Content: types.Content{Type: "text", Text: string(encoded)},
			}},
		}
	}
}
