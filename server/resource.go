package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/hawoond/gomcp/internal/types"
)

func (s *Server) invokeResource(resource Resource, uri string, values []string) (result interface{}, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = fmt.Errorf("resource handler panicked: %v", recovered)
		}
	}()

	args := make([]reflect.Value, len(values))
	for index, value := range values {
		converted, convertErr := convertString(value, resource.Func.Type().In(index))
		if convertErr != nil {
			return nil, convertErr
		}
		args[index] = converted
	}
	outValues := resource.Func.Call(args)
	var responseError *types.ResponseError
	result, err = s.handleFunctionOutputs(outValues, &responseError)
	if responseError != nil && err == nil {
		err = fmt.Errorf("%s", responseError.Message)
	}
	return result, err
}

func resourceResult(uri string, result interface{}) (types.ReadResourceResult, error) {
	switch value := result.(type) {
	case types.ReadResourceResult:
		return value, nil
	case types.Content:
		if value.URI == "" {
			value.URI = uri
		}
		return types.ReadResourceResult{Contents: []types.Content{value}}, nil
	case []types.Content:
		for index := range value {
			if value[index].URI == "" {
				value[index].URI = uri
			}
		}
		return types.ReadResourceResult{Contents: value}, nil
	case []byte:
		return types.ReadResourceResult{Contents: []types.Content{{
			URI:      uri,
			Type:     "blob",
			Data:     base64.StdEncoding.EncodeToString(value),
			MimeType: "application/octet-stream",
		}}}, nil
	case string:
		return types.ReadResourceResult{Contents: []types.Content{{
			URI:      uri,
			Type:     "text",
			Text:     value,
			MimeType: "text/plain",
		}}}, nil
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return types.ReadResourceResult{}, fmt.Errorf("encode resource result: %w", err)
		}
		return types.ReadResourceResult{Contents: []types.Content{{
			URI:      uri,
			Type:     "text",
			Text:     string(encoded),
			MimeType: "application/json",
		}}}, nil
	}
}

func convertString(value string, target reflect.Type) (reflect.Value, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return reflect.Value{}, err
	}
	converted := reflect.New(target)
	if target.Kind() == reflect.String {
		converted.Elem().SetString(value)
		return converted.Elem(), nil
	}
	if err := json.Unmarshal(encoded, converted.Interface()); err == nil {
		return converted.Elem(), nil
	}

	var generic interface{}
	if err := json.Unmarshal([]byte(value), &generic); err != nil {
		return reflect.Value{}, fmt.Errorf("convert URI value %q to %s: %w", value, target, err)
	}
	return convertJSONValue(generic, target)
}

func convertJSONValue(value interface{}, target reflect.Type) (reflect.Value, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return reflect.Value{}, err
	}
	converted := reflect.New(target)
	if err := json.Unmarshal(encoded, converted.Interface()); err != nil {
		return reflect.Value{}, err
	}
	return converted.Elem(), nil
}
