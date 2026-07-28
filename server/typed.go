package server

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

func RegisterTool[Input any, Output any](
	server *Server,
	name string,
	description string,
	handler func(context.Context, Input) (Output, error),
) error {
	return registerTypedTool(server, name, description, "forbidden", handler)
}

func RegisterTaskTool[Input any, Output any](
	server *Server,
	name string,
	description string,
	handler func(context.Context, Input) (Output, error),
) error {
	return registerTypedTool(server, name, description, "optional", handler)
}

func registerTypedTool[Input any, Output any](
	server *Server,
	name string,
	description string,
	taskSupport string,
	handler func(context.Context, Input) (Output, error),
) error {
	if server == nil {
		return fmt.Errorf("server is required")
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("tool name is required")
	}
	if handler == nil {
		return fmt.Errorf("tool handler is required")
	}

	inputType := reflect.TypeOf((*Input)(nil)).Elem()
	schema := schemaForType(inputType, make(map[reflect.Type]bool))
	if schema["type"] != "object" {
		schema = map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"value": schema,
			},
			"required": []string{"value"},
		}
	}

	tool := Tool{
		Name:        name,
		Description: description,
		InputSchema: schema,
		TaskSupport: taskSupport,
		Handler: func(ctx context.Context, arguments map[string]interface{}) (interface{}, error) {
			var input Input
			encoded, err := json.Marshal(arguments)
			if err != nil {
				return nil, fmt.Errorf("encode tool arguments: %w", err)
			}
			if err := json.Unmarshal(encoded, &input); err != nil {
				return nil, fmt.Errorf("decode tool arguments: %w", err)
			}
			if err := server.validator.Struct(input); err != nil {
				return nil, fmt.Errorf("validate tool arguments: %w", err)
			}
			return handler(ctx, input)
		},
	}

	server.rwMu.Lock()
	defer server.rwMu.Unlock()
	if _, exists := server.tools[name]; exists {
		return fmt.Errorf("tool %q is already registered", name)
	}
	server.tools[name] = tool
	return nil
}

func schemaForType(valueType reflect.Type, visiting map[reflect.Type]bool) map[string]interface{} {
	for valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	if visiting[valueType] {
		return map[string]interface{}{"type": "object"}
	}

	switch valueType.Kind() {
	case reflect.Bool:
		return map[string]interface{}{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]interface{}{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]interface{}{"type": "number"}
	case reflect.String:
		return map[string]interface{}{"type": "string"}
	case reflect.Slice, reflect.Array:
		return map[string]interface{}{
			"type":  "array",
			"items": schemaForType(valueType.Elem(), visiting),
		}
	case reflect.Map:
		return map[string]interface{}{
			"type":                 "object",
			"additionalProperties": schemaForType(valueType.Elem(), visiting),
		}
	case reflect.Struct:
		visiting[valueType] = true
		defer delete(visiting, valueType)

		properties := make(map[string]interface{})
		required := make([]string, 0, valueType.NumField())
		for index := 0; index < valueType.NumField(); index++ {
			field := valueType.Field(index)
			if !field.IsExported() {
				continue
			}
			tag := field.Tag.Get("json")
			tagParts := strings.Split(tag, ",")
			name := tagParts[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			properties[name] = schemaForType(field.Type, visiting)

			optional := field.Type.Kind() == reflect.Pointer
			for _, option := range tagParts[1:] {
				optional = optional || option == "omitempty"
			}
			if !optional {
				required = append(required, name)
			}
		}
		schema := map[string]interface{}{
			"type":                 "object",
			"properties":           properties,
			"additionalProperties": false,
		}
		if len(required) > 0 {
			schema["required"] = required
		}
		return schema
	default:
		return map[string]interface{}{}
	}
}
