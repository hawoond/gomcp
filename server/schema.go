package server

import (
	"encoding/json"
	"fmt"
	"math"
)

func validateSchemaValue(value interface{}, schema map[string]interface{}) error {
	if len(schema) == 0 {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode value for schema validation: %w", err)
	}
	var normalized interface{}
	if err := json.Unmarshal(encoded, &normalized); err != nil {
		return fmt.Errorf("normalize value for schema validation: %w", err)
	}
	return validateNormalizedValue(normalized, schema, "$")
}

func validateNormalizedValue(value interface{}, schema map[string]interface{}, path string) error {
	schemaType, _ := schema["type"].(string)
	switch schemaType {
	case "":
		return nil
	case "object":
		object, ok := value.(map[string]interface{})
		if !ok {
			return fmt.Errorf("%s must be an object", path)
		}
		properties, _ := schema["properties"].(map[string]interface{})
		for _, required := range stringSlice(schema["required"]) {
			if _, ok := object[required]; !ok {
				return fmt.Errorf("%s.%s is required", path, required)
			}
		}
		for name, child := range object {
			childSchema, declared := properties[name].(map[string]interface{})
			if !declared {
				if additional, ok := schema["additionalProperties"].(bool); ok && !additional {
					return fmt.Errorf("%s.%s is not allowed", path, name)
				}
				if additional, ok := schema["additionalProperties"].(map[string]interface{}); ok {
					childSchema = additional
					declared = true
				}
			}
			if declared {
				if err := validateNormalizedValue(child, childSchema, path+"."+name); err != nil {
					return err
				}
			}
		}
	case "array":
		array, ok := value.([]interface{})
		if !ok {
			return fmt.Errorf("%s must be an array", path)
		}
		itemSchema, _ := schema["items"].(map[string]interface{})
		for index, child := range array {
			if err := validateNormalizedValue(child, itemSchema, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s must be a string", path)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s must be a boolean", path)
		}
	case "number":
		if _, ok := value.(float64); !ok {
			return fmt.Errorf("%s must be a number", path)
		}
	case "integer":
		number, ok := value.(float64)
		if !ok || math.Trunc(number) != number {
			return fmt.Errorf("%s must be an integer", path)
		}
	case "null":
		if value != nil {
			return fmt.Errorf("%s must be null", path)
		}
	}
	return nil
}

func stringSlice(value interface{}) []string {
	switch values := value.(type) {
	case []string:
		return append([]string(nil), values...)
	case []interface{}:
		result := make([]string, 0, len(values))
		for _, value := range values {
			if text, ok := value.(string); ok {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
}
