package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
)

func BytesReader(b []byte) io.Reader {
	return bytes.NewReader(b)
}

func ConvertType(value interface{}, target reflect.Type) (reflect.Value, error) {
	if target == nil {
		return reflect.Value{}, fmt.Errorf("target type is nil")
	}
	if value == nil {
		switch target.Kind() {
		case reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			return reflect.Zero(target), nil
		default:
			return reflect.Value{}, fmt.Errorf("cannot convert null to %s", target)
		}
	}

	source := reflect.ValueOf(value)
	if source.Type().AssignableTo(target) {
		return source, nil
	}
	if source.Type().ConvertibleTo(target) && source.Kind() != reflect.Float64 {
		return source.Convert(target), nil
	}

	if target.Kind() == reflect.Pointer {
		converted, err := ConvertType(value, target.Elem())
		if err != nil {
			return reflect.Value{}, err
		}
		ptr := reflect.New(target.Elem())
		ptr.Elem().Set(converted)
		return ptr, nil
	}

	switch target.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		number, ok := value.(float64)
		if !ok || math.Trunc(number) != number {
			return reflect.Value{}, fmt.Errorf("cannot convert %v to %s", value, target)
		}
		if number < -9223372036854775808 || number >= 9223372036854775808 {
			return reflect.Value{}, fmt.Errorf("%v overflows %s", value, target)
		}
		result := reflect.New(target).Elem()
		integer := int64(number)
		if result.OverflowInt(integer) {
			return reflect.Value{}, fmt.Errorf("%v overflows %s", value, target)
		}
		result.SetInt(integer)
		return result, nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		number, ok := value.(float64)
		if !ok || number < 0 || math.Trunc(number) != number || number >= 18446744073709551616 {
			return reflect.Value{}, fmt.Errorf("cannot convert %v to %s", value, target)
		}
		result := reflect.New(target).Elem()
		integer := uint64(number)
		if result.OverflowUint(integer) {
			return reflect.Value{}, fmt.Errorf("%v overflows %s", value, target)
		}
		result.SetUint(integer)
		return result, nil
	case reflect.Float32, reflect.Float64:
		number, ok := value.(float64)
		if !ok {
			return reflect.Value{}, fmt.Errorf("cannot convert %v to %s", value, target)
		}
		result := reflect.New(target).Elem()
		if result.OverflowFloat(number) {
			return reflect.Value{}, fmt.Errorf("%v overflows %s", value, target)
		}
		result.SetFloat(number)
		return result, nil
	case reflect.Bool:
		if boolean, ok := value.(bool); ok {
			return reflect.ValueOf(boolean).Convert(target), nil
		}
	case reflect.String:
		if text, ok := value.(string); ok {
			return reflect.ValueOf(text).Convert(target), nil
		}
	case reflect.Interface:
		if source.Type().Implements(target) {
			return source, nil
		}
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		return reflect.Value{}, fmt.Errorf("encode %s: %w", target, err)
	}
	result := reflect.New(target)
	if err := json.Unmarshal(encoded, result.Interface()); err != nil {
		return reflect.Value{}, fmt.Errorf("convert to %s: %w", target, err)
	}
	return result.Elem(), nil
}

func MatchURI(template string, uri string) ([]string, bool) {
	var values []string
	templateOffset := 0
	uriOffset := 0

	for {
		openRelative := strings.IndexByte(template[templateOffset:], '{')
		if openRelative < 0 {
			return values, uri[uriOffset:] == template[templateOffset:]
		}
		open := templateOffset + openRelative
		closeRelative := strings.IndexByte(template[open+1:], '}')
		if closeRelative < 0 {
			return nil, false
		}
		closeIndex := open + 1 + closeRelative
		if closeIndex == open+1 {
			return nil, false
		}

		literal := template[templateOffset:open]
		if !strings.HasPrefix(uri[uriOffset:], literal) {
			return nil, false
		}
		uriOffset += len(literal)
		templateOffset = closeIndex + 1

		nextOpenRelative := strings.IndexByte(template[templateOffset:], '{')
		nextLiteralEnd := len(template)
		if nextOpenRelative >= 0 {
			nextLiteralEnd = templateOffset + nextOpenRelative
		}
		nextLiteral := template[templateOffset:nextLiteralEnd]

		if nextLiteral == "" {
			if nextOpenRelative >= 0 {
				return nil, false
			}
			values = append(values, uri[uriOffset:])
			uriOffset = len(uri)
			continue
		}
		valueEndRelative := strings.Index(uri[uriOffset:], nextLiteral)
		if valueEndRelative < 0 {
			return nil, false
		}
		values = append(values, uri[uriOffset:uriOffset+valueEndRelative])
		uriOffset += valueEndRelative
	}
}

func FuncParamTypes(fnType reflect.Type) []reflect.Type {
	paramTypes := make([]reflect.Type, fnType.NumIn())
	for i := range paramTypes {
		paramTypes[i] = fnType.In(i)
	}
	return paramTypes
}
