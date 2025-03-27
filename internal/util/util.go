package util

import (
	"fmt"
	"io"
	"reflect"
	"strings"
)

func BytesReader(b []byte) io.Reader {
	return &byteReader{data: b}
}

type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func ConvertType(val interface{}, t reflect.Type) (reflect.Value, error) {
	rv := reflect.ValueOf(val)
	if rv.IsValid() && rv.Type().AssignableTo(t) {
		return rv, nil
	}
	switch t.Kind() {
	case reflect.Int, reflect.Int64:
		if f, ok := val.(float64); ok {
			return reflect.ValueOf(int(f)), nil
		}
	case reflect.Float32, reflect.Float64:
		if f, ok := val.(float64); ok {
			return reflect.ValueOf(f).Convert(t), nil
		}
	case reflect.Bool:
		if b, ok := val.(bool); ok {
			return reflect.ValueOf(b), nil
		}
	case reflect.String:
		if s, ok := val.(string); ok {
			return reflect.ValueOf(s), nil
		}
	}

	return reflect.Value{}, fmt.Errorf("cannot convert %v to %s", val, t.Name())
}

func MatchURI(template string, uri string) ([]string, bool) {
	tmplParts := strings.Split(template, "{")
	if len(tmplParts) == 1 {
		if template == uri {
			return nil, true
		}
		return nil, false
	}
	prefix := tmplParts[0]
	suffixPart := tmplParts[1]
	suffixIdx := strings.LastIndex(suffixPart, "}")
	suffix := ""
	if suffixIdx != -1 {
		suffix = suffixPart[suffixIdx+1:]
	}
	if strings.HasPrefix(uri, prefix) && strings.HasSuffix(uri, suffix) {
		inner := uri[len(prefix) : len(uri)-len(suffix)]
		return []string{inner}, true
	}
	return nil, false
}

func FuncParamTypes(fnType reflect.Type) []reflect.Type {
	paramTypes := []reflect.Type{}
	for i := 0; i < fnType.NumIn(); i++ {
		paramTypes = append(paramTypes, fnType.In(i))
	}
	return paramTypes
}
