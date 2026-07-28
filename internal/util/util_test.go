package util

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertTypeNumbers(t *testing.T) {
	int64Value, err := ConvertType(float64(42), reflect.TypeOf(int64(0)))
	require.NoError(t, err)
	assert.Equal(t, int64(42), int64Value.Interface())

	int8Value, err := ConvertType(float64(127), reflect.TypeOf(int8(0)))
	require.NoError(t, err)
	assert.Equal(t, int8(127), int8Value.Interface())

	_, err = ConvertType(float64(128), reflect.TypeOf(int8(0)))
	require.Error(t, err)

	_, err = ConvertType(1.5, reflect.TypeOf(int(0)))
	require.Error(t, err)
}

func TestConvertTypeComposite(t *testing.T) {
	type input struct {
		Name string `json:"name"`
	}
	value, err := ConvertType(map[string]interface{}{"name": "test"}, reflect.TypeOf(input{}))
	require.NoError(t, err)
	assert.Equal(t, input{Name: "test"}, value.Interface())
}

func TestMatchURI(t *testing.T) {
	values, matched := MatchURI("accounts/{account}/orders/{order}", "accounts/acct-1/orders/order-2")
	require.True(t, matched)
	assert.Equal(t, []string{"acct-1", "order-2"}, values)

	_, matched = MatchURI("accounts/{account}/orders/{order}", "accounts/acct-1/products/order-2")
	assert.False(t, matched)

	_, matched = MatchURI("invalid/{}/template", "invalid/value/template")
	assert.False(t, matched)
}

func FuzzMatchURI(f *testing.F) {
	f.Add("resource/{id}", "resource/123")
	f.Add("accounts/{account}/orders/{order}", "accounts/a/orders/b")
	f.Fuzz(func(t *testing.T, template, uri string) {
		values, matched := MatchURI(template, uri)
		if matched && values == nil && template != uri {
			t.Fatalf("matched template without values: %q %q", template, uri)
		}
	})
}
