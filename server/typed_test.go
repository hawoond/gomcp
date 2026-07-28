package server

import (
	"context"
	"testing"

	"github.com/hawoond/gomcp/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypedToolSchemaAndInvocation(t *testing.T) {
	server, _, mcpClient := setupTestServer(t)
	type input struct {
		Name  string `json:"name" validate:"required"`
		Count *int   `json:"count,omitempty"`
	}
	type output struct {
		Message string `json:"message"`
	}
	require.NoError(t, RegisterTool(server, "greet", "greet a person", func(_ context.Context, value input) (output, error) {
		return output{Message: "hello " + value.Name}, nil
	}))

	tools, err := mcpClient.ListTools()
	require.NoError(t, err)
	require.Len(t, tools, 1)
	schema := tools[0]["inputSchema"].(map[string]interface{})
	assert.Equal(t, []interface{}{"name"}, schema["required"])
	assert.Equal(t, false, schema["additionalProperties"])

	var result protocol.CallToolResult
	require.NoError(t, mcpClient.Call("tools/call", map[string]interface{}{
		"name":      "greet",
		"arguments": map[string]interface{}{"name": "MCP"},
	}, &result))
	assert.False(t, result.IsError)
	assert.Contains(t, result.Content[0].Text, "hello MCP")
}

func TestToolPanicBecomesToolError(t *testing.T) {
	server, _, mcpClient := setupTestServer(t)
	require.NoError(t, server.AddTool("panic", "panic safely", func() string {
		panic("boom")
	}, nil))

	var result protocol.CallToolResult
	require.NoError(t, mcpClient.Call("tools/call", map[string]interface{}{
		"name":      "panic",
		"arguments": map[string]interface{}{},
	}, &result))
	assert.True(t, result.IsError)
	assert.Contains(t, result.Content[0].Text, "panicked")
}

func TestResourceResultAndMultipleTemplateValues(t *testing.T) {
	server, _, mcpClient := setupTestServer(t)
	require.NoError(t, server.AddResource(
		"accounts/{account}/orders/{order}",
		"order details",
		func(account, order string) map[string]string {
			return map[string]string{"account": account, "order": order}
		},
	))

	var result protocol.ReadResourceResult
	require.NoError(t, mcpClient.Call("resources/read", map[string]interface{}{
		"uri": "accounts/acct-1/orders/order-2",
	}, &result))
	require.Len(t, result.Contents, 1)
	assert.Equal(t, "accounts/acct-1/orders/order-2", result.Contents[0].URI)
	assert.Equal(t, "application/json", result.Contents[0].MimeType)
	assert.JSONEq(t, `{"account":"acct-1","order":"order-2"}`, result.Contents[0].Text)
}
