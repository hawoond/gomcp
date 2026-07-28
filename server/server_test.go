package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hawoond/gomcp/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPTransport(t *testing.T) {
	server, _, mcpClient := setupTestServer(t)
	require.NoError(t, server.AddTool("add", "add numbers", func(a int, b int) int {
		return a + b
	}, nil, "a", "b"))

	var result protocol.CallToolResult
	require.NoError(t, mcpClient.Call("tools/call", map[string]interface{}{
		"name":      "add",
		"arguments": map[string]interface{}{"a": 2, "b": 3},
	}, &result))
	require.Len(t, result.Content, 1)
	assert.Equal(t, "5", result.Content[0].Text)
	assert.Equal(t, float64(5), result.StructuredContent)
}

func TestStreamableHTTPRequiresInitialization(t *testing.T) {
	server := NewServer("test-server", "1.0", false, "")
	httpServer := httptest.NewServer(http.HandlerFunc(server.handleMcpRequest()))
	defer httpServer.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	request, err := http.NewRequest(http.MethodPost, httpServer.URL, strings.NewReader(body))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
}

func TestStreamableHTTPAcceptsNotifications(t *testing.T) {
	_, _, mcpClient := setupTestServer(t)
	require.NoError(t, mcpClient.Notify("notifications/cancelled", map[string]interface{}{
		"requestId": 42,
		"reason":    "test",
	}))
}

func TestHTTPOriginValidation(t *testing.T) {
	server := NewServer("test-server", "1.0", false, "")
	httpServer := httptest.NewServer(http.HandlerFunc(server.handleMcpRequest()))
	defer httpServer.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"test","version":"1"},"capabilities":{}}}`
	request, err := http.NewRequest(http.MethodPost, httpServer.URL, strings.NewReader(body))
	require.NoError(t, err)
	request.Header.Set("Origin", "https://example.invalid")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	assert.Equal(t, http.StatusForbidden, response.StatusCode)
}

func TestHTTPRequestLimit(t *testing.T) {
	server := NewServer("test-server", "1.0", false, "")
	require.NoError(t, server.SetLimits(128, 1024))
	httpServer := httptest.NewServer(http.HandlerFunc(server.handleMcpRequest()))
	defer httpServer.Close()

	request, err := http.NewRequest(http.MethodPost, httpServer.URL, bytes.NewReader(bytes.Repeat([]byte("x"), 256)))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
}
