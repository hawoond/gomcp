package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hawoond/gomcp/client"
	"github.com/hawoond/gomcp/internal/types"
	"github.com/hawoond/gomcp/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteMutationDisabledByDefault(t *testing.T) {
	server := NewServer("test-server", "1.0", false, "")
	require.NoError(t, server.AddTool("tool1", "desc1", func() string { return "one" }, nil))
	require.NoError(t, server.AddPrompt("prompt1", "desc1", func() string { return "one" }, nil))
	require.NoError(t, server.AddResource("res://a", "desc", func() string { return "one" }))

	httpServer := httptest.NewServer(http.HandlerFunc(server.handleMcpRequest()))
	defer httpServer.Close()

	mcpClient := client.NewClient()
	mcpClient.ConnectHTTP(httpServer.URL)

	assert.Error(t, mcpClient.UnregisterTool("tool1"))
	assert.Error(t, mcpClient.UnregisterPrompt("prompt1"))
	assert.Error(t, mcpClient.UnregisterResource("res://a"))

	tools, err := mcpClient.ListTools()
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Equal(t, "tool1", tools[0]["name"])

	prompts, err := mcpClient.ListPrompts()
	require.NoError(t, err)
	require.Len(t, prompts, 1)
	assert.Equal(t, "prompt1", prompts[0]["name"])

	resources, err := mcpClient.ListResources()
	require.NoError(t, err)
	require.Len(t, resources, 1)
	assert.Equal(t, "res://a", resources[0]["uri"])
}

func TestExperimentalDynamicToolUsesSeparateRegistry(t *testing.T) {
	server := NewServer("test-server", "1.0", false, "")
	server.EnableExperimentalMethods(true)
	require.NoError(t, server.AddDynamicTool(types.ToolDefinition{
		Name:        "dynamic",
		Description: "dynamic command",
		Type:        "command",
		Command:     &types.CommandConfig{Path: "echo"},
	}))

	httpServer := httptest.NewServer(http.HandlerFunc(server.handleMcpRequest()))
	defer httpServer.Close()

	mcpClient := client.NewClient()
	mcpClient.ConnectHTTP(httpServer.URL)

	var result protocol.CallToolResult
	require.NoError(t, mcpClient.Call("tools/call", map[string]interface{}{
		"name":      "dynamic",
		"arguments": map[string]interface{}{},
	}, &result))
	assert.True(t, result.IsError)
	assert.Contains(t, result.Content[0].Text, "allowlisted")

	require.NoError(t, mcpClient.UnregisterTool("dynamic"))
	tools, err := mcpClient.ListTools()
	require.NoError(t, err)
	assert.Empty(t, tools)
}
