package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hawoond/gomcp/client"
	"github.com/stretchr/testify/assert"
)

func TestDynamicUnregister(t *testing.T) {
	s := NewServer("test-dynamic-server", "1.0", false, "")

	// Register some tools, prompts, and resources
	_ = s.AddTool("tool1", "desc1", func() {}, nil)
	_ = s.AddTool("tool2", "desc2", func() {}, nil)
	_ = s.AddPrompt("prompt1", "desc1", func() {}, nil)
	_ = s.AddPrompt("prompt2", "desc2", func() {}, nil)
	_ = s.AddResource("res://a", "desc_a", func() {})
	_ = s.AddResource("res://b", "desc_b", func() {})

	httpServer := httptest.NewServer(http.HandlerFunc(s.handleMcpRequest()))
	defer httpServer.Close()

	c := client.NewClient()
	c.ConnectHTTP(httpServer.URL)

	// 1. Unregister tool1
	err := c.UnregisterTool("tool1")
	assert.NoError(t, err)

	// Verify tool1 is gone
	tools, err := c.ListTools()
	assert.NoError(t, err)
	assert.Equal(t, 1, len(tools))
	assert.Equal(t, "tool2", tools[0]["name"])

	// Try to call tool1, should fail
	err = c.Call("tools/call", map[string]interface{}{"name": "tool1"}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Tool not found")

	// 2. Unregister prompt1
	err = c.UnregisterPrompt("prompt1")
	assert.NoError(t, err)

	// Verify prompt1 is gone
	prompts, err := c.ListPrompts()
	assert.NoError(t, err)
	assert.Equal(t, 1, len(prompts))
	assert.Equal(t, "prompt2", prompts[0]["name"])

	// 3. Unregister res://a
	err = c.UnregisterResource("res://a")
	assert.NoError(t, err)

	// Verify res://a is gone
	resources, err := c.ListResources()
	assert.NoError(t, err)
	assert.Equal(t, 1, len(resources))
	assert.Equal(t, "res://b", resources[0]["uri"])

	// Try to read res://a, should fail
	err = c.Call("resources/read", map[string]interface{}{"uri": "res://a"}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Resource not found")
}