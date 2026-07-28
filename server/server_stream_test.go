package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hawoond/gomcp/client"
	"github.com/hawoond/gomcp/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupStreamServer(t *testing.T) (*Server, *client.Client) {
	t.Helper()
	server := NewServer("stream-server", "1.0", false, "")
	server.EnableExperimentalMethods(true)
	httpServer := httptest.NewServer(http.HandlerFunc(server.handleMcpRequest()))
	t.Cleanup(httpServer.Close)
	mcpClient := client.NewClient()
	mcpClient.ConnectHTTP(httpServer.URL)
	return server, mcpClient
}

func TestStreamTool(t *testing.T) {
	server, mcpClient := setupStreamServer(t)
	require.NoError(t, server.AddTool("streamer", "stream values", func() <-chan string {
		values := make(chan string, 3)
		values <- "one"
		values <- "two"
		values <- "three"
		close(values)
		return values
	}, nil))

	responses, err := mcpClient.ToolStream("streamer", map[string]interface{}{})
	require.NoError(t, err)
	var values []string
	for response := range responses {
		value, ok := response.Result.(string)
		require.True(t, ok)
		values = append(values, value)
	}
	assert.Equal(t, []string{"one", "two", "three"}, values)
}

func TestStreamPrompt(t *testing.T) {
	server, mcpClient := setupStreamServer(t)
	require.NoError(t, server.AddPrompt("streamer", "stream messages", func() <-chan protocol.Message {
		messages := make(chan protocol.Message, 3)
		for _, text := range []string{"one", "two", "three"} {
			messages <- protocol.Message{Role: "user", Content: protocol.Content{Type: "text", Text: text}}
		}
		close(messages)
		return messages
	}, nil))

	responses, err := mcpClient.PromptStream("streamer", map[string]interface{}{})
	require.NoError(t, err)
	var texts []string
	for response := range responses {
		encoded, err := json.Marshal(response.Result)
		require.NoError(t, err)
		var message protocol.Message
		require.NoError(t, json.Unmarshal(encoded, &message))
		texts = append(texts, message.Content.Text)
	}
	assert.Equal(t, []string{"one", "two", "three"}, texts)
}
