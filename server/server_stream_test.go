package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hawoond/gomcp/client"
	"github.com/hawoond/gomcp/internal/types"
	"github.com/stretchr/testify/assert"
)

func streamTool(name string) chan types.Content {
	ch := make(chan types.Content)
	go func() {
		defer close(ch)
		for i := 0; i < 3; i++ {
			time.Sleep(10 * time.Millisecond)
			ch <- types.Content{
				Type:      "text",
				Text:      fmt.Sprintf("Hello %s, part %d", name, i),
				IsPartial: true,
			}
		}
	}	()
	return ch
}

func streamPrompt(name string) chan types.Message {
	ch := make(chan types.Message)
	go func() {
		defer close(ch)
		for i := 0; i < 3; i++ {
			time.Sleep(10 * time.Millisecond)
			ch <- types.Message{
				Role: "user",
				Content: types.Content{
					Type:      "text",
					Text:      fmt.Sprintf("Hello %s, part %d", name, i),
					IsPartial: true,
				},
			}
		}
	}()
	return ch
}

func TestStreamTool(t *testing.T) {
	s := NewServer("test-stream-server", "1.0", false, "")
	err := s.AddTool("streamer", "A streaming tool", streamTool, nil, "name")
	assert.NoError(t, err)

	httpServer := httptest.NewServer(http.HandlerFunc(s.handleMcpRequest()))
	defer httpServer.Close()

	c := client.NewClient()
	c.ConnectHTTP(httpServer.URL)

	args := map[string]interface{}{"name": "Streamy"}
	respCh, err := c.ToolStream("streamer", args)
	assert.NoError(t, err)

	var responses []types.Response
	for resp := range respCh {
		responses = append(responses, resp)
	}

	assert.Equal(t, 3, len(responses))

	for i, resp := range responses {
		assert.Nil(t, resp.Error)
		content, ok := resp.Result.(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, "text", content["type"])
		assert.Equal(t, fmt.Sprintf("Hello Streamy, part %d", i), content["text"])
		assert.Equal(t, true, content["isPartial"])
	}
}

func TestStreamPrompt(t *testing.T) {
	s := NewServer("test-stream-prompt-server", "1.0", false, "")
	err := s.AddPrompt("streamer", "A streaming prompt", streamPrompt, nil, "name")
	assert.NoError(t, err)

	httpServer := httptest.NewServer(http.HandlerFunc(s.handleMcpRequest()))
	defer httpServer.Close()

	c := client.NewClient()
	c.ConnectHTTP(httpServer.URL)

	args := map[string]interface{}{"name": "Streamy"}
	respCh, err := c.PromptStream("streamer", args)
	assert.NoError(t, err)

	var responses []types.Response
	for resp := range respCh {
		responses = append(responses, resp)
	}

	assert.Equal(t, 3, len(responses))

	for i, resp := range responses {
		assert.Nil(t, resp.Error)
		msg, ok := resp.Result.(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, "user", msg["role"])
		content := msg["content"].(map[string]interface{})
		assert.Equal(t, "text", content["type"])
		assert.Equal(t, fmt.Sprintf("Hello Streamy, part %d", i), content["text"])
		assert.Equal(t, true, content["isPartial"])
	}
}