package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/hawoond/gomcp/client"
	"github.com/hawoond/gomcp/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestStreamToolCall(t *testing.T) {
	// Server setup
	go func() {
		s := NewServer("test-stream-server", "1.0", false, "")
		s.AddTool("streaming_tool", "A tool that streams results", func() (<-chan types.Content, error) {
			ch := make(chan types.Content)
			go func() {
				defer close(ch)
				for i := 0; i < 3; i++ {
					ch <- types.Content{Type: "text", Text: fmt.Sprintf("Chunk %d", i), IsPartial: true}
					time.Sleep(50 * time.Millisecond)
				}
			}()
			return ch, nil
		}, nil)
		s.ListenAndServe(":8082")
	}()

	// Allow server to start
	time.Sleep(1 * time.Second)

	// Client setup
	c := client.NewClient()
	c.ConnectHTTP("http://localhost:8082")

	// Call the tool with streaming
	params := map[string]interface{}{
		"name": "streaming_tool",
	}
	respCh, err := c.CallStream("tools/call_stream", params)
	assert.NoError(t, err)
	assert.NotNil(t, respCh)

	var responses []types.Response
	for resp := range respCh {
		responses = append(responses, resp)
	}

	assert.Len(t, responses, 3)

	for i, resp := range responses {
		assert.Nil(t, resp.Error)
		content, ok := resp.Result.(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, "text", content["type"])
		assert.Equal(t, fmt.Sprintf("Chunk %d", i), content["text"])
		assert.Equal(t, true, content["isPartial"])
	}
}

