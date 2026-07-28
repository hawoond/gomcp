package client_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/hawoond/gomcp/client"
	"github.com/hawoond/gomcp/protocol"
	"github.com/hawoond/gomcp/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConcurrentHTTPCalls(t *testing.T) {
	mcpServer := server.NewServer("client-test", "1.0", false, "")
	require.NoError(t, mcpServer.AddTool("double", "double a value", func(value int) int {
		return value * 2
	}, nil, "value"))
	httpServer := httptest.NewServer(mcpServer.Handler())
	defer httpServer.Close()

	mcpClient := client.NewClient()
	mcpClient.ConnectHTTP(httpServer.URL)

	var waitGroup sync.WaitGroup
	errors := make(chan error, 32)
	for value := 0; value < 32; value++ {
		value := value
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			var result protocol.CallToolResult
			err := mcpClient.Call("tools/call", map[string]interface{}{
				"name":      "double",
				"arguments": map[string]interface{}{"value": value},
			}, &result)
			if err != nil {
				errors <- err
				return
			}
			if result.Content[0].Text != fmt.Sprintf("%d", value*2) {
				errors <- fmt.Errorf("unexpected result %q", result.Content[0].Text)
			}
		}()
	}
	waitGroup.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
}

func TestCallContextCancellation(t *testing.T) {
	mcpServer := server.NewServer("client-test", "1.0", false, "")
	type input struct{}
	require.NoError(t, server.RegisterTool(mcpServer, "wait", "wait for context", func(ctx context.Context, _ input) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}))
	httpServer := httptest.NewServer(mcpServer.Handler())
	defer httpServer.Close()

	mcpClient := client.NewClient()
	mcpClient.ConnectHTTP(httpServer.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	var result protocol.CallToolResult
	err := mcpClient.CallContext(ctx, "tools/call", map[string]interface{}{
		"name":      "wait",
		"arguments": map[string]interface{}{},
	}, &result)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestResponseLimit(t *testing.T) {
	mcpServer := server.NewServer("client-test", "1.0", false, "")
	require.NoError(t, mcpServer.AddTool("large", "large result", func() string {
		return string(make([]byte, 2048))
	}, nil))
	httpServer := httptest.NewServer(mcpServer.Handler())
	defer httpServer.Close()

	mcpClient := client.NewClient()
	require.NoError(t, mcpClient.SetResponseLimit(512))
	mcpClient.ConnectHTTP(httpServer.URL)

	var result protocol.CallToolResult
	err := mcpClient.Call("tools/call", map[string]interface{}{
		"name":      "large",
		"arguments": map[string]interface{}{},
	}, &result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}
