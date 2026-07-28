package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hawoond/gomcp/client"
	"github.com/hawoond/gomcp/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestServer(t *testing.T) (*Server, *httptest.Server, *client.Client) {
	t.Helper()
	server := NewServer("test-server", "1.0", false, "")
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", server.handleMcpRequest())
	mux.HandleFunc("/health", server.healthCheckHandler())
	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)

	mcpClient := client.NewClient()
	mcpClient.ConnectHTTP(httpServer.URL)
	t.Cleanup(func() {
		_ = mcpClient.Close()
	})
	return server, httpServer, mcpClient
}

func TestHealthCheck(t *testing.T) {
	_, httpServer, _ := setupTestServer(t)
	response, err := http.Get(httpServer.URL + "/health")
	require.NoError(t, err)
	defer response.Body.Close()
	assert.Equal(t, http.StatusOK, response.StatusCode)
}

func TestTaskLifecycle(t *testing.T) {
	server, _, mcpClient := setupTestServer(t)
	require.NoError(t, server.AddTool("long_task", "long task", func() string {
		time.Sleep(20 * time.Millisecond)
		return "done"
	}, nil))

	taskID, err := mcpClient.CallAsync("long_task", map[string]interface{}{})
	require.NoError(t, err)
	require.NotEmpty(t, taskID)

	var task *protocol.Task
	require.Eventually(t, func() bool {
		task, err = mcpClient.GetResult(taskID)
		return err == nil && task.Status == protocol.TaskStatusCompleted
	}, time.Second, 10*time.Millisecond)
	require.NotNil(t, task.Result)
}

func TestTaskCancellation(t *testing.T) {
	server, _, mcpClient := setupTestServer(t)
	type input struct{}
	require.NoError(t, RegisterTaskTool(server, "wait", "wait for cancellation", func(ctx context.Context, _ input) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}))

	taskID, err := mcpClient.CallAsync("wait", map[string]interface{}{})
	require.NoError(t, err)
	cancelled, err := mcpClient.CancelTask(taskID)
	require.NoError(t, err)
	assert.Equal(t, protocol.TaskStatusCancelled, cancelled.Status)
}

func TestEventSystemViaHTTP(t *testing.T) {
	server, _, mcpClient := setupTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notifications, err := mcpClient.ListenForNotifications(ctx)
	require.NoError(t, err)

	server.PublishNotification("events/first", map[string]string{"value": "one"})
	server.PublishNotification("events/second", map[string]string{"value": "two"})

	received := make([]protocol.Request, 0, 2)
	timeout := time.After(time.Second)
	for len(received) < 2 {
		select {
		case notification := <-notifications:
			received = append(received, notification)
		case <-timeout:
			t.Fatal("timed out waiting for notifications")
		}
	}
	assert.ElementsMatch(t, []string{"events/first", "events/second"}, []string{received[0].Method, received[1].Method})
}
