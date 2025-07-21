package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hawoond/gomcp/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Test Setup ---

func setupTestServer(t *testing.T) (*Server, *httptest.Server) {
	srv := NewServer("FeatureTestApp", "1.0.0", false, "")
	// Use a custom mux to gain more control for testing
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", srv.handleMcpRequest())
	mux.HandleFunc("/health", srv.healthCheckHandler())

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return srv, ts
}

// --- Feature Tests ---

func TestHealthCheck(t *testing.T) {
	_, ts := setupTestServer(t)
	resp, err := http.Get(ts.URL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "OK", string(body))
}

func TestAsyncToolCall(t *testing.T) {
	srv, ts := setupTestServer(t)

	srv.AddTool("long_task", "A task that takes time", func() string {
		time.Sleep(50 * time.Millisecond)
		return "done"
	}, nil)

	// 1. Call the tool asynchronously
	callReqBody := `{"jsonrpc":"2.0","id":"async1","method":"tools/call_async","params":{"name":"long_task","arguments":{}}}`
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(callReqBody))
	require.NoError(t, err)

	var callResp types.Response
	json.NewDecoder(resp.Body).Decode(&callResp)
	require.Nil(t, callResp.Error)
	resultMap, ok := callResp.Result.(map[string]interface{})
	require.True(t, ok)
	taskID, ok := resultMap["taskId"].(string)
	require.True(t, ok)

	// 2. Poll for the result
	getResultBody := fmt.Sprintf(`{"jsonrpc":"2.0","id":"getres1","method":"tools/get_result","params":{"taskId":"%s"}}`, taskID)
	var taskResp types.Response

	require.Eventually(t, func() bool {
		resp, err = http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(getResultBody))
		require.NoError(t, err)
		json.NewDecoder(resp.Body).Decode(&taskResp)
		require.Nil(t, taskResp.Error)
		task, _ := taskResp.Result.(map[string]interface{})
		return task["status"] == string(types.TaskStatusCompleted)
	}, 2*time.Second, 100*time.Millisecond, "Task did not complete in time")

	task, _ := taskResp.Result.(map[string]interface{})
	assert.Equal(t, "done", task["result"].(string))
}

func TestEventSystemViaHTTP(t *testing.T) {
	srv, ts := setupTestServer(t)

	// Add a tool that will be called to trigger notifications
	srv.AddTool("event_generator", "Generates events", func() string {
		time.Sleep(50 * time.Millisecond)
		return "event_done"
	}, nil)

	// --- Setup SSE Client ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create the SSE request
	initReq, _ := http.NewRequestWithContext(ctx, "POST", ts.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":"init1","method":"initialize","params":{"protocolVersion":"2024-11-05"}}`))
	initReq.Header.Set("Accept", "text/event-stream")
	initReq.Header.Set("Content-Type", "application/json")

	// Channel to receive notifications on
	notificationChan := make(chan types.Task, 2) // Buffer for 2 tasks
	var wg sync.WaitGroup
	wg.Add(1)

	// Goroutine to listen for SSE events
	go func() {
		defer wg.Done()
		resp, err := http.DefaultClient.Do(initReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data:") {
				data := strings.TrimPrefix(line, "data: ")
				var notification types.Request
				if json.Unmarshal([]byte(data), &notification) == nil {
					if notification.Method == "events/taskStatusChanged" {
						var task types.Task
						if json.Unmarshal(notification.Params, &task) == nil {
							notificationChan <- task
						}
					}
				}
			}
		}
	}()

	// --- Trigger Event ---
	// Give the SSE client a moment to connect before triggering the event
	time.Sleep(100 * time.Millisecond)

	// Make a separate, non-SSE call to trigger the async task
	callReqBody := `{"jsonrpc":"2.0","id":"event_call","method":"tools/call_async","params":{"name":"event_generator","arguments":{}}}`
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(callReqBody))
	require.NoError(t, err)
	resp.Body.Close()

	// --- Verification ---
	var receivedTasks []types.Task
	timeout := time.After(2 * time.Second)
	for i := 0; i < 2; i++ { // We expect 2 notifications
		select {
		case task := <-notificationChan:
			receivedTasks = append(receivedTasks, task)
		case <-timeout:
			t.Fatal("timed out waiting for notifications")
		}
	}

	// Stop the listening goroutine
	cancel()
	wg.Wait()

	// Verify the received notifications (order is not guaranteed)
	assert.Len(t, receivedTasks, 2)
	var hasRunning, hasCompleted bool
	for _, task := range receivedTasks {
		if task.Status == types.TaskStatusRunning {
			hasRunning = true
		}
		if task.Status == types.TaskStatusCompleted {
			hasCompleted = true
			assert.Equal(t, "event_done", task.Result)
		}
	}

	assert.True(t, hasRunning, "Did not receive 'running' status notification")
	assert.True(t, hasCompleted, "Did not receive 'completed' status notification")
}
