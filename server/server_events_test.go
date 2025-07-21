package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/hawoond/gomcp/client"
	"github.com/hawoond/gomcp/internal/types"
	"github.com/stretchr/testify/assert"
)

// longRunningTool simulates a tool that takes some time to complete.
func longRunningTool(name string) (string, error) {
	time.Sleep(100 * time.Millisecond) // Simulate work
	return "Hello, " + name, nil
}

func TestEventSystemForAsyncTasks(t *testing.T) {
	s := NewServer("test-events-server", "1.0", false, "")
	err := s.AddTool("long_runner", "A tool that runs for a while", longRunningTool, nil, "name")
	assert.NoError(t, err)

	httpServer := httptest.NewServer(http.HandlerFunc(s.handleMcpRequest()))
	defer httpServer.Close()

	c := client.NewClient()
	c.ConnectHTTP(httpServer.URL)

	var wg sync.WaitGroup
	wg.Add(2) // Expecting two notifications: running and completed

	var receivedTasks []types.Task
	notificationHandler := func(method string, params json.RawMessage) {
		assert.Equal(t, "events/taskStatusChanged", method)
		var task types.Task
		err := json.Unmarshal(params, &task)
		assert.NoError(t, err)
		receivedTasks = append(receivedTasks, task)
		wg.Done()
	}
	c.HandleNotifications(notificationHandler)

	// We need to make a streaming call to keep the connection open for notifications
	// The actual response of this call is not important for this test.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notificationCh, err := c.ListenForNotifications(ctx)
	assert.NoError(t, err)

	var notificationWg sync.WaitGroup
	notificationWg.Add(1) // For the notification consumer goroutine

	go func() {
		defer notificationWg.Done()
		for notification := range notificationCh {
			// Process notifications here if needed for the test
			// For this test, we are primarily interested in the taskStatusChanged event
			if notification.Method == "events/taskStatusChanged" {
				var task types.Task
				err := json.Unmarshal(notification.Params, &task)
				assert.NoError(t, err)
				receivedTasks = append(receivedTasks, task)
				wg.Done()
			}
		}
	}()

	// Ensure the notification consumer goroutine has started before proceeding
	// This is a bit of a hack, but ensures the channel is being listened to.
	time.Sleep(10 * time.Millisecond)

	// Now, call the async tool
	args := map[string]interface{}{"name": "Event Tester"}
	taskID, err := c.CallAsync("long_runner", args)
	assert.NoError(t, err)
	assert.NotEmpty(t, taskID)

	// Wait for notifications to be received
	waitChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitChan)
	}()

	select {
	case <-waitChan:
		// All good
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for notifications")
	}

	// After the main test logic, cancel the context to stop the notification listener
	cancel()
	notificationWg.Wait() // Wait for the notification consumer goroutine to finish

	assert.Equal(t, 2, len(receivedTasks))

	// Check the 'running' notification
	assert.Equal(t, taskID, receivedTasks[0].ID)
	assert.Equal(t, types.TaskStatusRunning, receivedTasks[0].Status)

	// Check the 'completed' notification
	assert.Equal(t, taskID, receivedTasks[1].ID)
	assert.Equal(t, types.TaskStatusCompleted, receivedTasks[1].Status)
	assert.Equal(t, "Hello, Event Tester", receivedTasks[1].Result)
}
