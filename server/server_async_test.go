package server

import (
	"testing"
	"time"

	"github.com/hawoond/gomcp/client"
	"github.com/stretchr/testify/assert"
)

func TestAsyncToolCall(t *testing.T) {
	// Server setup
	go func() {
		s := NewServer("test-server", "1.0", false, "")
		s.AddTool("long_running_tool", "A tool that takes a while", func() (string, error) {
			time.Sleep(2 * time.Second)
			return "All done!", nil
		}, nil)
		s.ListenAndServe(":8081")
	}()

	// Allow server to start
	time.Sleep(1 * time.Second)

	// Client setup
	c := client.NewClient()
	c.ConnectHTTP("http://localhost:8081")

	// Call the tool asynchronously
	taskID, err := c.CallAsync("long_running_tool", nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, taskID)

	// Check the status while it's running
	initialTask, err := c.GetResult(taskID)
	assert.NoError(t, err)
	assert.NotNil(t, initialTask)
	assert.Equal(t, "running", string(initialTask.Status))

	// Wait for the tool to complete
	time.Sleep(3 * time.Second)

	// Check the final status and result
	finalTask, err := c.GetResult(taskID)
	assert.NoError(t, err)
	assert.NotNil(t, finalTask)
	assert.Equal(t, "completed", string(finalTask.Status))
	assert.Equal(t, "All done!", finalTask.Result)
	assert.Nil(t, finalTask.Error)
}
