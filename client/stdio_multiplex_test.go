package client_test

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hawoond/gomcp/client"
	"github.com/hawoond/gomcp/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStdioMultiplexHelper(t *testing.T) {
	if !slices.Contains(os.Args, "--stdio-multiplex-helper") {
		return
	}
	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	var initialize protocol.Request
	if decoder.Decode(&initialize) != nil {
		os.Exit(2)
	}
	_ = encoder.Encode(protocol.Response{
		JSONRPC: "2.0",
		ID:      initialize.ID,
		Result: map[string]interface{}{
			"protocolVersion": protocol.LatestProtocolVersion,
			"capabilities":    map[string]interface{}{},
			"serverInfo":      map[string]string{"name": "helper", "version": "1"},
		},
	})

	var calls []protocol.Request
	elicitationSent := false
	elicitationAnswered := false
	for len(calls) < 2 || !elicitationAnswered {
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			os.Exit(3)
		}
		var request protocol.Request
		if json.Unmarshal(raw, &request) == nil && request.Method != "" {
			if request.ID == nil {
				continue
			}
			calls = append(calls, request)
			if !elicitationSent {
				elicitationSent = true
				serverRequestID := json.RawMessage(`"server-1"`)
				_ = encoder.Encode(protocol.Request{
					JSONRPC: "2.0",
					ID:      &serverRequestID,
					Method:  "elicitation/create",
					Params:  json.RawMessage(`{"mode":"form","message":"confirm"}`),
				})
			}
			continue
		}
		var response protocol.Response
		if json.Unmarshal(raw, &response) == nil && response.ID != nil && string(*response.ID) == `"server-1"` {
			elicitationAnswered = response.Error == nil
		}
	}

	for index := len(calls) - 1; index >= 0; index-- {
		var params struct {
			Value string `json:"value"`
		}
		_ = json.Unmarshal(calls[index].Params, &params)
		_ = encoder.Encode(protocol.Response{JSONRPC: "2.0", ID: calls[index].ID, Result: params.Value})
	}
	os.Exit(0)
}

func TestConcurrentStdioCallsAndServerRequests(t *testing.T) {
	mcpClient := client.NewClient()
	require.NoError(t, mcpClient.StartProcess(
		os.Args[0],
		"-test.run=TestStdioMultiplexHelper",
		"--",
		"--stdio-multiplex-helper",
	))
	defer mcpClient.StopProcess()

	elicitation := make(chan protocol.ElicitParams, 1)
	mcpClient.HandleElicitation(func(_ context.Context, params protocol.ElicitParams) (protocol.ElicitResult, error) {
		elicitation <- params
		return protocol.ElicitResult{Action: "accept"}, nil
	})

	values := []string{"first", "second"}
	results := make([]string, len(values))
	errors := make([]error, len(values))
	var waitGroup sync.WaitGroup
	for index, value := range values {
		waitGroup.Add(1)
		go func(index int, value string) {
			defer waitGroup.Done()
			errors[index] = mcpClient.Call("echo", map[string]string{"value": value}, &results[index])
		}(index, value)
	}
	finished := make(chan struct{})
	go func() {
		waitGroup.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent stdio calls were serialized")
	}
	require.NoError(t, errors[0])
	require.NoError(t, errors[1])
	assert.Equal(t, values, results)
	select {
	case request := <-elicitation:
		assert.Equal(t, "confirm", request.Message)
	case <-time.After(time.Second):
		t.Fatal("elicitation request was not handled")
	}
}
