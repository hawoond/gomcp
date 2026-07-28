package server

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/hawoond/gomcp/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStdioServerRequestAndLogging(t *testing.T) {
	mcpServer := NewServer("peer-test", "1.0", false, "")
	type input struct{}
	require.NoError(t, RegisterTool(mcpServer, "confirm", "confirm an action", func(ctx context.Context, _ input) (string, error) {
		if err := mcpServer.Log(ctx, "info", "confirm", map[string]string{"state": "started"}); err != nil {
			return "", err
		}
		result, err := mcpServer.Elicit(ctx, protocol.ElicitParams{Mode: "form", Message: "continue?"})
		return result.Action, err
	}))

	serverReader, clientWriter := io.Pipe()
	clientReader, serverWriter := io.Pipe()
	runDone := make(chan error, 1)
	go func() {
		runDone <- mcpServer.RunStdio(serverReader, serverWriter)
	}()
	encoder := json.NewEncoder(clientWriter)
	decoder := json.NewDecoder(clientReader)

	requestID := json.RawMessage(`1`)
	require.NoError(t, encoder.Encode(protocol.Request{
		JSONRPC: "2.0",
		ID:      &requestID,
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","clientInfo":{"name":"test","version":"1"},"capabilities":{"elicitation":{}}}`),
	}))
	var initializeResponse protocol.Response
	require.NoError(t, decoder.Decode(&initializeResponse))
	require.Nil(t, initializeResponse.Error)
	require.NoError(t, encoder.Encode(protocol.Request{JSONRPC: "2.0", Method: "notifications/initialized"}))

	callID := json.RawMessage(`2`)
	require.NoError(t, encoder.Encode(protocol.Request{
		JSONRPC: "2.0",
		ID:      &callID,
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"confirm","arguments":{}}`),
	}))

	logReceived := false
	var toolResponse protocol.Response
	for toolResponse.ID == nil {
		var raw json.RawMessage
		require.NoError(t, decoder.Decode(&raw))
		var request protocol.Request
		if json.Unmarshal(raw, &request) == nil && request.Method != "" {
			switch request.Method {
			case "notifications/message":
				logReceived = true
			case "elicitation/create":
				require.NotNil(t, request.ID)
				require.NoError(t, encoder.Encode(protocol.Response{
					JSONRPC: "2.0",
					ID:      request.ID,
					Result:  protocol.ElicitResult{Action: "accept"},
				}))
			}
			continue
		}
		require.NoError(t, json.Unmarshal(raw, &toolResponse))
	}
	require.Nil(t, toolResponse.Error)
	require.True(t, logReceived)
	encodedResult, err := json.Marshal(toolResponse.Result)
	require.NoError(t, err)
	var result protocol.CallToolResult
	require.NoError(t, json.Unmarshal(encodedResult, &result))
	require.Len(t, result.Content, 1)
	assert.Equal(t, "accept", result.Content[0].Text)

	require.NoError(t, clientWriter.Close())
	select {
	case err := <-runDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("stdio server did not stop")
	}
}

func TestStdioCancellationNotification(t *testing.T) {
	mcpServer := NewServer("cancel-test", "1.0", false, "")
	type input struct{}
	require.NoError(t, RegisterTool(mcpServer, "wait", "wait for cancellation", func(ctx context.Context, _ input) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}))

	serverReader, clientWriter := io.Pipe()
	clientReader, serverWriter := io.Pipe()
	go mcpServer.RunStdio(serverReader, serverWriter)
	encoder := json.NewEncoder(clientWriter)
	decoder := json.NewDecoder(clientReader)

	initializeID := json.RawMessage(`1`)
	require.NoError(t, encoder.Encode(protocol.Request{
		JSONRPC: "2.0",
		ID:      &initializeID,
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","clientInfo":{"name":"test","version":"1"},"capabilities":{}}`),
	}))
	var initializeResponse protocol.Response
	require.NoError(t, decoder.Decode(&initializeResponse))
	require.NoError(t, encoder.Encode(protocol.Request{JSONRPC: "2.0", Method: "notifications/initialized"}))

	callID := json.RawMessage(`2`)
	require.NoError(t, encoder.Encode(protocol.Request{
		JSONRPC: "2.0",
		ID:      &callID,
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"wait","arguments":{}}`),
	}))
	require.NoError(t, encoder.Encode(protocol.Request{
		JSONRPC: "2.0",
		Method:  "notifications/cancelled",
		Params:  json.RawMessage(`{"requestId":2,"reason":"test"}`),
	}))

	var response protocol.Response
	require.NoError(t, decoder.Decode(&response))
	require.Nil(t, response.Error)
	encodedResult, err := json.Marshal(response.Result)
	require.NoError(t, err)
	var result protocol.CallToolResult
	require.NoError(t, json.Unmarshal(encodedResult, &result))
	assert.True(t, result.IsError)
	require.NoError(t, clientWriter.Close())
}
