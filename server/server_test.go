package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hawoond/gomcp/internal/types"
)

func TestHTTPTransport(t *testing.T) {
	srv := NewServer("TestApp", "0.1.0", false, "")
	type AddParams struct {
		A int `validate:"required"`
		B int `validate:"required"`
	}
	srv.AddTool("add", "Adds two integers", func(a int, b int) int {
		return a + b
	}, AddParams{}, "a", "b")

	// Create a test HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.handleMcpRequest().ServeHTTP(w, r)
	}))
	defer ts.Close()

	// Simulate a tools/call request over HTTP
	reqBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add","arguments":{"a":10,"b":20}}}`
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("Failed to send HTTP request: %v", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	var jsonRpcResp types.Response
	if err := json.Unmarshal(respBytes, &jsonRpcResp); err != nil {
		t.Fatalf("Failed to unmarshal JSON-RPC response: %v", err)
	}

	if jsonRpcResp.Error != nil {
		t.Errorf("Expected no error, got: %+v", jsonRpcResp.Error)
	}

	expectedResult := float64(30) // JSON numbers are often float64
	if jsonRpcResp.Result != expectedResult {
		t.Errorf("Expected result %v, got %v", expectedResult, jsonRpcResp.Result)
	}

	// Test with authentication enabled
	srvAuth := NewServer("TestAppAuth", "0.1.0", true, "test-api-key")
	srvAuth.AddTool("add", "Adds two integers", func(a int, b int) int {
		return a + b
	}, AddParams{}, "a", "b")

	tsAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srvAuth.authMiddleware(srvAuth.handleMcpRequest()).ServeHTTP(w, r)
	}))
	defer tsAuth.Close()

	// Test unauthorized request
	respUnauthorized, err := http.Post(tsAuth.URL+"/mcp", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("Failed to send unauthorized HTTP request: %v", err)
	}
	defer respUnauthorized.Body.Close()

	if respUnauthorized.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, respUnauthorized.StatusCode)
	}

	// Test authorized request
	req, err := http.NewRequest("POST", tsAuth.URL+"/mcp", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("Failed to create authorized HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")

	respAuthorized, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send authorized HTTP request: %v", err)
	}
	defer respAuthorized.Body.Close()

	if respAuthorized.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, respAuthorized.StatusCode)
	}

	respBytesAuthorized, err := io.ReadAll(respAuthorized.Body)
	if err != nil {
		t.Fatalf("Failed to read authorized response body: %v", err)
	}

	var jsonRpcRespAuthorized types.Response
	if err := json.Unmarshal(respBytesAuthorized, &jsonRpcRespAuthorized); err != nil {
		t.Fatalf("Failed to unmarshal authorized JSON-RPC response: %v", err)
	}

	if jsonRpcRespAuthorized.Error != nil {
		t.Errorf("Expected no error, got: %+v", jsonRpcRespAuthorized.Error)
	}

	if jsonRpcRespAuthorized.Result != expectedResult {
		t.Errorf("Expected result %v, got %v", expectedResult, jsonRpcRespAuthorized.Result)
	}
}
