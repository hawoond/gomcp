package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hawoond/gomcp/client"
	"github.com/hawoond/gomcp/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestVersionNegotiation_Success(t *testing.T) {
	// Server supports v1 and v2
	s := NewServer("test-version-server", "1.0", false, "", "v1", "v2")
	httpServer := httptest.NewServer(http.HandlerFunc(s.handleMcpRequest()))
	defer httpServer.Close()

	c := client.NewClient()
	c.ConnectHTTP(httpServer.URL)

	// Client requests v2, which is supported
	err := c.Initialize("test-client", "1.0", "v2")
	assert.NoError(t, err)
}

func TestVersionNegotiation_Failure(t *testing.T) {
	// Server only supports v1
	s := NewServer("test-version-server", "1.0", false, "", "v1")
	httpServer := httptest.NewServer(http.HandlerFunc(s.handleMcpRequest()))
	defer httpServer.Close()

	c := client.NewClient()
	c.ConnectHTTP(httpServer.URL)

	// Client requests v3, which is not supported
	err := c.Initialize("test-client", "1.0", "v3")
	assert.Error(t, err)

	// Check if the error is the specific version mismatch error
	assert.Contains(t, err.Error(), "Unsupported protocol version")
	assert.Contains(t, err.Error(), fmt.Sprintf("%d", types.CodeVersionMismatch))
}
