package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hawoond/gomcp/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionNegotiationUsesRequestedSupportedVersion(t *testing.T) {
	server := NewServer("version-server", "1.0", false, "", "v2", "v1")
	httpServer := httptest.NewServer(http.HandlerFunc(server.handleMcpRequest()))
	defer httpServer.Close()

	mcpClient := client.NewClient()
	mcpClient.ConnectHTTP(httpServer.URL)
	require.NoError(t, mcpClient.Initialize("test-client", "1.0", "v1"))
	assert.Equal(t, "v1", mcpClient.ProtocolVersion())
}

func TestVersionNegotiationFallsBackToServerPreference(t *testing.T) {
	server := NewServer("version-server", "1.0", false, "", "v2", "v1")
	httpServer := httptest.NewServer(http.HandlerFunc(server.handleMcpRequest()))
	defer httpServer.Close()

	mcpClient := client.NewClient()
	mcpClient.ConnectHTTP(httpServer.URL)
	require.NoError(t, mcpClient.Initialize("test-client", "1.0", "v3"))
	assert.Equal(t, "v2", mcpClient.ProtocolVersion())
}
