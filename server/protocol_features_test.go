package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hawoond/gomcp/auth"
	"github.com/hawoond/gomcp/client"
	"github.com/hawoond/gomcp/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPaginatedDiscoveryAndResourceTemplates(t *testing.T) {
	mcpServer, _, mcpClient := setupTestServer(t)
	require.NoError(t, mcpServer.SetPageSize(2))
	for _, name := range []string{"alpha", "bravo", "charlie", "delta", "echo"} {
		require.NoError(t, mcpServer.AddTool(name, name, func() string { return name }, nil))
	}
	require.NoError(t, mcpServer.AddResource("config://current", "current config", func() string { return "ok" }))
	require.NoError(t, mcpServer.AddResource("users://{id}", "user", func(id string) string { return id }))

	tools, err := mcpClient.ListTools()
	require.NoError(t, err)
	require.Len(t, tools, 5)
	assert.Equal(t, "alpha", tools[0]["name"])
	assert.NotNil(t, tools[0]["outputSchema"])

	resources, err := mcpClient.ListResources()
	require.NoError(t, err)
	require.Len(t, resources, 1)
	assert.Equal(t, "config://current", resources[0]["uri"])

	templates, err := mcpClient.ListResourceTemplates()
	require.NoError(t, err)
	require.Len(t, templates, 1)
	assert.Equal(t, "users://{id}", templates[0].URITemplate)

	var result protocol.ListToolsResult
	err = mcpClient.Call("tools/list", map[string]interface{}{"cursor": "invalid"}, &result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid cursor")
}

func TestCompletionHandler(t *testing.T) {
	mcpServer, _, mcpClient := setupTestServer(t)
	mcpServer.SetCompletionHandler(func(_ context.Context, params protocol.CompleteParams) (protocol.CompleteResult, error) {
		return protocol.CompleteResult{
			Completion: protocol.Completion{Values: []string{params.Argument.Value + "-one"}},
		}, nil
	})

	var result protocol.CompleteResult
	err := mcpClient.Call("completion/complete", protocol.CompleteParams{
		Ref:      map[string]interface{}{"type": "ref/prompt", "name": "search"},
		Argument: protocol.CompleteArgument{Name: "query", Value: "go"},
	}, &result)
	require.NoError(t, err)
	assert.Equal(t, []string{"go-one"}, result.Completion.Values)
}

func TestResourceNotificationsAreSessionScopedAndReplayable(t *testing.T) {
	mcpServer := NewServer("session-test", "1.0", false, "")
	httpServer := httptest.NewServer(mcpServer.Handler())
	defer httpServer.Close()

	firstClient := client.NewClient()
	firstClient.ConnectHTTP(httpServer.URL)
	secondClient := client.NewClient()
	secondClient.ConnectHTTP(httpServer.URL)

	firstContext, cancelFirst := context.WithCancel(context.Background())
	firstNotifications, err := firstClient.ListenForNotifications(firstContext)
	require.NoError(t, err)
	secondContext, cancelSecond := context.WithCancel(context.Background())
	secondNotifications, err := secondClient.ListenForNotifications(secondContext)
	require.NoError(t, err)
	defer cancelSecond()

	require.NoError(t, firstClient.Notify("resources/subscribe", map[string]string{"uri": "config://current"}))
	mcpServer.NotifyResourceUpdated("config://current")

	select {
	case notification := <-firstNotifications:
		assert.Equal(t, "notifications/resources/updated", notification.Method)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for subscribed resource notification")
	}
	select {
	case notification := <-secondNotifications:
		t.Fatalf("unexpected notification for another session: %s", notification.Method)
	case <-time.After(50 * time.Millisecond):
	}

	cancelFirst()
	for range firstNotifications {
	}
	mcpServer.NotifyResourceUpdated("config://current")

	reconnectContext, cancelReconnect := context.WithCancel(context.Background())
	defer cancelReconnect()
	replayed, err := firstClient.ListenForNotifications(reconnectContext)
	require.NoError(t, err)
	select {
	case notification := <-replayed:
		assert.Equal(t, "notifications/resources/updated", notification.Method)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for replayed notification")
	}
}

func TestBearerAuthenticationAndMetadata(t *testing.T) {
	mcpServer := NewServer("auth-test", "1.0", false, "")
	mcpServer.SetBearerTokenVerifier(auth.StaticTokenVerifier(map[string]auth.TokenInfo{
		"read-token":  {Subject: "reader", Scopes: []string{"mcp:read"}},
		"other-token": {Subject: "other", Scopes: []string{"other"}},
	}), "mcp:read")
	mcpServer.SetProtectedResourceMetadata(auth.ProtectedResourceMetadata{
		Resource:             "https://mcp.example.test",
		AuthorizationServers: []string{"https://auth.example.test"},
		ScopesSupported:      []string{"mcp:read"},
		BearerMethods:        []string{"header"},
	})
	httpServer := httptest.NewServer(mcpServer.Handler())
	defer httpServer.Close()

	response, err := http.Get(httpServer.URL + "/.well-known/oauth-protected-resource")
	require.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, http.StatusOK, response.StatusCode)

	unauthorized := client.NewClient()
	unauthorized.ConnectHTTP(httpServer.URL)
	_, err = unauthorized.ListTools()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")

	forbidden := client.NewClient()
	forbidden.SetBearerToken("other-token")
	forbidden.ConnectHTTP(httpServer.URL)
	_, err = forbidden.ListTools()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")

	authorized := client.NewClient()
	authorized.SetBearerToken("read-token")
	authorized.ConnectHTTP(httpServer.URL)
	_, err = authorized.ListTools()
	require.NoError(t, err)
}

func TestSchemaValidationRejectsInvalidStructuredOutput(t *testing.T) {
	err := validateSchemaValue(map[string]interface{}{"count": "wrong"}, map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"count": map[string]interface{}{"type": "integer"},
		},
		"required":             []string{"count"},
		"additionalProperties": false,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "$.count")
}

func TestStatelessHTTP(t *testing.T) {
	mcpServer := NewServer("stateless-test", "1.0", false, "")
	mcpServer.SetStatelessHTTP(true)
	httpServer := httptest.NewServer(mcpServer.Handler())
	defer httpServer.Close()

	mcpClient := client.NewClient()
	mcpClient.ConnectHTTP(httpServer.URL)
	require.NoError(t, mcpClient.Ping())
	require.NoError(t, mcpClient.Ping())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := mcpClient.ListenForNotifications(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "405")
}

func TestTasksAreSessionScoped(t *testing.T) {
	mcpServer := NewServer("task-session-test", "1.0", false, "")
	require.NoError(t, mcpServer.AddTool("task", "task", func() string { return "done" }, nil))
	httpServer := httptest.NewServer(mcpServer.Handler())
	defer httpServer.Close()

	owner := client.NewClient()
	owner.ConnectHTTP(httpServer.URL)
	other := client.NewClient()
	other.ConnectHTTP(httpServer.URL)

	taskID, err := owner.CallAsync("task", map[string]interface{}{})
	require.NoError(t, err)
	_, err = other.GetResult(taskID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Task not found")
}
