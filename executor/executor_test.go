package executor

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/hawoond/gomcp/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandRequiresAllowlist(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	_, err = RunCommand(context.Background(), &protocol.CommandConfig{Path: executable}, nil, Policy{
		AllowedCommands: make(map[string]struct{}),
		CommandTimeout:  time.Second,
	})
	var executionError *Error
	require.ErrorAs(t, err, &executionError)
	assert.Equal(t, ErrorPolicy, executionError.Kind)
}

func TestHTTPRejectsPrivateTargets(t *testing.T) {
	_, err := RunHTTP(context.Background(), &protocol.HTTPConfig{
		URL:    "http://127.0.0.1/internal",
		Method: http.MethodGet,
	}, nil, Policy{
		AllowedHTTPHosts: map[string]struct{}{"127.0.0.1": {}},
	})
	var executionError *Error
	require.True(t, errors.As(err, &executionError))
	assert.Equal(t, ErrorPolicy, executionError.Kind)
	assert.Contains(t, err.Error(), "non-public")
}
