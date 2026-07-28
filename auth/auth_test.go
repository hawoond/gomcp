package auth

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyRequest(t *testing.T) {
	verifier := StaticTokenVerifier(map[string]TokenInfo{
		"valid":   {Subject: "user", Scopes: []string{"mcp:read"}},
		"expired": {ExpiresAt: time.Now().Add(-time.Minute), Scopes: []string{"mcp:read"}},
	})

	request := httptest.NewRequest("POST", "/mcp", nil)
	_, err := VerifyRequest(context.Background(), request, verifier, []string{"mcp:read"})
	assert.ErrorIs(t, err, ErrMissingToken)

	request.Header.Set("Authorization", "Bearer expired")
	_, err = VerifyRequest(context.Background(), request, verifier, []string{"mcp:read"})
	assert.ErrorIs(t, err, ErrInvalidToken)

	request.Header.Set("Authorization", "Bearer valid")
	_, err = VerifyRequest(context.Background(), request, verifier, []string{"mcp:write"})
	assert.ErrorIs(t, err, ErrInsufficientScope)

	info, err := VerifyRequest(context.Background(), request, verifier, []string{"mcp:read"})
	require.NoError(t, err)
	assert.Equal(t, "user", info.Subject)
}

func TestTokenInfoContext(t *testing.T) {
	expected := &TokenInfo{Subject: "subject"}
	ctx := NewContext(context.Background(), expected)
	actual, ok := FromContext(ctx)
	require.True(t, ok)
	assert.Same(t, expected, actual)

	_, ok = FromContext(context.Background())
	assert.False(t, ok)
	assert.False(t, errors.Is(ErrInvalidToken, ErrMissingToken))
}
