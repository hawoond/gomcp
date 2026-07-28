package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

var (
	ErrMissingToken      = errors.New("bearer token is required")
	ErrInvalidToken      = errors.New("bearer token is invalid")
	ErrInsufficientScope = errors.New("bearer token has insufficient scope")
)

type TokenInfo struct {
	Subject   string
	Scopes    []string
	ExpiresAt time.Time
	Claims    map[string]interface{}
}

type tokenInfoContextKey struct{}

func NewContext(ctx context.Context, info *TokenInfo) context.Context {
	if info == nil {
		return ctx
	}
	return context.WithValue(ctx, tokenInfoContextKey{}, info)
}

func FromContext(ctx context.Context) (*TokenInfo, bool) {
	info, ok := ctx.Value(tokenInfoContextKey{}).(*TokenInfo)
	return info, ok
}

type TokenVerifier interface {
	VerifyToken(context.Context, string) (*TokenInfo, error)
}

type TokenVerifierFunc func(context.Context, string) (*TokenInfo, error)

func (f TokenVerifierFunc) VerifyToken(ctx context.Context, token string) (*TokenInfo, error) {
	return f(ctx, token)
}

type TokenSource interface {
	Token(context.Context) (string, error)
}

type TokenSourceFunc func(context.Context) (string, error)

func (f TokenSourceFunc) Token(ctx context.Context) (string, error) {
	return f(ctx)
}

type ProtectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
	BearerMethods        []string `json:"bearer_methods_supported,omitempty"`
	ResourceName         string   `json:"resource_name,omitempty"`
}

func ProtectedResourceMetadataHandler(metadata ProtectedResourceMetadata) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(metadata)
	}
}

func BearerToken(r *http.Request) (string, error) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, token, ok := strings.Cut(authorization, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return "", ErrMissingToken
	}
	return strings.TrimSpace(token), nil
}

func VerifyRequest(ctx context.Context, r *http.Request, verifier TokenVerifier, requiredScopes []string) (*TokenInfo, error) {
	if verifier == nil {
		return nil, ErrInvalidToken
	}
	token, err := BearerToken(r)
	if err != nil {
		return nil, err
	}
	info, err := verifier.VerifyToken(ctx, token)
	if err != nil || info == nil {
		return nil, ErrInvalidToken
	}
	if !info.ExpiresAt.IsZero() && !time.Now().Before(info.ExpiresAt) {
		return nil, ErrInvalidToken
	}
	if !containsScopes(info.Scopes, requiredScopes) {
		return nil, ErrInsufficientScope
	}
	return info, nil
}

func StaticTokenVerifier(tokens map[string]TokenInfo) TokenVerifier {
	copied := make(map[string]TokenInfo, len(tokens))
	for token, info := range tokens {
		copied[token] = info
	}
	return TokenVerifierFunc(func(_ context.Context, candidate string) (*TokenInfo, error) {
		for token, info := range copied {
			if len(token) == len(candidate) && subtle.ConstantTimeCompare([]byte(token), []byte(candidate)) == 1 {
				result := info
				result.Scopes = append([]string(nil), info.Scopes...)
				return &result, nil
			}
		}
		return nil, ErrInvalidToken
	})
}

func containsScopes(granted, required []string) bool {
	if len(required) == 0 {
		return true
	}
	scopeSet := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		scopeSet[scope] = struct{}{}
	}
	for _, scope := range required {
		if _, ok := scopeSet[scope]; !ok {
			return false
		}
	}
	return true
}
