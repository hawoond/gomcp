package server

import (
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/hawoond/gomcp/auth"
	"github.com/hawoond/gomcp/internal/types"
	"go.uber.org/zap"
)

func (s *Server) SetLogger(logger *zap.Logger) {
	if logger == nil {
		logger = zap.NewNop()
	}
	s.rwMu.Lock()
	s.logger = logger
	s.rwMu.Unlock()
}

func (s *Server) SetHTTPClient(client *http.Client) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	s.rwMu.Lock()
	s.httpClient = client
	s.rwMu.Unlock()
}

func (s *Server) SetLimits(maxRequestBytes, maxResponseBytes int64) error {
	if maxRequestBytes <= 0 || maxResponseBytes <= 0 {
		return fmt.Errorf("request and response limits must be positive")
	}
	s.rwMu.Lock()
	s.maxRequestBytes = maxRequestBytes
	s.maxResponseBytes = maxResponseBytes
	s.rwMu.Unlock()
	return nil
}

func (s *Server) SetCommandTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return fmt.Errorf("command timeout must be positive")
	}
	s.rwMu.Lock()
	s.commandTimeout = timeout
	s.rwMu.Unlock()
	return nil
}

func (s *Server) SetTaskPolicy(ttl time.Duration, maxTasks int) error {
	if ttl <= 0 || maxTasks <= 0 {
		return fmt.Errorf("task TTL and capacity must be positive")
	}
	s.tasksMu.Lock()
	s.taskTTL = ttl
	s.maxTasks = maxTasks
	s.tasksMu.Unlock()
	return nil
}

func (s *Server) SetPageSize(pageSize int) error {
	if pageSize <= 0 {
		return fmt.Errorf("page size must be positive")
	}
	s.rwMu.Lock()
	s.pageSize = pageSize
	s.rwMu.Unlock()
	return nil
}

func (s *Server) SetSessionPolicy(ttl time.Duration, maxEvents int) error {
	if ttl <= 0 || maxEvents <= 0 {
		return fmt.Errorf("session TTL and event capacity must be positive")
	}
	s.sessionsMu.Lock()
	s.sessionTTL = ttl
	s.maxSessionEvents = maxEvents
	s.sessionsMu.Unlock()
	return nil
}

func (s *Server) SetStatelessHTTP(enabled bool) {
	s.rwMu.Lock()
	s.statelessHTTP = enabled
	s.rwMu.Unlock()
}

func (s *Server) SetCompletionHandler(handler CompletionHandler) {
	s.rwMu.Lock()
	s.completionHandler = handler
	s.rwMu.Unlock()
}

func (s *Server) SetToolMetadata(name, title string, annotations *types.ToolAnnotations, icons ...types.Icon) error {
	s.rwMu.Lock()
	tool, ok := s.tools[name]
	if !ok {
		s.rwMu.Unlock()
		return fmt.Errorf("tool %q is not registered", name)
	}
	tool.Title = title
	if annotations != nil {
		copyAnnotations := *annotations
		tool.Annotations = &copyAnnotations
	} else {
		tool.Annotations = nil
	}
	tool.Icons = append([]types.Icon(nil), icons...)
	s.tools[name] = tool
	s.rwMu.Unlock()
	s.PublishNotification("notifications/tools/list_changed", nil)
	return nil
}

func (s *Server) SetResourceMetadata(uri, name, title, mimeType string, annotations *types.Annotations, icons ...types.Icon) error {
	s.rwMu.Lock()
	for index := range s.resources {
		if s.resources[index].URITemplate != uri {
			continue
		}
		s.resources[index].Name = name
		s.resources[index].Title = title
		s.resources[index].MimeType = mimeType
		if annotations != nil {
			copyAnnotations := *annotations
			copyAnnotations.Audience = append([]string(nil), annotations.Audience...)
			s.resources[index].Annotations = &copyAnnotations
		} else {
			s.resources[index].Annotations = nil
		}
		s.resources[index].Icons = append([]types.Icon(nil), icons...)
		s.rwMu.Unlock()
		s.PublishNotification("notifications/resources/list_changed", nil)
		return nil
	}
	s.rwMu.Unlock()
	return fmt.Errorf("resource %q is not registered", uri)
}

func (s *Server) SetPromptMetadata(name, title string, icons ...types.Icon) error {
	s.rwMu.Lock()
	prompt, ok := s.prompts[name]
	if !ok {
		s.rwMu.Unlock()
		return fmt.Errorf("prompt %q is not registered", name)
	}
	prompt.Title = title
	prompt.Icons = append([]types.Icon(nil), icons...)
	s.prompts[name] = prompt
	s.rwMu.Unlock()
	s.PublishNotification("notifications/prompts/list_changed", nil)
	return nil
}

func (s *Server) SetBearerTokenVerifier(verifier auth.TokenVerifier, requiredScopes ...string) {
	s.rwMu.Lock()
	s.bearerVerifier = verifier
	s.requiredScopes = append([]string(nil), requiredScopes...)
	s.rwMu.Unlock()
}

func (s *Server) SetProtectedResourceMetadata(metadata auth.ProtectedResourceMetadata) {
	s.rwMu.Lock()
	copyMetadata := metadata
	copyMetadata.AuthorizationServers = append([]string(nil), metadata.AuthorizationServers...)
	copyMetadata.ScopesSupported = append([]string(nil), metadata.ScopesSupported...)
	copyMetadata.BearerMethods = append([]string(nil), metadata.BearerMethods...)
	s.protectedResourceMetadata = &copyMetadata
	s.rwMu.Unlock()
}

func (s *Server) AllowOrigin(origins ...string) error {
	s.rwMu.Lock()
	defer s.rwMu.Unlock()
	for _, origin := range origins {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("invalid origin %q", origin)
		}
		s.allowedOrigins[strings.ToLower(parsed.Scheme+"://"+parsed.Host)] = struct{}{}
	}
	return nil
}

func (s *Server) AllowCommand(paths ...string) error {
	s.rwMu.Lock()
	defer s.rwMu.Unlock()
	for _, commandPath := range paths {
		resolved, err := exec.LookPath(commandPath)
		if err != nil {
			return fmt.Errorf("resolve command %q: %w", commandPath, err)
		}
		s.allowedCommandPaths[resolved] = struct{}{}
	}
	return nil
}

func (s *Server) AllowHTTPHost(hosts ...string) error {
	s.rwMu.Lock()
	defer s.rwMu.Unlock()
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || strings.ContainsAny(host, "/?#") {
			return fmt.Errorf("invalid HTTP host %q", host)
		}
		s.allowedHTTPHosts[host] = struct{}{}
	}
	return nil
}

func (s *Server) EnableExperimentalMethods(enabled bool) {
	s.rwMu.Lock()
	s.enableExperimentalMethods = enabled
	s.rwMu.Unlock()
}

func (s *Server) experimentalMethodsEnabled() bool {
	s.rwMu.RLock()
	defer s.rwMu.RUnlock()
	return s.enableExperimentalMethods
}

func (s *Server) AddDynamicTool(definition types.ToolDefinition) error {
	if err := validateDynamicDefinition(definition.Type, definition.Command, definition.HTTP); err != nil {
		return err
	}
	if strings.TrimSpace(definition.Name) == "" {
		return fmt.Errorf("tool name is required")
	}
	s.rwMu.Lock()
	s.dynamicTools[definition.Name] = definition
	s.rwMu.Unlock()
	s.PublishNotification("notifications/tools/list_changed", nil)
	return nil
}

func (s *Server) AddDynamicPrompt(definition types.PromptDefinition) error {
	if err := validateDynamicDefinition(definition.Type, definition.Command, definition.HTTP); err != nil {
		return err
	}
	if strings.TrimSpace(definition.Name) == "" {
		return fmt.Errorf("prompt name is required")
	}
	s.rwMu.Lock()
	s.dynamicPrompts[definition.Name] = definition
	s.rwMu.Unlock()
	s.PublishNotification("notifications/prompts/list_changed", nil)
	return nil
}

func validateDynamicDefinition(kind string, command *types.CommandConfig, httpConfig *types.HTTPConfig) error {
	switch kind {
	case "command":
		if command == nil || strings.TrimSpace(command.Path) == "" {
			return fmt.Errorf("command configuration is required")
		}
	case "http":
		if httpConfig == nil {
			return fmt.Errorf("HTTP configuration is required")
		}
		parsed, err := url.Parse(httpConfig.URL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
			return fmt.Errorf("HTTP URL must use http or https")
		}
	default:
		return fmt.Errorf("unsupported dynamic definition type %q", kind)
	}
	return nil
}
