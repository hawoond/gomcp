package server

import (
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

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
	defer s.rwMu.Unlock()
	s.dynamicTools[definition.Name] = definition
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
	defer s.rwMu.Unlock()
	s.dynamicPrompts[definition.Name] = definition
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
