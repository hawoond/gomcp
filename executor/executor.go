package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hawoond/gomcp/protocol"
)

type ErrorKind string

const (
	ErrorConfiguration ErrorKind = "configuration"
	ErrorPolicy        ErrorKind = "policy"
	ErrorExecution     ErrorKind = "execution"
)

type Error struct {
	Kind    ErrorKind
	Details interface{}
	Err     error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

type Policy struct {
	AllowedCommands  map[string]struct{}
	AllowedHTTPHosts map[string]struct{}
	HTTPClient       *http.Client
	CommandTimeout   time.Duration
	MaxResponseBytes int64
}

func RunCommand(ctx context.Context, config *protocol.CommandConfig, arguments map[string]interface{}, policy Policy) (string, error) {
	if config == nil {
		return "", newError(ErrorConfiguration, nil, errors.New("command configuration is required"))
	}
	resolvedPath, err := exec.LookPath(config.Path)
	if err != nil {
		return "", newError(ErrorConfiguration, nil, fmt.Errorf("command is not available: %w", err))
	}
	if _, allowed := policy.AllowedCommands[resolvedPath]; !allowed {
		return "", newError(ErrorPolicy, nil, fmt.Errorf("command %q is not allowlisted", resolvedPath))
	}
	timeout := policy.CommandTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if config.TimeoutMillis > 0 {
		configured := time.Duration(config.TimeoutMillis) * time.Millisecond
		if configured < timeout {
			timeout = configured
		}
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	commandArguments := append([]string(nil), config.Args...)
	names := make([]string, 0, len(arguments))
	for name := range arguments {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		commandArguments = append(commandArguments, fmt.Sprintf("%v", arguments[name]))
	}

	output := newCappedBuffer(policy.MaxResponseBytes)
	command := exec.CommandContext(commandContext, resolvedPath, commandArguments...)
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		return "", newError(ErrorExecution, output.String(), fmt.Errorf("command execution failed: %w", err))
	}
	if output.Exceeded() {
		return "", newError(ErrorExecution, output.String(), errors.New("command output limit exceeded"))
	}
	return output.String(), nil
}

func RunHTTP(ctx context.Context, config *protocol.HTTPConfig, arguments map[string]interface{}, policy Policy) (string, error) {
	if config == nil {
		return "", newError(ErrorConfiguration, nil, errors.New("HTTP configuration is required"))
	}
	target, err := url.Parse(config.URL)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" {
		return "", newError(ErrorConfiguration, nil, errors.New("invalid HTTP target URL"))
	}
	host := strings.ToLower(target.Hostname())
	_, allowed := policy.AllowedHTTPHosts[host]
	if !allowed {
		_, allowed = policy.AllowedHTTPHosts[strings.ToLower(target.Host)]
	}
	if !allowed {
		return "", newError(ErrorPolicy, nil, fmt.Errorf("HTTP host %q is not allowlisted", host))
	}
	addresses, err := resolvePublicHost(ctx, host)
	if err != nil {
		return "", newError(ErrorPolicy, nil, err)
	}

	method := strings.ToUpper(config.Method)
	if method == "" {
		method = http.MethodPost
	}
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return "", newError(ErrorConfiguration, nil, fmt.Errorf("HTTP method %q is not allowed", method))
	}

	var body io.Reader
	if config.Body != "" {
		bodyContent := config.Body
		for name, value := range arguments {
			bodyContent = strings.ReplaceAll(bodyContent, "{"+name+"}", fmt.Sprintf("%v", value))
		}
		body = strings.NewReader(bodyContent)
	} else if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		encoded, err := json.Marshal(arguments)
		if err != nil {
			return "", newError(ErrorConfiguration, nil, fmt.Errorf("encode HTTP arguments: %w", err))
		}
		body = bytes.NewReader(encoded)
	}

	requestContext := ctx
	cancel := func() {}
	if config.TimeoutMillis > 0 {
		requestContext, cancel = context.WithTimeout(ctx, time.Duration(config.TimeoutMillis)*time.Millisecond)
	}
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, method, target.String(), body)
	if err != nil {
		return "", newError(ErrorConfiguration, nil, fmt.Errorf("create HTTP request: %w", err))
	}
	for name, value := range config.Headers {
		if !strings.EqualFold(name, "Host") {
			request.Header.Set(name, value)
		}
	}
	if body != nil && request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/json")
	}

	baseClient := policy.HTTPClient
	if baseClient == nil {
		baseClient = &http.Client{Timeout: 30 * time.Second}
	}
	client := *baseClient
	transport, err := pinnedTransport(baseClient.Transport, host, addresses)
	if err != nil {
		return "", newError(ErrorConfiguration, nil, err)
	}
	client.Transport = transport
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := client.Do(request)
	if err != nil {
		return "", newError(ErrorExecution, nil, fmt.Errorf("HTTP request failed: %w", err))
	}
	defer response.Body.Close()

	limit := policy.MaxResponseBytes
	if limit <= 0 {
		limit = 4 << 20
	}
	if config.MaxResponseBytes > 0 && config.MaxResponseBytes < limit {
		limit = config.MaxResponseBytes
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return "", newError(ErrorExecution, nil, fmt.Errorf("read HTTP response: %w", err))
	}
	if int64(len(responseBody)) > limit {
		return "", newError(ErrorExecution, nil, fmt.Errorf("HTTP response exceeds %d bytes", limit))
	}
	if response.StatusCode >= 400 {
		return "", newError(ErrorExecution, string(responseBody), fmt.Errorf("HTTP request failed with status %d", response.StatusCode))
	}
	return string(responseBody), nil
}

func resolvePublicHost(ctx context.Context, host string) ([]net.IP, error) {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve HTTP host %q: %w", host, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("HTTP host %q has no addresses", host)
	}
	publicAddresses := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		ip := address.IP
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, fmt.Errorf("HTTP host %q resolves to a non-public address", host)
		}
		publicAddresses = append(publicAddresses, append(net.IP(nil), ip...))
	}
	return publicAddresses, nil
}

func pinnedTransport(base http.RoundTripper, expectedHost string, addresses []net.IP) (*http.Transport, error) {
	var transport *http.Transport
	switch value := base.(type) {
	case nil:
		transport = http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		transport = value.Clone()
	default:
		return nil, fmt.Errorf("custom HTTP transport must be *http.Transport")
	}
	transport.Proxy = nil
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("parse dial address: %w", err)
		}
		if !strings.EqualFold(host, expectedHost) {
			return nil, fmt.Errorf("unexpected dial host %q", host)
		}
		var lastErr error
		for _, ip := range addresses {
			connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return connection, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
	return transport, nil
}

func newError(kind ErrorKind, details interface{}, err error) *Error {
	return &Error{Kind: kind, Details: details, Err: err}
}

type cappedBuffer struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	remaining int64
	exceeded  bool
}

func newCappedBuffer(limit int64) *cappedBuffer {
	if limit <= 0 {
		limit = 4 << 20
	}
	return &cappedBuffer{remaining: limit}
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.remaining <= 0 {
		b.exceeded = true
		return 0, errors.New("output limit exceeded")
	}
	writeLength := int64(len(data))
	if writeLength > b.remaining {
		writeLength = b.remaining
		b.exceeded = true
	}
	written, err := b.buffer.Write(data[:writeLength])
	b.remaining -= int64(written)
	if err == nil && written < len(data) {
		err = errors.New("output limit exceeded")
	}
	return written, err
}

func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func (b *cappedBuffer) Exceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exceeded
}
