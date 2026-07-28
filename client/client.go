package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/hawoond/gomcp/auth"
	"github.com/hawoond/gomcp/protocol"
)

type NotificationHandler func(method string, params json.RawMessage)
type RequestHandler func(context.Context, string, json.RawMessage) (interface{}, error)

type stdioResult struct {
	response protocol.Response
	err      error
}

type Client struct {
	stateMu             sync.RWMutex
	transport           string
	cmd                 *exec.Cmd
	stdin               io.WriteCloser
	stdout              io.ReadCloser
	stdioEncoder        *json.Encoder
	stdioDecoder        *json.Decoder
	baseURL             string
	sessionID           string
	protocolVersion     string
	initialized         bool
	apiKey              string
	tokenSource         auth.TokenSource
	httpClient          *http.Client
	maxResponseBytes    int64
	nextID              int64
	idMu                sync.Mutex
	stdioWriteMu        sync.Mutex
	pendingMu           sync.Mutex
	pending             map[string]chan stdioResult
	readerDone          chan struct{}
	readerErrMu         sync.RWMutex
	readerErr           error
	initMu              sync.Mutex
	notificationMu      sync.RWMutex
	notificationHandler NotificationHandler
	requestMu           sync.RWMutex
	requestHandler      RequestHandler
	requestHandlers     map[string]RequestHandler
	lastEventID         string
}

func NewClient() *Client {
	return &Client{
		nextID:           1,
		httpClient:       &http.Client{Timeout: 30 * time.Second},
		maxResponseBytes: 4 << 20,
		protocolVersion:  protocol.LatestProtocolVersion,
		pending:          make(map[string]chan stdioResult),
		requestHandlers:  make(map[string]RequestHandler),
	}
}

func (c *Client) SetHTTPClient(client *http.Client) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	c.stateMu.Lock()
	c.httpClient = client
	c.stateMu.Unlock()
}

func (c *Client) SetAPIKey(apiKey string) {
	c.stateMu.Lock()
	c.apiKey = apiKey
	c.stateMu.Unlock()
}

func (c *Client) SetBearerToken(token string) {
	c.SetTokenSource(auth.TokenSourceFunc(func(context.Context) (string, error) {
		return token, nil
	}))
}

func (c *Client) SetTokenSource(source auth.TokenSource) {
	c.stateMu.Lock()
	c.tokenSource = source
	c.stateMu.Unlock()
}

func (c *Client) SetResponseLimit(limit int64) error {
	if limit <= 0 {
		return fmt.Errorf("response limit must be positive")
	}
	c.stateMu.Lock()
	c.maxResponseBytes = limit
	c.stateMu.Unlock()
	return nil
}

func (c *Client) ProtocolVersion() string {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.protocolVersion
}

func (c *Client) StartProcess(command string, args ...string) error {
	return c.StartProcessContext(context.Background(), command, args...)
}

func (c *Client) StartProcessContext(ctx context.Context, command string, args ...string) error {
	cmd := exec.CommandContext(ctx, command, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = stdout.Close()
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return err
	}

	c.stateMu.Lock()
	c.transport = "stdio"
	c.cmd = cmd
	c.stdout = stdout
	c.stdin = stdin
	c.stdioEncoder = json.NewEncoder(stdin)
	c.stdioDecoder = json.NewDecoder(stdout)
	c.readerDone = make(chan struct{})
	c.readerErr = nil
	c.pending = make(map[string]chan stdioResult)
	c.initialized = false
	c.sessionID = ""
	c.lastEventID = ""
	decoder := c.stdioDecoder
	readerDone := c.readerDone
	c.stateMu.Unlock()
	go c.readStdio(decoder, readerDone)
	return nil
}

func (c *Client) StopProcess() error {
	c.stateMu.Lock()
	cmd := c.cmd
	stdin := c.stdin
	stdout := c.stdout
	c.cmd = nil
	c.stdin = nil
	c.stdout = nil
	c.stdioEncoder = nil
	c.stdioDecoder = nil
	c.initialized = false
	c.stateMu.Unlock()

	if cmd == nil {
		return nil
	}
	var closeErrors []error
	if stdin != nil {
		if err := stdin.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			closeErrors = append(closeErrors, err)
		}
	}
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- cmd.Wait()
	}()
	select {
	case err := <-waitDone:
		if err != nil {
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) {
				closeErrors = append(closeErrors, err)
			}
		}
	case <-time.After(5 * time.Second):
		if cmd.Process != nil {
			if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				closeErrors = append(closeErrors, err)
			}
		}
		if err := <-waitDone; err != nil {
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) {
				closeErrors = append(closeErrors, err)
			}
		}
	}
	if stdout != nil {
		if err := stdout.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			closeErrors = append(closeErrors, err)
		}
	}
	return errors.Join(closeErrors...)
}

func (c *Client) ConnectHTTP(baseURL string) {
	c.stateMu.Lock()
	c.transport = "http"
	c.baseURL = strings.TrimRight(baseURL, "/")
	c.sessionID = ""
	c.lastEventID = ""
	c.initialized = false
	c.stateMu.Unlock()
}

func (c *Client) Initialize(clientName string, clientVersion string, protocolVersion string) error {
	return c.InitializeContext(context.Background(), clientName, clientVersion, protocolVersion)
}

func (c *Client) InitializeContext(ctx context.Context, clientName string, clientVersion string, protocolVersion string) error {
	c.initMu.Lock()
	defer c.initMu.Unlock()
	return c.initializeLocked(ctx, clientName, clientVersion, protocolVersion)
}

func (c *Client) initializeLocked(ctx context.Context, clientName string, clientVersion string, protocolVersion string) error {
	if protocolVersion == "" {
		protocolVersion = protocol.LatestProtocolVersion
	}
	c.requestMu.RLock()
	capabilities := make(map[string]interface{})
	if c.requestHandlers["roots/list"] != nil {
		capabilities["roots"] = map[string]interface{}{"listChanged": true}
	}
	if c.requestHandlers["sampling/createMessage"] != nil {
		capabilities["sampling"] = map[string]interface{}{}
	}
	if c.requestHandlers["elicitation/create"] != nil {
		capabilities["elicitation"] = map[string]interface{}{}
	}
	c.requestMu.RUnlock()
	params := map[string]interface{}{
		"protocolVersion": protocolVersion,
		"clientInfo": map[string]string{
			"name":    clientName,
			"version": clientVersion,
		},
		"capabilities": capabilities,
	}
	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := c.callRaw(ctx, "initialize", params, &result); err != nil {
		return err
	}
	if result.ProtocolVersion == "" {
		return fmt.Errorf("initialize response omitted protocolVersion")
	}
	c.stateMu.Lock()
	c.protocolVersion = result.ProtocolVersion
	c.initialized = true
	c.stateMu.Unlock()
	if err := c.notifyRaw(ctx, "notifications/initialized", map[string]interface{}{}); err != nil {
		c.stateMu.Lock()
		c.initialized = false
		c.stateMu.Unlock()
		return err
	}
	return nil
}

func (c *Client) ensureInitialized(ctx context.Context) error {
	c.stateMu.RLock()
	initialized := c.initialized
	c.stateMu.RUnlock()
	if initialized {
		return nil
	}
	c.initMu.Lock()
	defer c.initMu.Unlock()
	c.stateMu.RLock()
	initialized = c.initialized
	c.stateMu.RUnlock()
	if initialized {
		return nil
	}
	return c.initializeLocked(ctx, "gomcp-client", "0.1.0", protocol.LatestProtocolVersion)
}

func (c *Client) ListTools() ([]map[string]interface{}, error) {
	var tools []map[string]interface{}
	cursor := ""
	for {
		var result struct {
			Tools      []map[string]interface{} `json:"tools"`
			NextCursor string                   `json:"nextCursor"`
		}
		if err := c.Call("tools/list", map[string]interface{}{"cursor": cursor}, &result); err != nil {
			return nil, err
		}
		tools = append(tools, result.Tools...)
		if result.NextCursor == "" {
			return tools, nil
		}
		cursor = result.NextCursor
	}
}

func (c *Client) ListPrompts() ([]map[string]interface{}, error) {
	var prompts []map[string]interface{}
	cursor := ""
	for {
		var result struct {
			Prompts    []map[string]interface{} `json:"prompts"`
			NextCursor string                   `json:"nextCursor"`
		}
		if err := c.Call("prompts/list", map[string]interface{}{"cursor": cursor}, &result); err != nil {
			return nil, err
		}
		prompts = append(prompts, result.Prompts...)
		if result.NextCursor == "" {
			return prompts, nil
		}
		cursor = result.NextCursor
	}
}

func (c *Client) ListResources() ([]map[string]interface{}, error) {
	var resources []map[string]interface{}
	cursor := ""
	for {
		var result struct {
			Resources  []map[string]interface{} `json:"resources"`
			NextCursor string                   `json:"nextCursor"`
		}
		if err := c.Call("resources/list", map[string]interface{}{"cursor": cursor}, &result); err != nil {
			return nil, err
		}
		resources = append(resources, result.Resources...)
		if result.NextCursor == "" {
			return resources, nil
		}
		cursor = result.NextCursor
	}
}

func (c *Client) ListResourceTemplates() ([]protocol.ResourceTemplate, error) {
	var templates []protocol.ResourceTemplate
	cursor := ""
	for {
		var result protocol.ListResourceTemplatesResult
		if err := c.Call("resources/templates/list", map[string]interface{}{"cursor": cursor}, &result); err != nil {
			return nil, err
		}
		templates = append(templates, result.ResourceTemplates...)
		if result.NextCursor == "" {
			return templates, nil
		}
		cursor = result.NextCursor
	}
}

func (c *Client) Ping() error {
	return c.Call("ping", map[string]interface{}{}, nil)
}

func (c *Client) Complete(params protocol.CompleteParams) (protocol.CompleteResult, error) {
	var result protocol.CompleteResult
	err := c.Call("completion/complete", params, &result)
	return result, err
}

func (c *Client) SubscribeResource(uri string) error {
	return c.Call("resources/subscribe", map[string]string{"uri": uri}, nil)
}

func (c *Client) UnsubscribeResource(uri string) error {
	return c.Call("resources/unsubscribe", map[string]string{"uri": uri}, nil)
}

func (c *Client) NotifyProgress(progressToken interface{}, progress float64, total *float64, message string) error {
	return c.Notify("notifications/progress", protocol.ProgressParams{
		ProgressToken: progressToken,
		Progress:      progress,
		Total:         total,
		Message:       message,
	})
}

func (c *Client) Call(method string, params interface{}, result interface{}) error {
	return c.CallContext(context.Background(), method, params, result)
}

func (c *Client) CallContext(ctx context.Context, method string, params interface{}, result interface{}) error {
	if method != "initialize" {
		if err := c.ensureInitialized(ctx); err != nil {
			return err
		}
	}
	return c.callRaw(ctx, method, params, result)
}

func (c *Client) callRaw(ctx context.Context, method string, params interface{}, result interface{}) error {
	id := c.nextRequestID()
	idBytes, err := json.Marshal(id)
	if err != nil {
		return err
	}
	var paramBytes json.RawMessage
	if params != nil {
		paramBytes, err = json.Marshal(params)
		if err != nil {
			return fmt.Errorf("encode request parameters: %w", err)
		}
	}
	request := protocol.Request{
		JSONRPC: "2.0",
		ID:      rawMessagePointer(idBytes),
		Method:  method,
		Params:  paramBytes,
	}

	response, err := c.exchange(ctx, request)
	if err != nil {
		return err
	}
	if response.Error != nil {
		return fmt.Errorf("RPC error %d: %s", response.Error.Code, response.Error.Message)
	}
	if result == nil {
		return nil
	}
	encoded, err := json.Marshal(response.Result)
	if err != nil {
		return fmt.Errorf("encode response result: %w", err)
	}
	if err := json.Unmarshal(encoded, result); err != nil {
		return fmt.Errorf("decode response result: %w", err)
	}
	return nil
}

func (c *Client) exchange(ctx context.Context, request protocol.Request) (protocol.Response, error) {
	c.stateMu.RLock()
	transport := c.transport
	c.stateMu.RUnlock()
	switch transport {
	case "stdio":
		return c.exchangeStdio(ctx, request)
	case "http":
		return c.exchangeHTTP(ctx, request)
	default:
		return protocol.Response{}, fmt.Errorf("client not connected")
	}
}

func (c *Client) exchangeStdio(ctx context.Context, request protocol.Request) (protocol.Response, error) {
	c.stateMu.RLock()
	encoder := c.stdioEncoder
	readerDone := c.readerDone
	c.stateMu.RUnlock()
	if encoder == nil || readerDone == nil || request.ID == nil {
		return protocol.Response{}, fmt.Errorf("stdio transport is not running")
	}
	if err := ctx.Err(); err != nil {
		return protocol.Response{}, err
	}
	requestID := string(*request.ID)
	responseChannel := make(chan stdioResult, 1)
	c.pendingMu.Lock()
	c.pending[requestID] = responseChannel
	c.pendingMu.Unlock()

	c.stdioWriteMu.Lock()
	err := encoder.Encode(request)
	c.stdioWriteMu.Unlock()
	if err != nil {
		c.removePending(requestID)
		return protocol.Response{}, err
	}

	select {
	case result := <-responseChannel:
		return result.response, result.err
	case <-ctx.Done():
		c.removePending(requestID)
		_ = c.writeStdio(protocol.Request{
			JSONRPC: "2.0",
			Method:  "notifications/cancelled",
			Params: mustMarshal(map[string]interface{}{
				"requestId": json.RawMessage(*request.ID),
				"reason":    ctx.Err().Error(),
			}),
		})
		return protocol.Response{}, ctx.Err()
	case <-readerDone:
		c.removePending(requestID)
		c.readerErrMu.RLock()
		readerErr := c.readerErr
		c.readerErrMu.RUnlock()
		if readerErr == nil {
			readerErr = io.EOF
		}
		return protocol.Response{}, readerErr
	}
}

func (c *Client) exchangeHTTP(ctx context.Context, request protocol.Request) (protocol.Response, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return protocol.Response{}, err
	}
	httpRequest, err := c.newHTTPRequest(ctx, http.MethodPost, bytes.NewReader(encoded))
	if err != nil {
		return protocol.Response{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json, text/event-stream")

	c.stateMu.RLock()
	client := c.httpClient
	maxResponseBytes := c.maxResponseBytes
	c.stateMu.RUnlock()
	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		if ctx.Err() != nil && request.ID != nil {
			cancelContext, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = c.notifyRaw(cancelContext, "notifications/cancelled", map[string]interface{}{
				"requestId": json.RawMessage(*request.ID),
				"reason":    ctx.Err().Error(),
			})
			cancel()
		}
		return protocol.Response{}, err
	}
	defer httpResponse.Body.Close()
	if request.Method == "initialize" {
		if sessionID := httpResponse.Header.Get("MCP-Session-Id"); sessionID != "" {
			c.stateMu.Lock()
			c.sessionID = sessionID
			c.stateMu.Unlock()
		}
	}
	body, err := io.ReadAll(io.LimitReader(httpResponse.Body, maxResponseBytes+1))
	if err != nil {
		return protocol.Response{}, err
	}
	if int64(len(body)) > maxResponseBytes {
		return protocol.Response{}, fmt.Errorf("HTTP response exceeds %d bytes", maxResponseBytes)
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		return protocol.Response{}, fmt.Errorf("HTTP error %d: %s", httpResponse.StatusCode, strings.TrimSpace(string(body)))
	}
	var response protocol.Response
	if err := json.Unmarshal(body, &response); err != nil {
		return protocol.Response{}, fmt.Errorf("decode HTTP response: %w", err)
	}
	return response, nil
}

func (c *Client) Notify(method string, params interface{}) error {
	return c.NotifyContext(context.Background(), method, params)
}

func (c *Client) NotifyContext(ctx context.Context, method string, params interface{}) error {
	if err := c.ensureInitialized(ctx); err != nil {
		return err
	}
	return c.notifyRaw(ctx, method, params)
}

func (c *Client) notifyRaw(ctx context.Context, method string, params interface{}) error {
	paramBytes, err := json.Marshal(params)
	if err != nil {
		return err
	}
	request := protocol.Request{JSONRPC: "2.0", Method: method, Params: paramBytes}

	c.stateMu.RLock()
	transport := c.transport
	c.stateMu.RUnlock()
	if transport == "stdio" {
		return c.writeStdio(request)
	}
	if transport != "http" {
		return fmt.Errorf("client not connected")
	}

	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	httpRequest, err := c.newHTTPRequest(ctx, http.MethodPost, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json, text/event-stream")
	c.stateMu.RLock()
	client := c.httpClient
	c.stateMu.RUnlock()
	response, err := client.Do(httpRequest)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("notification HTTP error %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *Client) CallAsync(toolName string, args map[string]interface{}) (string, error) {
	var task protocol.Task
	err := c.Call("tools/call", map[string]interface{}{
		"name":      toolName,
		"arguments": args,
		"task":      map[string]interface{}{},
	}, &task)
	return task.ID, err
}

func (c *Client) GetResult(taskID string) (*protocol.Task, error) {
	var task protocol.Task
	if err := c.Call("tasks/get", map[string]interface{}{"taskId": taskID}, &task); err != nil {
		return nil, err
	}
	if task.Status == protocol.TaskStatusCompleted || task.Status == protocol.TaskStatusFailed || task.Status == protocol.TaskStatusCancelled {
		var result interface{}
		if err := c.Call("tasks/result", map[string]interface{}{"taskId": taskID}, &result); err == nil {
			task.Result = result
		}
	}
	return &task, nil
}

func (c *Client) CancelTask(taskID string) (*protocol.Task, error) {
	var task protocol.Task
	err := c.Call("tasks/cancel", map[string]interface{}{"taskId": taskID}, &task)
	return &task, err
}

func (c *Client) ListTasks() ([]protocol.Task, error) {
	var tasks []protocol.Task
	cursor := ""
	for {
		var result struct {
			Tasks      []protocol.Task `json:"tasks"`
			NextCursor string          `json:"nextCursor"`
		}
		if err := c.Call("tasks/list", map[string]interface{}{"cursor": cursor}, &result); err != nil {
			return nil, err
		}
		tasks = append(tasks, result.Tasks...)
		if result.NextCursor == "" {
			return tasks, nil
		}
		cursor = result.NextCursor
	}
}

func (c *Client) HandleNotifications(handler NotificationHandler) {
	c.notificationMu.Lock()
	c.notificationHandler = handler
	c.notificationMu.Unlock()
}

func (c *Client) HandleRequests(handler RequestHandler) {
	c.requestMu.Lock()
	c.requestHandler = handler
	c.requestMu.Unlock()
}

func (c *Client) HandleRequest(method string, handler RequestHandler) {
	c.requestMu.Lock()
	if handler == nil {
		delete(c.requestHandlers, method)
	} else {
		c.requestHandlers[method] = handler
	}
	c.requestMu.Unlock()
}

func (c *Client) HandleElicitation(handler func(context.Context, protocol.ElicitParams) (protocol.ElicitResult, error)) {
	if handler == nil {
		c.HandleRequest("elicitation/create", nil)
		return
	}
	c.HandleRequest("elicitation/create", func(ctx context.Context, _ string, params json.RawMessage) (interface{}, error) {
		var request protocol.ElicitParams
		if err := json.Unmarshal(params, &request); err != nil {
			return nil, fmt.Errorf("decode elicitation request: %w", err)
		}
		return handler(ctx, request)
	})
}

func (c *Client) HandleRoots(handler func(context.Context) (protocol.ListRootsResult, error)) {
	if handler == nil {
		c.HandleRequest("roots/list", nil)
		return
	}
	c.HandleRequest("roots/list", func(ctx context.Context, _ string, _ json.RawMessage) (interface{}, error) {
		return handler(ctx)
	})
}

func (c *Client) HandleSampling(handler func(context.Context, protocol.CreateMessageParams) (protocol.CreateMessageResult, error)) {
	if handler == nil {
		c.HandleRequest("sampling/createMessage", nil)
		return
	}
	c.HandleRequest("sampling/createMessage", func(ctx context.Context, _ string, params json.RawMessage) (interface{}, error) {
		var request protocol.CreateMessageParams
		if err := json.Unmarshal(params, &request); err != nil {
			return nil, fmt.Errorf("decode sampling request: %w", err)
		}
		return handler(ctx, request)
	})
}

func (c *Client) UnregisterTool(name string) error {
	return c.Call("x-gomcp/tools/unregister", map[string]interface{}{"name": name}, nil)
}

func (c *Client) RegisterToolDefinition(definition protocol.ToolDefinition) error {
	return c.Call("x-gomcp/tools/register", definition, nil)
}

func (c *Client) RegisterPromptDefinition(definition protocol.PromptDefinition) error {
	return c.Call("x-gomcp/prompts/register", definition, nil)
}

func (c *Client) UnregisterPrompt(name string) error {
	return c.Call("x-gomcp/prompts/unregister", map[string]interface{}{"name": name}, nil)
}

func (c *Client) UnregisterResource(uri string) error {
	return c.Call("x-gomcp/resources/unregister", map[string]interface{}{"uri": uri}, nil)
}

func (c *Client) ToolStream(name string, args map[string]interface{}) (<-chan protocol.Response, error) {
	return c.CallStream("tools/call_stream", map[string]interface{}{"name": name, "arguments": args})
}

func (c *Client) PromptStream(name string, args map[string]interface{}) (<-chan protocol.Response, error) {
	return c.CallStream("prompts/get_stream", map[string]interface{}{"name": name, "arguments": args})
}

func (c *Client) CallStream(method string, params interface{}) (<-chan protocol.Response, error) {
	return c.CallStreamContext(context.Background(), method, params)
}

func (c *Client) CallStreamContext(ctx context.Context, method string, params interface{}) (<-chan protocol.Response, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	id := c.nextRequestID()
	idBytes, err := json.Marshal(id)
	if err != nil {
		return nil, err
	}
	paramBytes, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	request := protocol.Request{JSONRPC: "2.0", ID: rawMessagePointer(idBytes), Method: method, Params: paramBytes}
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	httpRequest, err := c.newHTTPRequest(ctx, http.MethodPost, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json, text/event-stream")
	c.stateMu.RLock()
	client := c.httpClient
	c.stateMu.RUnlock()
	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		defer httpResponse.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(httpResponse.Body, 4096))
		return nil, fmt.Errorf("HTTP error %d: %s", httpResponse.StatusCode, strings.TrimSpace(string(body)))
	}

	responses := make(chan protocol.Response, 16)
	go func() {
		defer httpResponse.Body.Close()
		defer close(responses)
		scanner := bufio.NewScanner(httpResponse.Body)
		scanner.Buffer(make([]byte, 64*1024), 1<<20)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if data == "" {
				continue
			}
			var notification protocol.Request
			if err := json.Unmarshal([]byte(data), &notification); err == nil && notification.ID == nil && notification.Method != "" {
				c.dispatchNotification(notification.Method, notification.Params)
				continue
			}
			var response protocol.Response
			if err := json.Unmarshal([]byte(data), &response); err != nil {
				continue
			}
			select {
			case responses <- response:
			case <-ctx.Done():
				return
			}
		}
	}()
	return responses, nil
}

func (c *Client) ListenForNotifications(ctx context.Context) (<-chan protocol.Request, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	request, err := c.newHTTPRequest(ctx, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "text/event-stream")
	c.stateMu.RLock()
	client := c.httpClient
	lastEventID := c.lastEventID
	c.stateMu.RUnlock()
	if lastEventID != "" {
		request.Header.Set("Last-Event-ID", lastEventID)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		defer response.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("notification HTTP error %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}

	notifications := make(chan protocol.Request, 16)
	go func() {
		defer response.Body.Close()
		defer close(notifications)
		scanner := bufio.NewScanner(response.Body)
		scanner.Buffer(make([]byte, 64*1024), 1<<20)
		eventID := ""
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "id:") {
				eventID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
				continue
			}
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if data == "" {
				continue
			}
			var notification protocol.Request
			if err := json.Unmarshal([]byte(data), &notification); err != nil || notification.ID != nil || notification.Method == "" {
				continue
			}
			if eventID != "" {
				c.stateMu.Lock()
				c.lastEventID = eventID
				c.stateMu.Unlock()
			}
			c.dispatchNotification(notification.Method, notification.Params)
			select {
			case notifications <- notification:
			case <-ctx.Done():
				return
			}
		}
	}()
	return notifications, nil
}

func (c *Client) Close() error {
	c.stateMu.RLock()
	transport := c.transport
	c.stateMu.RUnlock()
	if transport == "stdio" {
		return c.StopProcess()
	}
	if transport != "http" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := c.newHTTPRequest(ctx, http.MethodDelete, nil)
	if err != nil {
		return err
	}
	c.stateMu.RLock()
	client := c.httpClient
	c.stateMu.RUnlock()
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("session close HTTP error %d", response.StatusCode)
	}
	c.stateMu.Lock()
	c.initialized = false
	c.sessionID = ""
	c.stateMu.Unlock()
	return nil
}

func (c *Client) newHTTPRequest(ctx context.Context, method string, body io.Reader) (*http.Request, error) {
	c.stateMu.RLock()
	baseURL := c.baseURL
	sessionID := c.sessionID
	protocolVersion := c.protocolVersion
	apiKey := c.apiKey
	tokenSource := c.tokenSource
	c.stateMu.RUnlock()
	if baseURL == "" {
		return nil, fmt.Errorf("HTTP transport is not connected")
	}
	request, err := http.NewRequestWithContext(ctx, method, baseURL+"/mcp", body)
	if err != nil {
		return nil, err
	}
	if sessionID != "" {
		request.Header.Set("MCP-Session-Id", sessionID)
		request.Header.Set("MCP-Protocol-Version", protocolVersion)
	}
	if apiKey != "" {
		request.Header.Set("X-API-Key", apiKey)
	}
	if tokenSource != nil {
		token, err := tokenSource.Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("get bearer token: %w", err)
		}
		if strings.TrimSpace(token) == "" {
			return nil, auth.ErrMissingToken
		}
		request.Header.Set("Authorization", "Bearer "+token)
	}
	return request, nil
}

func (c *Client) nextRequestID() int64 {
	c.idMu.Lock()
	defer c.idMu.Unlock()
	id := c.nextID
	c.nextID++
	return id
}

func (c *Client) dispatchNotification(method string, params json.RawMessage) {
	c.notificationMu.RLock()
	handler := c.notificationHandler
	c.notificationMu.RUnlock()
	if handler != nil {
		handler(method, params)
	}
}

func (c *Client) readStdio(decoder *json.Decoder, done chan struct{}) {
	var readerErr error
	defer func() {
		c.readerErrMu.Lock()
		c.readerErr = readerErr
		c.readerErrMu.Unlock()
		close(done)
	}()

	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			readerErr = err
			return
		}
		var request protocol.Request
		if err := json.Unmarshal(raw, &request); err == nil && request.Method != "" {
			if request.ID == nil {
				c.dispatchNotification(request.Method, request.Params)
			} else {
				go c.handleServerRequest(request)
			}
			continue
		}
		var response protocol.Response
		if err := json.Unmarshal(raw, &response); err != nil || response.ID == nil {
			continue
		}
		requestID := string(*response.ID)
		c.pendingMu.Lock()
		responseChannel := c.pending[requestID]
		delete(c.pending, requestID)
		c.pendingMu.Unlock()
		if responseChannel != nil {
			responseChannel <- stdioResult{response: response}
		}
	}
}

func (c *Client) handleServerRequest(request protocol.Request) {
	c.requestMu.RLock()
	handler := c.requestHandlers[request.Method]
	if handler == nil {
		handler = c.requestHandler
	}
	c.requestMu.RUnlock()
	response := protocol.Response{JSONRPC: "2.0", ID: request.ID}
	if handler == nil {
		response.Error = &protocol.ResponseError{Code: -32601, Message: "Method not found"}
	} else {
		result, err := handler(context.Background(), request.Method, request.Params)
		if err != nil {
			response.Error = &protocol.ResponseError{Code: -32603, Message: err.Error()}
		} else {
			response.Result = result
		}
	}
	_ = c.writeStdio(response)
}

func (c *Client) writeStdio(message interface{}) error {
	c.stateMu.RLock()
	encoder := c.stdioEncoder
	c.stateMu.RUnlock()
	if encoder == nil {
		return fmt.Errorf("stdio transport is not running")
	}
	c.stdioWriteMu.Lock()
	defer c.stdioWriteMu.Unlock()
	return encoder.Encode(message)
}

func (c *Client) removePending(requestID string) {
	c.pendingMu.Lock()
	delete(c.pending, requestID)
	c.pendingMu.Unlock()
}

func mustMarshal(value interface{}) json.RawMessage {
	encoded, _ := json.Marshal(value)
	return encoded
}

func rawMessagePointer(value json.RawMessage) *json.RawMessage {
	copyValue := append(json.RawMessage(nil), value...)
	return &copyValue
}
