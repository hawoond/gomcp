package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"

	"github.com/hawoond/gomcp/internal/types"
	"github.com/hawoond/gomcp/internal/util"
)

type NotificationHandler func(method string, params json.RawMessage)

type Client struct {
	transport           string
	cmd                 *exec.Cmd
	stdin               io.WriteCloser
	stdout              io.ReadCloser
	baseURL             string
	mu                  sync.Mutex
	nextID              int
	notificationHandler NotificationHandler
}

func NewClient() *Client {
	return &Client{nextID: 1}
}

func (c *Client) StartProcess(command string, args ...string) error {
	c.transport = "stdio"
	c.cmd = exec.Command(command, args...)
	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stdin, err := c.cmd.StdinPipe()
	if err != nil {
		return err
	}
	c.stdout = stdout
	c.stdin = stdin
	if err := c.cmd.Start(); err != nil {
		return err
	}
	return nil
}

func (c *Client) StopProcess() error {
	if c.cmd != nil {
		if err := c.cmd.Process.Kill(); err != nil {
			return err
		}
	}
	if c.stdin != nil {
		if err := c.stdin.Close(); err != nil {
			return err
		}
	}
	if c.stdout != nil {
		if err := c.stdout.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) ConnectHTTP(baseURL string) {
	c.transport = "http"
	c.baseURL = baseURL
}

func (c *Client) Initialize(clientName string, clientVersion string, protocolVersion string) error {
	params := map[string]interface{}{
		"protocolVersion": protocolVersion,
		"clientInfo": map[string]string{
			"name":    clientName,
			"version": clientVersion,
		},
		"capabilities": map[string]interface{}{},
	}
	var result map[string]interface{}
	if err := c.Call("initialize", params, &result); err != nil {
		return err
	}
	return nil
}

func (c *Client) ListTools() ([]map[string]interface{}, error) {
	var result struct {
		Tools []map[string]interface{} `json:"tools"`
	}
	err := c.Call("tools/list", map[string]interface{}{}, &result)
	return result.Tools, err
}

func (c *Client) ListPrompts() ([]map[string]interface{}, error) {
	var result struct {
		Prompts []map[string]interface{} `json:"prompts"`
	}
	err := c.Call("prompts/list", map[string]interface{}{}, &result)
	return result.Prompts, err
}

func (c *Client) ListResources() ([]map[string]interface{}, error) {
	var result struct {
		Resources []map[string]interface{} `json:"resources"`
	}
	err := c.Call("resources/list", map[string]interface{}{}, &result)
	return result.Resources, err
}

func (c *Client) Call(method string, params interface{}, result interface{}) error {
	c.mu.Lock()
	id := c.nextID
	c.nextID++
	c.mu.Unlock()
	reqObj := types.Request{
		JSONRPC: "2.0",
		Method:  method,
	}
	idBytes, _ := json.Marshal(id)
	rawID := json.RawMessage(idBytes)
	reqObj.ID = &rawID
	if params != nil {
		paramBytes, _ := json.Marshal(params)
		reqObj.Params = json.RawMessage(paramBytes)
	}
	reqBytes, _ := json.Marshal(reqObj)
	var respBytes []byte
	var err error
	if c.transport == "stdio" {
		_, err = c.stdin.Write(reqBytes)
		if err != nil {
			return err
		}
		_, err = c.stdin.Write([]byte("\n"))
		if err != nil {
			return err
		}
		buf := make([]byte, 65536)
		n, err := c.stdout.Read(buf)
		if err != nil {
			return err
		}
		respBytes = buf[:n]
	} else if c.transport == "http" {
		url := c.baseURL + "/mcp"
		resp, err2 := http.Post(url, "application/json", util.BytesReader(reqBytes))
		if err2 != nil {
			return err2
		}
		defer resp.Body.Close()
		respBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(respBytes))
		}
	} else {
		return fmt.Errorf("client not connected")
	}
	var respObj types.Response
	if err := json.Unmarshal(respBytes, &respObj); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if respObj.Error != nil {
		return fmt.Errorf("RPC error %d: %s", respObj.Error.Code, respObj.Error.Message)
	}
	if result != nil {
		resBytes, _ := json.Marshal(respObj.Result)
		_ = json.Unmarshal(resBytes, result)
	}
	return nil
}

func (c *Client) CallAsync(toolName string, arguments map[string]interface{}) (string, error) {
	params := map[string]interface{}{
		"name":      toolName,
		"arguments": arguments,
	}
	var result struct {
		TaskID string `json:"taskId"`
	}
	if err := c.Call("tools/call_async", params, &result); err != nil {
		return "", err
	}
	return result.TaskID, nil
}

func (c *Client) GetResult(taskID string) (*types.Task, error) {
	params := map[string]interface{}{
		"taskId": taskID,
	}
	var result types.Task
	if err := c.Call("tools/get_result", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) HandleNotifications(handler NotificationHandler) {
	c.notificationHandler = handler
}

func (c *Client) UnregisterTool(name string) error {
	params := map[string]interface{}{"name": name}
	return c.Call("tools/unregister", params, nil)
}

func (c *Client) UnregisterPrompt(name string) error {
	params := map[string]interface{}{"name": name}
	return c.Call("prompts/unregister", params, nil)
}

func (c *Client) UnregisterResource(uri string) error {
	params := map[string]interface{}{"uri": uri}
	return c.Call("resources/unregister", params, nil)
}

func (c *Client) ToolStream(toolName string, arguments map[string]interface{}) (<-chan types.Response, error) {
	params := map[string]interface{}{
		"name":      toolName,
		"arguments": arguments,
	}
	return c.CallStream("tools/call_stream", params)
}

func (c *Client) PromptStream(promptName string, arguments map[string]interface{}) (<-chan types.Response, error) {
	params := map[string]interface{}{
		"name":      promptName,
		"arguments": arguments,
	}
	return c.CallStream("prompts/get_stream", params)
}

func (c *Client) CallStream(method string, params interface{}) (<-chan types.Response, error) {
	if c.transport != "http" {
		return nil, fmt.Errorf("streaming is only supported over HTTP")
	}

	c.mu.Lock()
	id := c.nextID
	c.nextID++
	c.mu.Unlock()

	reqObj := types.Request{
		JSONRPC: "2.0",
		Method:  method,
	}
	idBytes, _ := json.Marshal(id)
	rawID := json.RawMessage(idBytes)
	reqObj.ID = &rawID
	if params != nil {
		paramBytes, _ := json.Marshal(params)
		reqObj.Params = json.RawMessage(paramBytes)
	}
	reqBytes, _ := json.Marshal(reqObj)

	url := c.baseURL + "/mcp"
	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	ch := make(chan types.Response)

	go func() {
		defer resp.Body.Close()
		defer close(ch)

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				data := strings.TrimPrefix(line, "data: ")
				var req types.Request
				if err := json.Unmarshal([]byte(data), &req); err == nil && req.ID == nil { // It's a notification
					if c.notificationHandler != nil {
						c.notificationHandler(req.Method, req.Params)
					}
					continue
				}

				var respObj types.Response
				if err := json.Unmarshal([]byte(data), &respObj); err == nil {
					ch <- respObj
				}
			}
		}
	}()

	return ch, nil
}

func (c *Client) ListenForNotifications(ctx context.Context) (<-chan types.Request, error) {
	if c.transport != "http" {
		return nil, fmt.Errorf("notifications are only supported over HTTP")
	}

	url := c.baseURL + "/mcp"
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)) // Dummy request to establish SSE
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	notificationCh := make(chan types.Request)

	go func() {
		defer resp.Body.Close()
		defer close(notificationCh)

		scanner := bufio.NewScanner(resp.Body)
		for {
			select {
			case <-ctx.Done():
				resp.Body.Close()
				return
			default:
				if !scanner.Scan() {
					return // Scanner finished or encountered an error
				}
				line := scanner.Text()
				if strings.HasPrefix(line, "data: ") {
					data := strings.TrimPrefix(line, "data: ")
					var notification types.Request
					if err := json.Unmarshal([]byte(data), &notification); err == nil && notification.ID == nil {
						select {
						case notificationCh <- notification:
						case <-ctx.Done():
							resp.Body.Close() // Close body explicitly on context done
							return
						}
					}
				}
			}
		}
	}()

	return notificationCh, nil
}
