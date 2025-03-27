package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"sync"

	"mcp/internal/types"
	"mcp/internal/util"
)

type Client struct {
	transport string
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	baseURL   string
	mu        sync.Mutex
	nextID    int
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

func (c *Client) ConnectHTTP(baseURL string) {
	c.transport = "http"
	c.baseURL = baseURL
}

func (c *Client) Initialize(clientName string, clientVersion string) error {
	params := map[string]interface{}{
		"protocolVersion": "2024-11-05",
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
