package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestToolAndResource(t *testing.T) {
	srv := NewServer("TestApp", "0.1.0")
	srv.AddTool("echo", "Message Echo", func(msg string) string {
		return "Echo: " + msg
	})
	srv.AddResource("const://hello", "Fixed Greeting", func() string {
		return "Hello World"
	})
	reqList := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	respListArr := srv.handleMessage(json.RawMessage(reqList))
	if len(respListArr) != 1 {
		t.Fatalf("Expected one response, got %d", len(respListArr))
	}
	respList := respListArr[0]
	if respList.Error != nil {
		t.Errorf("tools/list error: %+v", respList.Error)
	}
	data, _ := json.Marshal(respList.Result)
	strData := string(data)
	if !contains(strData, "echo") {
		t.Errorf("tools/list result missing 'echo': %s", strData)
	}

	reqCall := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"param1":"TestMsg"}}}`
	respCallArr := srv.handleMessage(json.RawMessage(reqCall))
	respCall := respCallArr[0]
	if respCall.Error != nil {
		t.Errorf("tools/call error: %+v", respCall.Error)
	}
	expected := "Echo: TestMsg"
	got := extractResultText(respCall.Result)
	if got != expected {
		t.Errorf("tools/call echo expected '%s', got '%s'", expected, got)
	}

	reqRes := `{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"const://hello"}}`
	respResArr := srv.handleMessage(json.RawMessage(reqRes))
	respRes := respResArr[0]
	if respRes.Error != nil {
		t.Errorf("resources/read error: %+v", respRes.Error)
	}
	resText := fmt.Sprintf("%v", respRes.Result)
	if resText != "Hello World" && resText != "\"Hello World\"" {
		t.Errorf("resources/read expected 'Hello World', got %s", resText)
	}
}

func contains(str, substr string) bool {
	return len(str) >= len(substr) && strings.Contains(str, substr)
}

func extractResultText(result interface{}) string {
	bytes, _ := json.Marshal(result)
	if idx := indexOf(bytes, []byte("Echo:")); idx != -1 {
		start := idx
		end := indexOf(bytes[start:], []byte("\""))
		if end != -1 {
			return string(bytes[start : start+end])
		}
	}
	return fmt.Sprintf("%v", result)
}

func indexOf(data []byte, sub []byte) int {
	for i := 0; i+len(sub) <= len(data); i++ {
		if string(data[i:i+len(sub)]) == string(sub) {
			return i
		}
	}
	return -1
}
