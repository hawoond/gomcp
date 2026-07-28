package main

import (
	"fmt"
	"log"

	"github.com/hawoond/gomcp/client"
	"github.com/hawoond/gomcp/protocol"
)

func main() {
	mcpClient := client.NewClient()
	mcpClient.ConnectHTTP("http://127.0.0.1:8080")

	var result protocol.CallToolResult
	if err := mcpClient.Call("tools/call", map[string]interface{}{
		"name":      "add",
		"arguments": map[string]interface{}{"a": 2, "b": 3},
	}, &result); err != nil {
		log.Fatal(err)
	}
	fmt.Println(result.Content[0].Text)
}
