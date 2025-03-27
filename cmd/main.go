package main

import (
	"flag"
	"log"

	"mcp/server"
)

func main() {
	mode := flag.String("mode", "stdio", "Server operation mode: stdio or http")
	addr := flag.String("addr", ":8080", "Binding address for HTTP mode (e.g., :8080)")
	flag.Parse()

	mcpServer := server.NewServer("DemoApp", "1.0.0")

	mcpServer.AddTool("add", "Calculate the sum of two numbers", func(a int, b int) int {
		return a + b
	})
	mcpServer.AddResource("greeting://{name}", "Greeting message by name", func(name string) string {
		return "Hello, " + name + "!"
	})
	mcpServer.AddPrompt("echoPrompt", "Prompt that returns the message as-is", func(message string) string {
		return "Please process this message: " + message
	})

	if *mode == "http" {
		log.Fatal(mcpServer.ListenAndServe(*addr))
	} else {
		log.Fatal(mcpServer.RunStdio())
	}
}
