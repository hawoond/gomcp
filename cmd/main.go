package main

import (
	"flag"
	"log"
	"os"

	"github.com/hawoond/gomcp/server"
)

func main() {
	mode := flag.String("mode", "stdio", "Server operation mode: stdio or http")
	addr := flag.String("addr", ":8080", "Binding address for HTTP mode (e.g., :8080)")
	enableAuth := flag.Bool("enable-auth", false, "Enable API Key authentication for HTTP mode")
	apiKey := flag.String("api-key", "", "API Key for authentication (required if --enable-auth is true)")
	flag.Parse()

	mcpServer := server.NewServer("DemoApp", "1.0.0", *enableAuth, *apiKey)

	type AddParams struct {
		A int `validate:"required"`
		B int `validate:"required"`
	}
	mcpServer.AddTool("add", "Calculate the sum of two numbers", func(a int, b int) int {
		return a + b
	}, AddParams{}, "a", "b")
	mcpServer.AddResource("greeting://{name}", "Greeting message by name", func(name string) string {
		return "Hello, " + name + "!"
	})
	type EchoPromptParams struct {
		Message string `validate:"required" json:"Message"`
	}
	mcpServer.AddPrompt("echoPrompt", "Prompt that returns the message as-is", func(message string) string {
		return "Please process this message: " + message
	}, EchoPromptParams{}, "message")

	if *mode == "http" {
		log.Fatal(mcpServer.ListenAndServe(*addr))
	} else {
		if err := s.RunStdio(os.Stdin, os.Stdout); err != nil {
		}
	}
}
