package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/hawoond/gomcp/server"
)

type addInput struct {
	A int `json:"a"`
	B int `json:"b"`
}

type addOutput struct {
	Result int `json:"result"`
}

func main() {
	mode := flag.String("mode", "stdio", "Server operation mode: stdio or http")
	addr := flag.String("addr", "127.0.0.1:8080", "Binding address for HTTP mode")
	enableAuth := flag.Bool("enable-auth", false, "Enable API key authentication for HTTP mode")
	apiKey := flag.String("api-key", "", "API key for HTTP authentication")
	flag.Parse()

	if *mode != "stdio" && *mode != "http" {
		log.Fatal("mode must be stdio or http")
	}
	if *mode == "http" && *enableAuth && *apiKey == "" {
		log.Fatal("api-key is required when authentication is enabled")
	}

	mcpServer := server.NewServer("DemoApp", "0.1.0", *enableAuth, *apiKey)
	if err := server.RegisterTool(mcpServer, "add", "Calculate the sum of two numbers", func(_ context.Context, input addInput) (addOutput, error) {
		return addOutput{Result: input.A + input.B}, nil
	}); err != nil {
		log.Fatal(err)
	}
	if err := mcpServer.AddResource("greeting://{name}", "Greeting message by name", func(name string) string {
		return "Hello, " + name + "!"
	}); err != nil {
		log.Fatal(err)
	}
	if err := mcpServer.AddPrompt("echoPrompt", "Prompt that returns the message as-is", func(message string) string {
		return fmt.Sprintf("Please process this message: %s", message)
	}, nil, "message"); err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *mode == "http" {
		if err := mcpServer.ListenAndServeContext(ctx, *addr); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := mcpServer.RunStdioContext(ctx, os.Stdin, os.Stdout); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}
