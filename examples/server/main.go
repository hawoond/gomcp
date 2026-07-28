package main

import (
	"context"
	"log"
	"os"

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
	mcpServer := server.NewServer("calculator", "0.1.0", false, "")
	if err := server.RegisterTool(mcpServer, "add", "Add two integers", func(_ context.Context, input addInput) (addOutput, error) {
		return addOutput{Result: input.A + input.B}, nil
	}); err != nil {
		log.Fatal(err)
	}
	if err := mcpServer.RunStdio(os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}
