package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/hawoond/gomcp/internal/types"
)

type peerRequester func(context.Context, string, interface{}, interface{}) error
type peerRequesterContextKey struct{}

type peerResult struct {
	response types.Response
	err      error
}

type stdioPeer struct {
	write   func(interface{}) error
	nextID  atomic.Uint64
	mu      sync.Mutex
	pending map[string]chan peerResult
}

func newStdioPeer(write func(interface{}) error) *stdioPeer {
	return &stdioPeer{write: write, pending: make(map[string]chan peerResult)}
}

func (p *stdioPeer) request(ctx context.Context, method string, params interface{}, result interface{}) error {
	requestID := fmt.Sprintf("\"server-%d\"", p.nextID.Add(1))
	rawID := json.RawMessage(requestID)
	rawParams, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("encode peer request parameters: %w", err)
	}
	responseChannel := make(chan peerResult, 1)
	p.mu.Lock()
	p.pending[requestID] = responseChannel
	p.mu.Unlock()
	if err := p.write(types.Request{
		JSONRPC: "2.0",
		ID:      &rawID,
		Method:  method,
		Params:  rawParams,
	}); err != nil {
		p.remove(requestID)
		return err
	}

	select {
	case peerResponse := <-responseChannel:
		if peerResponse.err != nil {
			return peerResponse.err
		}
		if peerResponse.response.Error != nil {
			return fmt.Errorf("peer RPC error %d: %s", peerResponse.response.Error.Code, peerResponse.response.Error.Message)
		}
		if result == nil {
			return nil
		}
		encoded, err := json.Marshal(peerResponse.response.Result)
		if err != nil {
			return fmt.Errorf("encode peer response: %w", err)
		}
		if err := json.Unmarshal(encoded, result); err != nil {
			return fmt.Errorf("decode peer response: %w", err)
		}
		return nil
	case <-ctx.Done():
		p.remove(requestID)
		return ctx.Err()
	}
}

func (p *stdioPeer) deliver(response types.Response) {
	if response.ID == nil {
		return
	}
	requestID := string(*response.ID)
	p.mu.Lock()
	responseChannel := p.pending[requestID]
	delete(p.pending, requestID)
	p.mu.Unlock()
	if responseChannel != nil {
		responseChannel <- peerResult{response: response}
	}
}

func (p *stdioPeer) close(err error) {
	p.mu.Lock()
	pending := p.pending
	p.pending = make(map[string]chan peerResult)
	p.mu.Unlock()
	for _, responseChannel := range pending {
		responseChannel <- peerResult{err: err}
	}
}

func (p *stdioPeer) remove(requestID string) {
	p.mu.Lock()
	delete(p.pending, requestID)
	p.mu.Unlock()
}

func withPeerRequester(ctx context.Context, requester peerRequester) context.Context {
	return context.WithValue(ctx, peerRequesterContextKey{}, requester)
}

func (s *Server) RequestClient(ctx context.Context, method string, params interface{}, result interface{}) error {
	requester, _ := ctx.Value(peerRequesterContextKey{}).(peerRequester)
	if requester == nil {
		return fmt.Errorf("request context does not support client requests")
	}
	return requester(ctx, method, params, result)
}

func (s *Server) Elicit(ctx context.Context, params types.ElicitParams) (types.ElicitResult, error) {
	var result types.ElicitResult
	err := s.RequestClient(ctx, "elicitation/create", params, &result)
	return result, err
}

func (s *Server) ListRoots(ctx context.Context) (types.ListRootsResult, error) {
	var result types.ListRootsResult
	err := s.RequestClient(ctx, "roots/list", map[string]interface{}{}, &result)
	return result, err
}

func (s *Server) CreateMessage(ctx context.Context, params types.CreateMessageParams) (types.CreateMessageResult, error) {
	var result types.CreateMessageResult
	err := s.RequestClient(ctx, "sampling/createMessage", params, &result)
	return result, err
}
