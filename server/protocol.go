package server

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/hawoond/gomcp/internal/types"
)

const defaultPageSize = 100

type CompletionHandler func(context.Context, types.CompleteParams) (types.CompleteResult, error)
type notificationSender func(string, interface{}) error
type notificationSenderContextKey struct{}

func encodeCursor(offset int) string {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(offset))
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func decodeCursor(cursor string) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(raw) != 8 {
		return 0, fmt.Errorf("invalid cursor")
	}
	offset := binary.BigEndian.Uint64(raw)
	if uint64(int(offset)) != offset {
		return 0, fmt.Errorf("cursor is out of range")
	}
	return int(offset), nil
}

func paginate[T any](items []T, cursor string, pageSize int) ([]T, string, error) {
	offset, err := decodeCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	if offset > len(items) {
		return nil, "", fmt.Errorf("cursor is out of range")
	}
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	end := offset + pageSize
	if end > len(items) {
		end = len(items)
	}
	nextCursor := ""
	if end < len(items) {
		nextCursor = encodeCursor(end)
	}
	return items[offset:end], nextCursor, nil
}

func (s *Server) complete(ctx context.Context, params types.CompleteParams) (types.CompleteResult, error) {
	s.rwMu.RLock()
	handler := s.completionHandler
	s.rwMu.RUnlock()
	if handler == nil {
		return types.CompleteResult{Completion: types.Completion{Values: []string{}}}, nil
	}
	return handler(ctx, params)
}

func requestKey(ctx context.Context, requestID json.RawMessage) string {
	sessionID := sessionIDFromContext(ctx)
	if sessionID == "" {
		sessionID = "stdio"
	}
	return sessionID + ":" + string(requestID)
}

func withNotificationSender(ctx context.Context, sender notificationSender) context.Context {
	return context.WithValue(ctx, notificationSenderContextKey{}, sender)
}

func notificationSenderFromContext(ctx context.Context) notificationSender {
	sender, _ := ctx.Value(notificationSenderContextKey{}).(notificationSender)
	return sender
}

func (s *Server) SendNotification(ctx context.Context, method string, params interface{}) error {
	if sender := notificationSenderFromContext(ctx); sender != nil {
		return sender(method, params)
	}
	if sessionIDFromContext(ctx) != "" {
		s.PublishSessionNotification(ctx, method, params)
		return nil
	}
	return fmt.Errorf("request context has no notification transport")
}

func (s *Server) Log(ctx context.Context, level, logger string, data interface{}) error {
	return s.SendNotification(ctx, "notifications/message", types.LoggingMessageParams{
		Level:  level,
		Logger: logger,
		Data:   data,
	})
}
