package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hawoond/gomcp/internal/types"
)

type sessionContextKey struct{}

type sessionEvent struct {
	ID   uint64
	Data []byte
}

type httpSession struct {
	mu                    sync.Mutex
	protocolVersion       string
	lastSeen              time.Time
	nextEventID           uint64
	history               []sessionEvent
	subscribers           map[chan sessionEvent]struct{}
	resourceSubscriptions map[string]struct{}
}

type stdioTransport struct {
	mu                    sync.Mutex
	sender                notificationSender
	resourceSubscriptions map[string]struct{}
}

func newHTTPSession(protocolVersion string) *httpSession {
	return &httpSession{
		protocolVersion:       protocolVersion,
		lastSeen:              time.Now(),
		nextEventID:           1,
		subscribers:           make(map[chan sessionEvent]struct{}),
		resourceSubscriptions: make(map[string]struct{}),
	}
}

func withSessionID(ctx context.Context, sessionID string) context.Context {
	if sessionID == "" {
		return ctx
	}
	return context.WithValue(ctx, sessionContextKey{}, sessionID)
}

func sessionIDFromContext(ctx context.Context) string {
	sessionID, _ := ctx.Value(sessionContextKey{}).(string)
	return sessionID
}

func (s *Server) createSession(protocolVersion string) string {
	sessionID := uuid.NewString()
	s.sessionsMu.Lock()
	s.pruneSessionsLocked(time.Now())
	s.sessions[sessionID] = newHTTPSession(protocolVersion)
	s.sessionsMu.Unlock()
	return sessionID
}

func (s *Server) session(sessionID string) (*httpSession, bool) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	s.pruneSessionsLocked(time.Now())
	session, ok := s.sessions[sessionID]
	if ok {
		session.mu.Lock()
		session.lastSeen = time.Now()
		session.mu.Unlock()
	}
	return session, ok
}

func (s *Server) pruneSessionsLocked(now time.Time) {
	for sessionID, session := range s.sessions {
		session.mu.Lock()
		expired := s.sessionTTL > 0 && now.Sub(session.lastSeen) > s.sessionTTL
		if expired {
			for subscriber := range session.subscribers {
				close(subscriber)
			}
			session.subscribers = make(map[chan sessionEvent]struct{})
		}
		session.mu.Unlock()
		if expired {
			delete(s.sessions, sessionID)
		}
	}
}

func (s *Server) closeSession(sessionID string) {
	s.sessionsMu.Lock()
	session, ok := s.sessions[sessionID]
	if ok {
		delete(s.sessions, sessionID)
	}
	s.sessionsMu.Unlock()
	if !ok {
		return
	}
	session.mu.Lock()
	for subscriber := range session.subscribers {
		close(subscriber)
	}
	session.subscribers = make(map[chan sessionEvent]struct{})
	session.mu.Unlock()
}

func (s *Server) addSessionSubscriber(session *httpSession, afterID uint64) (chan sessionEvent, []sessionEvent) {
	notifications := make(chan sessionEvent, 64)
	session.mu.Lock()
	replay := make([]sessionEvent, 0)
	for _, event := range session.history {
		if event.ID > afterID {
			replay = append(replay, event)
		}
	}
	session.subscribers[notifications] = struct{}{}
	session.lastSeen = time.Now()
	session.mu.Unlock()
	return notifications, replay
}

func (s *Server) removeSessionSubscriber(session *httpSession, notifications chan sessionEvent) {
	session.mu.Lock()
	if _, ok := session.subscribers[notifications]; ok {
		delete(session.subscribers, notifications)
		close(notifications)
	}
	session.mu.Unlock()
}

func (s *Server) publishToSession(session *httpSession, method string, params interface{}) {
	notification := types.Request{JSONRPC: "2.0", Method: method}
	if params != nil {
		notification.Params, _ = json.Marshal(params)
	}
	data, err := json.Marshal(notification)
	if err != nil {
		return
	}

	s.sessionsMu.RLock()
	maxEvents := s.maxSessionEvents
	s.sessionsMu.RUnlock()
	session.mu.Lock()
	event := sessionEvent{ID: session.nextEventID, Data: data}
	session.nextEventID++
	session.history = append(session.history, event)
	if len(session.history) > maxEvents {
		session.history = append([]sessionEvent(nil), session.history[len(session.history)-maxEvents:]...)
	}
	for subscriber := range session.subscribers {
		select {
		case subscriber <- event:
		default:
		}
	}
	session.mu.Unlock()
}

func (s *Server) PublishNotification(method string, params interface{}) {
	s.sessionsMu.RLock()
	sessions := make([]*httpSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.sessionsMu.RUnlock()
	for _, session := range sessions {
		s.publishToSession(session, method, params)
	}
	s.stdioTransportsMu.RLock()
	senders := make([]notificationSender, 0, len(s.stdioTransports))
	for _, transport := range s.stdioTransports {
		senders = append(senders, transport.sender)
	}
	s.stdioTransportsMu.RUnlock()
	for _, sender := range senders {
		_ = sender(method, params)
	}
}

func (s *Server) PublishSessionNotification(ctx context.Context, method string, params interface{}) {
	sessionID := sessionIDFromContext(ctx)
	if sessionID == "" {
		return
	}
	if session, ok := s.session(sessionID); ok {
		s.publishToSession(session, method, params)
	}
}

func (s *Server) NotifyResourceUpdated(uri string) {
	s.sessionsMu.RLock()
	sessions := make([]*httpSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.sessionsMu.RUnlock()
	for _, session := range sessions {
		session.mu.Lock()
		_, subscribed := session.resourceSubscriptions[uri]
		session.mu.Unlock()
		if subscribed {
			s.publishToSession(session, "notifications/resources/updated", map[string]string{"uri": uri})
		}
	}
	s.stdioTransportsMu.RLock()
	transports := make([]*stdioTransport, 0, len(s.stdioTransports))
	for _, transport := range s.stdioTransports {
		transports = append(transports, transport)
	}
	s.stdioTransportsMu.RUnlock()
	for _, transport := range transports {
		transport.mu.Lock()
		_, subscribed := transport.resourceSubscriptions[uri]
		sender := transport.sender
		transport.mu.Unlock()
		if subscribed {
			_ = sender("notifications/resources/updated", map[string]string{"uri": uri})
		}
	}
}

func (s *Server) setResourceSubscription(ctx context.Context, uri string, subscribe bool) error {
	sessionID := sessionIDFromContext(ctx)
	if sessionID == "" {
		return fmt.Errorf("resource subscriptions require a stateful HTTP session")
	}
	if len(sessionID) > len("stdio:") && sessionID[:len("stdio:")] == "stdio:" {
		s.stdioTransportsMu.RLock()
		transport := s.stdioTransports[sessionID]
		s.stdioTransportsMu.RUnlock()
		if transport == nil {
			return fmt.Errorf("stdio transport not found")
		}
		transport.mu.Lock()
		if subscribe {
			transport.resourceSubscriptions[uri] = struct{}{}
		} else {
			delete(transport.resourceSubscriptions, uri)
		}
		transport.mu.Unlock()
		return nil
	}
	session, ok := s.session(sessionID)
	if !ok {
		return fmt.Errorf("MCP session not found")
	}
	session.mu.Lock()
	if subscribe {
		session.resourceSubscriptions[uri] = struct{}{}
	} else {
		delete(session.resourceSubscriptions, uri)
	}
	session.mu.Unlock()
	return nil
}

func parseLastEventID(request *http.Request) (uint64, error) {
	value := request.Header.Get("Last-Event-ID")
	if value == "" {
		return 0, nil
	}
	eventID, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("Last-Event-ID must be an unsigned integer")
	}
	return eventID, nil
}
