package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/hawoond/gomcp/auth"
	"github.com/hawoond/gomcp/executor"
	"github.com/hawoond/gomcp/internal/types"
	"github.com/hawoond/gomcp/internal/util"
	"go.uber.org/zap"
)

type Resource struct {
	URITemplate string
	Name        string
	Title       string
	Description string
	MimeType    string
	Icons       []types.Icon
	Annotations *types.Annotations
	Meta        map[string]interface{}
	Func        reflect.Value
	ParamCount  int
}

type Tool struct {
	Name            string
	Title           string
	Description     string
	Func            reflect.Value
	ParamTypes      []reflect.Type
	ParamNames      []string
	ParamStructType reflect.Type
	InputSchema     map[string]interface{}
	OutputSchema    map[string]interface{}
	Annotations     *types.ToolAnnotations
	Icons           []types.Icon
	Meta            map[string]interface{}
	Handler         func(context.Context, map[string]interface{}) (interface{}, error)
	TaskSupport     string
}

type Prompt struct {
	Name            string
	Description     string
	Func            reflect.Value
	ParamTypes      []reflect.Type
	ParamNames      []string
	ParamStructType reflect.Type
	Title           string
	Icons           []types.Icon
	Meta            map[string]interface{}
}

type Middleware func(next http.HandlerFunc) http.HandlerFunc

type Server struct {
	Name                      string
	Version                   string
	SupportedProtocolVersions []string
	resources                 []Resource
	tools                     map[string]Tool
	prompts                   map[string]Prompt
	dynamicTools              map[string]types.ToolDefinition
	dynamicPrompts            map[string]types.PromptDefinition
	tasks                     map[string]*types.Task
	taskResults               map[string]interface{}
	taskCancels               map[string]context.CancelFunc
	taskExpires               map[string]time.Time
	taskSessions              map[string]string
	taskNotifiers             map[string]notificationSender
	tasksMu                   sync.RWMutex
	validator                 *validator.Validate
	rwMu                      sync.RWMutex
	logger                    *zap.Logger
	EnableAuth                bool
	APIKey                    string
	bearerVerifier            auth.TokenVerifier
	requiredScopes            []string
	protectedResourceMetadata *auth.ProtectedResourceMetadata
	middlewares               []Middleware
	httpClient                *http.Client
	maxRequestBytes           int64
	maxResponseBytes          int64
	commandTimeout            time.Duration
	taskTTL                   time.Duration
	maxTasks                  int
	allowedOrigins            map[string]struct{}
	allowedCommandPaths       map[string]struct{}
	allowedHTTPHosts          map[string]struct{}
	enableExperimentalMethods bool
	sessions                  map[string]*httpSession
	sessionsMu                sync.RWMutex
	sessionTTL                time.Duration
	maxSessionEvents          int
	statelessHTTP             bool
	stdioTransportsMu         sync.RWMutex
	stdioTransports           map[string]*stdioTransport
	pageSize                  int
	completionHandler         CompletionHandler
	inflightMu                sync.Mutex
	inflight                  map[string]context.CancelFunc
	pendingCancellations      map[string]struct{}
}

func NewServer(name string, version string, enableAuth bool, apiKey string, supportedVersions ...string) *Server {
	logger, _ := zap.NewDevelopment()
	if len(supportedVersions) == 0 {
		supportedVersions = []string{
			types.ProtocolVersion20251125,
			types.ProtocolVersion20250618,
			types.ProtocolVersion20250326,
			types.ProtocolVersion20241105,
		}
	}
	return &Server{
		Name:                      name,
		Version:                   version,
		SupportedProtocolVersions: supportedVersions,
		resources:                 []Resource{},
		tools:                     make(map[string]Tool),
		prompts:                   make(map[string]Prompt),
		dynamicTools:              make(map[string]types.ToolDefinition),
		dynamicPrompts:            make(map[string]types.PromptDefinition),
		tasks:                     make(map[string]*types.Task),
		taskResults:               make(map[string]interface{}),
		taskCancels:               make(map[string]context.CancelFunc),
		taskExpires:               make(map[string]time.Time),
		taskSessions:              make(map[string]string),
		taskNotifiers:             make(map[string]notificationSender),
		validator:                 validator.New(),
		logger:                    logger,
		EnableAuth:                enableAuth,
		APIKey:                    apiKey,
		middlewares:               []Middleware{},
		httpClient:                &http.Client{Timeout: 30 * time.Second},
		maxRequestBytes:           1 << 20,
		maxResponseBytes:          4 << 20,
		commandTimeout:            30 * time.Second,
		taskTTL:                   15 * time.Minute,
		maxTasks:                  1000,
		allowedOrigins:            make(map[string]struct{}),
		allowedCommandPaths:       make(map[string]struct{}),
		allowedHTTPHosts:          make(map[string]struct{}),
		sessions:                  make(map[string]*httpSession),
		sessionTTL:                30 * time.Minute,
		maxSessionEvents:          256,
		pageSize:                  defaultPageSize,
		inflight:                  make(map[string]context.CancelFunc),
		pendingCancellations:      make(map[string]struct{}),
		stdioTransports:           make(map[string]*stdioTransport),
	}
}

func (s *Server) AddResource(uriTemplate string, description string, handler interface{}) error {
	s.rwMu.Lock()
	registered := false
	defer func() {
		s.rwMu.Unlock()
		if registered {
			s.PublishNotification("notifications/resources/list_changed", nil)
		}
	}()
	for _, resource := range s.resources {
		if resource.URITemplate == uriTemplate {
			return fmt.Errorf("resource %q is already registered", uriTemplate)
		}
	}
	fnVal := reflect.ValueOf(handler)
	fnType := fnVal.Type()
	if fnType.Kind() != reflect.Func {
		return fmt.Errorf("handler for resource %s is not a function", uriTemplate)
	}
	paramCount := fnType.NumIn()
	count := strings.Count(uriTemplate, "{")
	if count != fnType.NumIn() {
		return fmt.Errorf("resource %s: number of URI parameters (%d) != function parameters (%d)", uriTemplate, count, fnType.NumIn())
	}
	res := Resource{
		URITemplate: uriTemplate,
		Description: description,
		Func:        fnVal,
		ParamCount:  paramCount,
	}
	s.resources = append(s.resources, res)
	registered = true
	s.logger.Info("Resource registered", zap.String("uriTemplate", uriTemplate))
	return nil
}

func (s *Server) AddTool(name string, description string, handler interface{}, paramStruct interface{}, paramNames ...string) error {
	s.rwMu.Lock()
	registered := false
	defer func() {
		s.rwMu.Unlock()
		if registered {
			s.PublishNotification("notifications/tools/list_changed", nil)
		}
	}()
	fnVal := reflect.ValueOf(handler)
	fnType := fnVal.Type()
	if fnType.Kind() != reflect.Func {
		return fmt.Errorf("handler for tool %s is not a function", name)
	}
	paramCount := fnType.NumIn()
	outCount := fnType.NumOut()
	if outCount > 2 {
		return fmt.Errorf("tool %s: too many return values", name)
	}
	if outCount == 2 && !fnType.Out(1).Implements(reflect.TypeOf((*error)(nil)).Elem()) {
		return fmt.Errorf("tool %s: second return value must implement error", name)
	}
	var paramStructType reflect.Type
	if paramStruct != nil {
		paramStructType = reflect.TypeOf(paramStruct)
		if paramStructType.Kind() != reflect.Struct {
			return fmt.Errorf("paramStruct for tool %s must be a struct type", name)
		}
	}

	var finalParamNames []string
	if len(paramNames) > 0 {
		finalParamNames = paramNames
	} else {
		finalParamNames = make([]string, paramCount)
		for i := 0; i < paramCount; i++ {
			finalParamNames[i] = fmt.Sprintf("param%d", i+1)
		}
	}
	if len(finalParamNames) != paramCount {
		return fmt.Errorf("tool %s: number of provided paramNames (%d) != function parameters (%d)", name, len(finalParamNames), paramCount)
	}
	if _, exists := s.tools[name]; exists {
		return fmt.Errorf("tool %q is already registered", name)
	}

	properties := make(map[string]interface{}, len(finalParamNames))
	for index, paramName := range finalParamNames {
		properties[paramName] = schemaForType(fnType.In(index), make(map[reflect.Type]bool))
	}
	inputSchema := map[string]interface{}{
		"type":                 "object",
		"properties":           properties,
		"required":             append([]string(nil), finalParamNames...),
		"additionalProperties": false,
	}
	if paramStructType != nil {
		inputSchema = schemaForType(paramStructType, make(map[reflect.Type]bool))
	}
	var outputSchema map[string]interface{}
	if outCount > 0 && !fnType.Out(0).Implements(reflect.TypeOf((*error)(nil)).Elem()) {
		outputType := fnType.Out(0)
		comparableOutputType := outputType
		for comparableOutputType.Kind() == reflect.Pointer {
			comparableOutputType = comparableOutputType.Elem()
		}
		if comparableOutputType != reflect.TypeOf(types.CallToolResult{}) {
			outputSchema = schemaForType(outputType, make(map[reflect.Type]bool))
		}
	}
	s.tools[name] = Tool{
		Name:            name,
		Description:     description,
		Func:            fnVal,
		ParamTypes:      util.FuncParamTypes(fnType),
		ParamNames:      finalParamNames,
		ParamStructType: paramStructType,
		InputSchema:     inputSchema,
		OutputSchema:    outputSchema,
		TaskSupport:     "optional",
	}
	registered = true
	s.logger.Info("Tool registered", zap.String("name", name))
	return nil
}

func (s *Server) AddPrompt(name string, description string, handler interface{}, paramStruct interface{}, paramNames ...string) error {
	s.rwMu.Lock()
	registered := false
	defer func() {
		s.rwMu.Unlock()
		if registered {
			s.PublishNotification("notifications/prompts/list_changed", nil)
		}
	}()
	fnVal := reflect.ValueOf(handler)
	fnType := fnVal.Type()
	if fnType.Kind() != reflect.Func {
		return fmt.Errorf("handler for prompt %s is not a function", name)
	}
	paramCount := fnType.NumIn()
	outCount := fnType.NumOut()
	if outCount == 0 || outCount > 2 {
		return fmt.Errorf("prompt %s: handler must return a value and optional error", name)
	}
	if outCount == 2 && !fnType.Out(1).Implements(reflect.TypeOf((*error)(nil)).Elem()) {
		return fmt.Errorf("prompt %s: second return value must implement error", name)
	}
	var paramStructType reflect.Type
	if paramStruct != nil {
		paramStructType = reflect.TypeOf(paramStruct)
		if paramStructType.Kind() != reflect.Struct {
			return fmt.Errorf("paramStruct for prompt %s must be a struct type", name)
		}
	}

	var finalParamNames []string
	if len(paramNames) > 0 {
		finalParamNames = paramNames
	} else {
		finalParamNames = make([]string, paramCount)
		for i := 0; i < paramCount; i++ {
			finalParamNames[i] = fmt.Sprintf("param%d", i+1)
		}
	}
	if len(finalParamNames) != paramCount {
		return fmt.Errorf("prompt %s: number of provided paramNames (%d) != function parameters (%d)", name, len(finalParamNames), paramCount)
	}
	if _, exists := s.prompts[name]; exists {
		return fmt.Errorf("prompt %q is already registered", name)
	}
	s.prompts[name] = Prompt{
		Name:            name,
		Description:     description,
		Func:            fnVal,
		ParamTypes:      util.FuncParamTypes(fnType),
		ParamNames:      finalParamNames,
		ParamStructType: paramStructType,
	}
	registered = true
	s.logger.Info("Prompt registered", zap.String("name", name))
	return nil
}

func (s *Server) RunStdio(reader io.Reader, writer io.Writer) error {
	return s.RunStdioContext(context.Background(), reader, writer)
}

func (s *Server) RunStdioContext(ctx context.Context, reader io.Reader, writer io.Writer) error {
	s.logger.Info("Starting MCP server via STDIO", zap.String("name", s.Name), zap.String("version", s.Version))

	decoder := json.NewDecoder(reader)
	encoder := json.NewEncoder(writer)
	var writerMu sync.Mutex
	var requests sync.WaitGroup
	writeMessage := func(message interface{}) error {
		writerMu.Lock()
		defer writerMu.Unlock()
		return encoder.Encode(message)
	}
	writeResponse := func(response types.Response) error {
		return writeMessage(response)
	}
	sender := notificationSender(func(method string, params interface{}) error {
		request := types.Request{JSONRPC: "2.0", Method: method}
		if params != nil {
			request.Params, _ = json.Marshal(params)
		}
		return writeMessage(request)
	})
	peer := newStdioPeer(writeMessage)
	transportContext := withNotificationSender(ctx, sender)
	transportContext = withPeerRequester(transportContext, peer.request)
	transportID := "stdio:" + uuid.NewString()
	transportContext = withSessionID(transportContext, transportID)
	s.stdioTransportsMu.Lock()
	s.stdioTransports[transportID] = &stdioTransport{
		sender:                sender,
		resourceSubscriptions: make(map[string]struct{}),
	}
	s.stdioTransportsMu.Unlock()
	defer func() {
		s.stdioTransportsMu.Lock()
		delete(s.stdioTransports, transportID)
		s.stdioTransportsMu.Unlock()
	}()
	initialized := false
	stopClose := make(chan struct{})
	if closer, ok := reader.(io.Closer); ok {
		go func() {
			select {
			case <-ctx.Done():
				_ = closer.Close()
			case <-stopClose:
			}
		}()
	}
	defer close(stopClose)
	defer requests.Wait()
	defer peer.close(io.EOF)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return nil
			}
			respErr := s.makeErrorResponse(nil, types.CodeParseError, "Parse error", nil)
			if encodeErr := writeResponse(respErr); encodeErr != nil {
				return encodeErr
			}
			continue
		}
		var envelope struct {
			JSONRPC string               `json:"jsonrpc"`
			ID      *json.RawMessage     `json:"id"`
			Method  string               `json:"method"`
			Result  json.RawMessage      `json:"result"`
			Error   *types.ResponseError `json:"error"`
		}
		if err := json.Unmarshal(raw, &envelope); err == nil && envelope.JSONRPC == "2.0" &&
			envelope.ID != nil && envelope.Method == "" && (len(envelope.Result) > 0 || envelope.Error != nil) {
			var response types.Response
			if err := json.Unmarshal(raw, &response); err == nil {
				peer.deliver(response)
			}
			continue
		}
		var request types.Request
		if err := json.Unmarshal(raw, &request); err != nil || request.JSONRPC != "2.0" || request.Method == "" {
			if err := writeResponse(s.makeErrorResponse(nil, types.CodeInvalidRequest, "Invalid Request", nil)); err != nil {
				return err
			}
			continue
		}
		if !initialized && request.Method != "initialize" {
			if err := writeResponse(s.makeErrorResponse(request.ID, types.CodeInvalidRequest, "initialize must be the first request", nil)); err != nil {
				return err
			}
			continue
		}
		if initialized && request.Method == "initialize" {
			if err := writeResponse(s.makeErrorResponse(request.ID, types.CodeInvalidRequest, "server is already initialized", nil)); err != nil {
				return err
			}
			continue
		}
		if request.Method == "initialize" {
			responses := s.handleMessage(transportContext, raw)
			if len(responses) == 1 && responses[0].Error == nil {
				initialized = true
			}
			for _, response := range responses {
				if err := writeResponse(response); err != nil {
					return err
				}
			}
			continue
		}
		if request.ID == nil {
			s.handleMessage(transportContext, raw)
			continue
		}
		requests.Add(1)
		go func(message json.RawMessage) {
			defer requests.Done()
			for _, response := range s.handleMessage(transportContext, message) {
				if err := writeResponse(response); err != nil {
					s.logger.Error("write stdio response", zap.Error(err))
					return
				}
			}
		}(append(json.RawMessage(nil), raw...))
	}
}

func (s *Server) AddMiddleware(mw Middleware) {
	s.rwMu.Lock()
	defer s.rwMu.Unlock()
	s.middlewares = append(s.middlewares, mw)
}

func (s *Server) ListenAndServe(addr string) error {
	return s.ListenAndServeContext(context.Background(), addr)
}

func (s *Server) ListenAndServeContext(ctx context.Context, addr string) error {
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-serveCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	s.logger.Info("Starting MCP server with Streamable HTTP", zap.String("addr", addr))
	err := httpServer.ListenAndServe()
	stopServe()
	<-shutdownDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	httpHandler := s.authMiddleware(s.handleMcpRequest())
	s.rwMu.RLock()
	for i := len(s.middlewares) - 1; i >= 0; i-- {
		httpHandler = s.middlewares[i](httpHandler)
	}
	s.rwMu.RUnlock()

	mux.HandleFunc("/mcp", httpHandler)
	mux.HandleFunc("/health", s.healthCheckHandler())
	s.rwMu.RLock()
	metadata := s.protectedResourceMetadata
	s.rwMu.RUnlock()
	if metadata != nil {
		mux.HandleFunc("/.well-known/oauth-protected-resource", auth.ProtectedResourceMetadataHandler(*metadata))
	}
	return mux
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.rwMu.RLock()
		verifier := s.bearerVerifier
		requiredScopes := append([]string(nil), s.requiredScopes...)
		metadata := s.protectedResourceMetadata
		s.rwMu.RUnlock()
		if verifier != nil {
			info, err := auth.VerifyRequest(r.Context(), r, verifier, requiredScopes)
			if err != nil {
				challenge := `Bearer error="invalid_token"`
				status := http.StatusUnauthorized
				if errors.Is(err, auth.ErrInsufficientScope) {
					status = http.StatusForbidden
					challenge = `Bearer error="insufficient_scope"`
				}
				if metadata != nil && metadata.Resource != "" {
					challenge += `, resource_metadata="` + strings.TrimRight(metadata.Resource, "/") + `/.well-known/oauth-protected-resource"`
				}
				w.Header().Set("WWW-Authenticate", challenge)
				http.Error(w, http.StatusText(status), status)
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.NewContext(r.Context(), info)))
			return
		}
		if s.EnableAuth {
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" || len(apiKey) != len(s.APIKey) ||
				subtle.ConstantTimeCompare([]byte(apiKey), []byte(s.APIKey)) != 1 {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	}
}

func (s *Server) handleMcpRequest() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.originAllowed(r) {
			http.Error(w, "Forbidden origin", http.StatusForbidden)
			return
		}

		switch r.Method {
		case http.MethodDelete:
			s.deleteSession(w, r)
			return
		case http.MethodGet:
			s.serveNotificationStream(w, r)
			return
		case http.MethodPost:
		default:
			w.Header().Set("Allow", "GET, POST, DELETE")
			http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
			return
		}

		if contentType := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		accept := strings.ToLower(r.Header.Get("Accept"))
		if !strings.Contains(accept, "application/json") || !strings.Contains(accept, "text/event-stream") {
			http.Error(w, "Accept must include application/json and text/event-stream", http.StatusNotAcceptable)
			return
		}

		s.rwMu.RLock()
		maxRequestBytes := s.maxRequestBytes
		s.rwMu.RUnlock()
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)

		var raw json.RawMessage
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&raw); err != nil {
			s.writeJSONRPCError(w, http.StatusBadRequest, nil, types.CodeParseError, "Parse error", nil)
			return
		}
		var extra json.RawMessage
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			s.writeJSONRPCError(w, http.StatusBadRequest, nil, types.CodeInvalidRequest, "Only one JSON-RPC message is allowed", nil)
			return
		}
		if len(raw) == 0 || raw[0] == '[' {
			s.writeJSONRPCError(w, http.StatusBadRequest, nil, types.CodeInvalidRequest, "Batch messages are not supported over HTTP", nil)
			return
		}

		var req types.Request
		if err := json.Unmarshal(raw, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
			s.writeJSONRPCError(w, http.StatusBadRequest, nil, types.CodeInvalidRequest, "Invalid Request", nil)
			return
		}

		isInitialize := req.Method == "initialize"
		sessionID := ""
		if !isInitialize {
			if status, message := s.validateSession(r); status != 0 {
				http.Error(w, message, status)
				return
			}
			sessionID = r.Header.Get("MCP-Session-Id")
		}

		s.rwMu.RLock()
		experimental := s.enableExperimentalMethods
		s.rwMu.RUnlock()
		isStream := experimental && (req.Method == "tools/call_stream" || req.Method == "prompts/get_stream")
		if isStream {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
				return
			}
			s.handleStreamRequest(r.Context(), &req, w, flusher)
			return
		}

		requestContext := withSessionID(r.Context(), sessionID)
		responses := s.handleMessage(requestContext, raw)
		if req.ID == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if len(responses) != 1 {
			s.writeJSONRPCError(w, http.StatusInternalServerError, req.ID, types.CodeInternalError, "Missing response", nil)
			return
		}
		if isInitialize && responses[0].Error == nil {
			protocolVersion := initializationProtocolVersion(responses[0].Result)
			s.rwMu.RLock()
			stateless := s.statelessHTTP
			s.rwMu.RUnlock()
			if !stateless {
				w.Header().Set("MCP-Session-Id", s.createSession(protocolVersion))
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(responses[0]); err != nil {
			s.logger.Error("write JSON-RPC response", zap.Error(err))
		}
	}
}

func (s *Server) serveNotificationStream(w http.ResponseWriter, r *http.Request) {
	s.rwMu.RLock()
	stateless := s.statelessHTTP
	s.rwMu.RUnlock()
	if stateless {
		http.Error(w, "Notification streams are disabled in stateless mode", http.StatusMethodNotAllowed)
		return
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream") {
		http.Error(w, "Accept must include text/event-stream", http.StatusNotAcceptable)
		return
	}
	if status, message := s.validateSession(r); status != 0 {
		http.Error(w, message, status)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}
	lastEventID, err := parseLastEventID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	session, ok := s.session(r.Header.Get("MCP-Session-Id"))
	if !ok {
		http.Error(w, "MCP session not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	_, _ = fmt.Fprint(w, "event: ready\ndata:\n\n")
	flusher.Flush()

	notifications, replay := s.addSessionSubscriber(session, lastEventID)
	defer s.removeSessionSubscriber(session, notifications)
	for _, notification := range replay {
		if _, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", notification.ID, notification.Data); err != nil {
			return
		}
	}
	flusher.Flush()
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case notification, open := <-notifications:
			if !open {
				return
			}
			if _, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", notification.ID, notification.Data); err != nil {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) originAllowed(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	normalized := strings.ToLower(parsed.Scheme + "://" + parsed.Host)
	s.rwMu.RLock()
	_, explicitlyAllowed := s.allowedOrigins[normalized]
	s.rwMu.RUnlock()
	if explicitlyAllowed {
		return true
	}
	requestScheme := "http"
	if r.TLS != nil {
		requestScheme = "https"
	}
	return normalized == strings.ToLower(requestScheme+"://"+r.Host)
}

func (s *Server) validateSession(r *http.Request) (int, string) {
	s.rwMu.RLock()
	stateless := s.statelessHTTP
	s.rwMu.RUnlock()
	if stateless {
		return 0, ""
	}
	sessionID := r.Header.Get("MCP-Session-Id")
	if sessionID == "" {
		return http.StatusBadRequest, "MCP-Session-Id is required"
	}
	session, ok := s.session(sessionID)
	if !ok {
		return http.StatusNotFound, "MCP session not found"
	}
	session.mu.Lock()
	protocolVersion := session.protocolVersion
	session.mu.Unlock()
	if r.Header.Get("MCP-Protocol-Version") != protocolVersion {
		return http.StatusBadRequest, "MCP-Protocol-Version does not match the session"
	}
	return 0, ""
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) {
	if status, message := s.validateSession(r); status != 0 {
		http.Error(w, message, status)
		return
	}
	sessionID := r.Header.Get("MCP-Session-Id")
	s.closeSession(sessionID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) writeJSONRPCError(
	w http.ResponseWriter,
	status int,
	id *json.RawMessage,
	code int,
	message string,
	data interface{},
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(s.makeErrorResponse(id, code, message, data))
}

func initializationProtocolVersion(result interface{}) string {
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return types.LatestProtocolVersion
	}
	version, _ := resultMap["protocolVersion"].(string)
	if version == "" {
		return types.LatestProtocolVersion
	}
	return version
}

func (s *Server) handleMessage(ctx context.Context, raw json.RawMessage) []types.Response {
	var responses []types.Response
	firstChar := []byte(strings.TrimSpace(string(raw)))[0]
	if firstChar == '[' {
		var reqs []types.Request
		if err := json.Unmarshal(raw, &reqs); err != nil {
			resp := s.makeErrorResponse(nil, types.CodeParseError, "Parse error", nil)
			return []types.Response{resp}
		}
		if len(reqs) == 0 {
			resp := s.makeErrorResponse(nil, types.CodeInvalidRequest, "Invalid request", nil)
			return []types.Response{resp}
		}
		for _, req := range reqs {
			resps := s.processRequest(ctx, &req)
			responses = append(responses, resps...)
		}
	} else {
		var req types.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			resp := s.makeErrorResponse(nil, types.CodeParseError, "Parse error", nil)
			return []types.Response{resp}
		}
		if req.JSONRPC != "2.0" || req.Method == "" {
			resp := s.makeErrorResponse(req.ID, types.CodeInvalidRequest, "Invalid Request", nil)
			return []types.Response{resp}
		}
		responses = s.processRequest(ctx, &req)
	}
	return responses
}

func (s *Server) processRequest(ctx context.Context, req *types.Request) []types.Response {
	if req.ID == nil {
		if req.Method == "notifications/initialized" {
			s.logger.Info("Received client initialization complete signal")
			return []types.Response{}
		}
		_, _ = s.routeMethod(ctx, req, nil)
		return []types.Response{}
	}
	requestContext, cancel := context.WithCancel(ctx)
	key := requestKey(ctx, *req.ID)
	s.inflightMu.Lock()
	s.inflight[key] = cancel
	if _, cancelled := s.pendingCancellations[key]; cancelled {
		delete(s.pendingCancellations, key)
		cancel()
	}
	s.inflightMu.Unlock()
	defer func() {
		cancel()
		s.inflightMu.Lock()
		delete(s.inflight, key)
		s.inflightMu.Unlock()
	}()
	var resp types.Response
	resp.ID = req.ID
	resp.JSONRPC = "2.0"
	result, err := s.routeMethod(requestContext, req, &resp.Error)
	if err != nil {
		resp.Result = nil
	} else {
		resp.Result = result
		resp.Error = nil
	}
	return []types.Response{resp}
}

func (s *Server) routeMethod(ctx context.Context, req *types.Request, respErrPtr **types.ResponseError) (interface{}, error) {
	method := req.Method
	s.logger.Info("Routing method", zap.String("method", method))
	switch method {
	case "notifications/cancelled":
		var params types.CancelledParams
		if err := json.Unmarshal(req.Params, &params); err != nil || len(params.RequestID) == 0 {
			return nil, errors.New("invalid cancellation parameters")
		}
		key := requestKey(ctx, params.RequestID)
		s.inflightMu.Lock()
		cancel := s.inflight[key]
		if cancel == nil {
			if len(s.pendingCancellations) >= 1024 {
				for pendingKey := range s.pendingCancellations {
					delete(s.pendingCancellations, pendingKey)
					break
				}
			}
			s.pendingCancellations[key] = struct{}{}
		}
		s.inflightMu.Unlock()
		if cancel != nil {
			cancel()
		}
		return nil, nil

	case "notifications/progress":
		var params types.ProgressParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, errors.New("invalid progress parameters")
		}
		return nil, nil

	case "initialize":
		var params struct {
			ProtocolVersion string                 `json:"protocolVersion"`
			ClientInfo      map[string]interface{} `json:"clientInfo"`
			Capabilities    map[string]interface{} `json:"capabilities"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid initialize parameters", nil)
			return nil, err
		}

		negotiatedVersion := ""
		for _, v := range s.SupportedProtocolVersions {
			if v == params.ProtocolVersion {
				negotiatedVersion = v
				break
			}
		}
		if negotiatedVersion == "" {
			if len(s.SupportedProtocolVersions) == 0 {
				*respErrPtr = s.newError(types.CodeInternalError, "Server has no supported protocol versions", nil)
				return nil, errors.New("no supported protocol versions")
			}
			negotiatedVersion = s.SupportedProtocolVersions[0]
		}

		s.logger.Info("Processing initialize request", zap.Any("client", params.ClientInfo), zap.String("protocolVersion", params.ProtocolVersion))
		serverCaps := map[string]interface{}{
			"tools":       map[string]interface{}{"listChanged": true},
			"resources":   map[string]interface{}{"subscribe": true, "listChanged": true},
			"prompts":     map[string]interface{}{"listChanged": true},
			"completions": map[string]interface{}{},
			"logging":     map[string]interface{}{},
			"tasks": map[string]interface{}{
				"list":   map[string]interface{}{},
				"cancel": map[string]interface{}{},
				"requests": map[string]interface{}{
					"tools": map[string]interface{}{"call": map[string]interface{}{}},
				},
			},
		}
		result := map[string]interface{}{
			"protocolVersion": negotiatedVersion,
			"serverInfo": map[string]interface{}{
				"name":    s.Name,
				"version": s.Version,
			},
			"capabilities": serverCaps,
		}
		return result, nil

	case "ping":
		return map[string]interface{}{}, nil

	case "tools/list":
		var params types.PaginatedParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &params); err != nil {
				*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
				return nil, err
			}
		}
		s.rwMu.RLock()
		toolNames := make([]string, 0, len(s.tools))
		for name := range s.tools {
			toolNames = append(toolNames, name)
		}
		sort.Strings(toolNames)
		toolsList := make([]types.ToolInfo, 0, len(s.tools)+len(s.dynamicTools))
		for _, name := range toolNames {
			tool := s.tools[name]
			entry := types.ToolInfo{
				Name:         name,
				Title:        tool.Title,
				Description:  tool.Description,
				InputSchema:  tool.InputSchema,
				OutputSchema: tool.OutputSchema,
				Annotations:  tool.Annotations,
				Icons:        append([]types.Icon(nil), tool.Icons...),
				Meta:         tool.Meta,
			}
			if tool.TaskSupport != "" {
				entry.Execution = map[string]interface{}{"taskSupport": tool.TaskSupport}
			}
			toolsList = append(toolsList, entry)
		}

		dynamicNames := make([]string, 0, len(s.dynamicTools))
		for name := range s.dynamicTools {
			dynamicNames = append(dynamicNames, name)
		}
		sort.Strings(dynamicNames)
		for _, name := range dynamicNames {
			toolDef := s.dynamicTools[name]
			toolEntry := types.ToolInfo{
				Name:        name,
				Description: toolDef.Description,
				InputSchema: map[string]interface{}{"type": "object"},
			}
			if toolDef.InputSchema != nil {
				var schema map[string]interface{}
				if err := json.Unmarshal(toolDef.InputSchema, &schema); err == nil {
					toolEntry.InputSchema = schema
				}
			}
			toolsList = append(toolsList, toolEntry)
		}
		pageSize := s.pageSize
		s.rwMu.RUnlock()
		page, nextCursor, err := paginate(toolsList, params.Cursor, pageSize)
		if err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, err.Error(), nil)
			return nil, err
		}
		return types.ListToolsResult{Tools: page, NextCursor: nextCursor}, nil

	case "tools/call":
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
			Task      *struct {
				TTL int64 `json:"ttl,omitempty"`
			} `json:"task,omitempty"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
			return nil, errors.New("param parse error")
		}

		s.rwMu.RLock()
		if toolDef, ok := s.dynamicTools[params.Name]; ok {
			s.rwMu.RUnlock()
			if params.Task != nil {
				*respErrPtr = s.newError(types.CodeInvalidParams, "Dynamic tools do not support tasks", nil)
				return nil, errors.New("task unsupported")
			}
			result, err := s.callDynamicTool(ctx, toolDef, params.Arguments, respErrPtr)
			return toToolResult(result, err), nil
		}
		tool, ok := s.tools[params.Name]
		s.rwMu.RUnlock()
		if !ok {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Tool not found", nil)
			return nil, errors.New("tool not found")
		}
		if params.Task != nil {
			if tool.TaskSupport == "forbidden" {
				*respErrPtr = s.newError(types.CodeInvalidParams, "Tool does not support task execution", nil)
				return nil, errors.New("task unsupported")
			}
			task, err := s.startToolTask(ctx, tool, params.Arguments, params.Task.TTL)
			if err != nil {
				*respErrPtr = s.newError(types.CodeServerError, err.Error(), nil)
				return nil, err
			}
			return task, nil
		}
		result, err := s.invokeTool(ctx, tool, params.Arguments)
		return toToolResult(result, err), nil

	case "tools/call_async":
		s.rwMu.RLock()
		experimental := s.enableExperimentalMethods
		s.rwMu.RUnlock()
		if !experimental {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
			return nil, errors.New("experimental methods disabled")
		}
		s.rwMu.RLock()
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.rwMu.RUnlock()
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
			return nil, errors.New("param parse error")
		}
		tool, ok := s.tools[params.Name]
		s.rwMu.RUnlock()
		if !ok {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Tool not found", nil)
			return nil, errors.New("tool not found")
		}
		task, err := s.startToolTask(ctx, tool, params.Arguments, 0)
		if err != nil {
			*respErrPtr = s.newError(types.CodeServerError, err.Error(), nil)
			return nil, err
		}
		return task, nil

	case "tools/get_result":
		s.rwMu.RLock()
		experimental := s.enableExperimentalMethods
		s.rwMu.RUnlock()
		if !experimental {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
			return nil, errors.New("experimental methods disabled")
		}
		var params struct {
			TaskID string `json:"taskId"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
			return nil, errors.New("param parse error")
		}
		task, err := s.getTask(ctx, params.TaskID)
		if err != nil {
			*respErrPtr = s.newError(types.CodeTaskNotFound, "Task not found", nil)
			return nil, err
		}
		return task, nil

	case "tasks/get":
		var params struct {
			TaskID string `json:"taskId"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || params.TaskID == "" {
			*respErrPtr = s.newError(types.CodeInvalidParams, "taskId is required", nil)
			return nil, errors.New("invalid task parameters")
		}
		task, err := s.getTask(ctx, params.TaskID)
		if err != nil {
			*respErrPtr = s.newError(types.CodeTaskNotFound, "Task not found", nil)
			return nil, err
		}
		return task, nil

	case "tasks/result":
		var params struct {
			TaskID string `json:"taskId"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || params.TaskID == "" {
			*respErrPtr = s.newError(types.CodeInvalidParams, "taskId is required", nil)
			return nil, errors.New("invalid task parameters")
		}
		result, err := s.getTaskResult(ctx, params.TaskID)
		if err != nil {
			*respErrPtr = s.newError(types.CodeServerError, err.Error(), nil)
			return nil, err
		}
		return result, nil

	case "tasks/list":
		var params struct {
			Cursor string `json:"cursor,omitempty"`
		}
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &params); err != nil {
				*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
				return nil, err
			}
		}
		tasks, nextCursor, err := s.listTasks(ctx, params.Cursor)
		if err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, err.Error(), nil)
			return nil, err
		}
		result := map[string]interface{}{"tasks": tasks}
		if nextCursor != "" {
			result["nextCursor"] = nextCursor
		}
		return result, nil

	case "tasks/cancel":
		var params struct {
			TaskID string `json:"taskId"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || params.TaskID == "" {
			*respErrPtr = s.newError(types.CodeInvalidParams, "taskId is required", nil)
			return nil, errors.New("invalid task parameters")
		}
		task, err := s.cancelTask(ctx, params.TaskID)
		if err != nil {
			*respErrPtr = s.newError(types.CodeTaskNotFound, "Task not found", nil)
			return nil, err
		}
		return task, nil

	case "tools/call_stream":
		s.rwMu.RLock()
		experimental := s.enableExperimentalMethods
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.rwMu.RUnlock()
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
			return nil, errors.New("param parse error")
		}
		tool, ok := s.tools[params.Name]
		s.rwMu.RUnlock()
		if !experimental {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
			return nil, errors.New("experimental methods disabled")
		}
		if !ok {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Tool not found", nil)
			return nil, errors.New("tool not found")
		}
		return s.invokeTool(ctx, tool, params.Arguments)

	case "prompts/get_stream":
		s.rwMu.RLock()
		defer s.rwMu.RUnlock()
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
			return nil, errors.New("param parse error")
		}
		prompt, ok := s.prompts[params.Name]
		if !ok {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Prompt not found", nil)
			return nil, errors.New("prompt not found")
		}

		args, err := s.prepareFuncArgs(prompt.ParamTypes, params.Arguments, prompt.ParamNames)
		if err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params: "+err.Error(), nil)
			return nil, err
		}

		outVals := prompt.Func.Call(args)
		return s.handleFunctionOutputs(outVals, respErrPtr)

	case "resources/list":
		var params types.PaginatedParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &params); err != nil {
				*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
				return nil, err
			}
		}
		s.rwMu.RLock()
		resources := append([]Resource(nil), s.resources...)
		pageSize := s.pageSize
		s.rwMu.RUnlock()
		sort.Slice(resources, func(i, j int) bool {
			return resources[i].URITemplate < resources[j].URITemplate
		})
		resourcesList := make([]types.ResourceInfo, 0, len(resources))
		for _, res := range resources {
			if strings.Contains(res.URITemplate, "{") {
				continue
			}
			name := res.Name
			if name == "" {
				name = res.URITemplate
			}
			resourcesList = append(resourcesList, types.ResourceInfo{
				Name:        name,
				URI:         res.URITemplate,
				Title:       res.Title,
				Description: res.Description,
				MimeType:    res.MimeType,
				Icons:       append([]types.Icon(nil), res.Icons...),
				Annotations: res.Annotations,
				Meta:        res.Meta,
			})
		}
		page, nextCursor, err := paginate(resourcesList, params.Cursor, pageSize)
		if err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, err.Error(), nil)
			return nil, err
		}
		return types.ListResourcesResult{Resources: page, NextCursor: nextCursor}, nil

	case "resources/templates/list":
		var params types.PaginatedParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &params); err != nil {
				*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
				return nil, err
			}
		}
		s.rwMu.RLock()
		resources := append([]Resource(nil), s.resources...)
		pageSize := s.pageSize
		s.rwMu.RUnlock()
		sort.Slice(resources, func(i, j int) bool {
			return resources[i].URITemplate < resources[j].URITemplate
		})
		templates := make([]types.ResourceTemplate, 0, len(resources))
		for _, res := range resources {
			if !strings.Contains(res.URITemplate, "{") {
				continue
			}
			name := res.Name
			if name == "" {
				name = res.URITemplate
			}
			templates = append(templates, types.ResourceTemplate{
				URITemplate: res.URITemplate,
				Name:        name,
				Title:       res.Title,
				Description: res.Description,
				MimeType:    res.MimeType,
				Icons:       append([]types.Icon(nil), res.Icons...),
				Annotations: res.Annotations,
				Meta:        res.Meta,
			})
		}
		page, nextCursor, err := paginate(templates, params.Cursor, pageSize)
		if err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, err.Error(), nil)
			return nil, err
		}
		return types.ListResourceTemplatesResult{ResourceTemplates: page, NextCursor: nextCursor}, nil

	case "resources/read":
		s.rwMu.RLock()
		resources := append([]Resource(nil), s.resources...)
		s.rwMu.RUnlock()
		var params struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
			return nil, errors.New("param parse error")
		}
		uri := params.URI
		for _, res := range resources {
			vals, match := util.MatchURI(res.URITemplate, uri)
			if match {
				result, err := s.invokeResource(res, uri, vals)
				if err != nil {
					*respErrPtr = s.newError(types.CodeServerError, err.Error(), nil)
					return nil, err
				}
				formatted, err := resourceResult(uri, result)
				if err != nil {
					*respErrPtr = s.newError(types.CodeInternalError, err.Error(), nil)
					return nil, err
				}
				return formatted, nil
			}
		}
		*respErrPtr = s.newError(types.CodeInvalidParams, "Resource not found", nil)
		return nil, errors.New("resource not found")

	case "resources/subscribe", "resources/unsubscribe":
		var params struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || params.URI == "" {
			*respErrPtr = s.newError(types.CodeInvalidParams, "uri is required", nil)
			return nil, errors.New("invalid subscription parameters")
		}
		if err := s.setResourceSubscription(ctx, params.URI, method == "resources/subscribe"); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidRequest, err.Error(), nil)
			return nil, err
		}
		return map[string]interface{}{}, nil

	case "prompts/list":
		var params types.PaginatedParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &params); err != nil {
				*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
				return nil, err
			}
		}
		s.rwMu.RLock()
		promptNames := make([]string, 0, len(s.prompts))
		for name := range s.prompts {
			promptNames = append(promptNames, name)
		}
		sort.Strings(promptNames)
		promptsList := make([]types.PromptInfo, 0, len(s.prompts)+len(s.dynamicPrompts))
		for _, name := range promptNames {
			prompt := s.prompts[name]
			arguments := make([]types.PromptArgument, 0, len(prompt.ParamNames))
			for _, paramName := range prompt.ParamNames {
				arguments = append(arguments, types.PromptArgument{
					Name:     paramName,
					Required: true,
				})
			}
			entry := types.PromptInfo{
				Name:        prompt.Name,
				Title:       prompt.Title,
				Description: prompt.Description,
				Arguments:   arguments,
				Icons:       append([]types.Icon(nil), prompt.Icons...),
				Meta:        prompt.Meta,
			}
			promptsList = append(promptsList, entry)
		}
		dynamicNames := make([]string, 0, len(s.dynamicPrompts))
		for name := range s.dynamicPrompts {
			dynamicNames = append(dynamicNames, name)
		}
		sort.Strings(dynamicNames)
		for _, name := range dynamicNames {
			promptDef := s.dynamicPrompts[name]
			promptEntry := types.PromptInfo{
				Name:        name,
				Description: promptDef.Description,
			}
			promptsList = append(promptsList, promptEntry)
		}
		pageSize := s.pageSize
		s.rwMu.RUnlock()
		page, nextCursor, err := paginate(promptsList, params.Cursor, pageSize)
		if err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, err.Error(), nil)
			return nil, err
		}
		return types.ListPromptsResult{Prompts: page, NextCursor: nextCursor}, nil

	case "prompts/get":
		s.rwMu.RLock()
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.rwMu.RUnlock()
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
			return nil, errors.New("param parse error")
		}

		if promptDef, ok := s.dynamicPrompts[params.Name]; ok {
			s.rwMu.RUnlock()
			return s.callDynamicPrompt(ctx, promptDef, params.Arguments, respErrPtr)
		}
		prompt, ok := s.prompts[params.Name]
		s.rwMu.RUnlock()
		if !ok {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Prompt not found", nil)
			return nil, errors.New("prompt not found")
		}
		value, err := s.invokePrompt(prompt, params.Arguments)
		if err != nil {
			*respErrPtr = s.newError(types.CodeServerError, err.Error(), nil)
			return nil, err
		}
		return promptResult(prompt.Description, value), nil

	case "completion/complete":
		var params types.CompleteParams
		if err := json.Unmarshal(req.Params, &params); err != nil || params.Argument.Name == "" {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid completion parameters", nil)
			return nil, errors.New("invalid completion parameters")
		}
		result, err := s.complete(ctx, params)
		if err != nil {
			*respErrPtr = s.newError(types.CodeServerError, err.Error(), nil)
			return nil, err
		}
		return result, nil

	case "x-gomcp/tools/register", "tools/register":
		if !s.experimentalMethodsEnabled() {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
			return nil, errors.New("experimental methods disabled")
		}
		var toolDef types.ToolDefinition
		if err := json.Unmarshal(req.Params, &toolDef); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params: "+err.Error(), nil)
			return nil, errors.New("param parse error")
		}
		if toolDef.Name == "" {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Tool name is required", nil)
			return nil, errors.New("tool name missing")
		}
		if err := validateDynamicDefinition(toolDef.Type, toolDef.Command, toolDef.HTTP); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, err.Error(), nil)
			return nil, err
		}

		s.rwMu.Lock()
		s.dynamicTools[toolDef.Name] = toolDef
		s.rwMu.Unlock()
		s.PublishNotification("notifications/tools/list_changed", nil)
		s.logger.Info("Dynamic tool registered", zap.String("name", toolDef.Name), zap.String("type", toolDef.Type))
		return map[string]interface{}{"status": "ok", "name": toolDef.Name}, nil

	case "x-gomcp/tools/unregister", "tools/unregister":
		if !s.experimentalMethodsEnabled() {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
			return nil, errors.New("experimental methods disabled")
		}
		var params struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
			return nil, errors.New("param parse error")
		}
		s.rwMu.Lock()
		if _, ok := s.dynamicTools[params.Name]; !ok {
			s.rwMu.Unlock()
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Tool not found", nil)
			return nil, errors.New("tool not found")
		}
		delete(s.dynamicTools, params.Name)
		s.rwMu.Unlock()
		s.PublishNotification("notifications/tools/list_changed", nil)
		s.logger.Info("Tool unregistered", zap.String("name", params.Name))
		return map[string]interface{}{"status": "ok"}, nil

	case "x-gomcp/prompts/register", "prompts/register":
		if !s.experimentalMethodsEnabled() {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
			return nil, errors.New("experimental methods disabled")
		}
		var promptDef types.PromptDefinition
		if err := json.Unmarshal(req.Params, &promptDef); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params: "+err.Error(), nil)
			return nil, errors.New("param parse error")
		}
		if promptDef.Name == "" {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Prompt name is required", nil)
			return nil, errors.New("prompt name missing")
		}
		if err := validateDynamicDefinition(promptDef.Type, promptDef.Command, promptDef.HTTP); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, err.Error(), nil)
			return nil, err
		}

		s.rwMu.Lock()
		s.dynamicPrompts[promptDef.Name] = promptDef
		s.rwMu.Unlock()
		s.PublishNotification("notifications/prompts/list_changed", nil)
		s.logger.Info("Dynamic prompt registered", zap.String("name", promptDef.Name), zap.String("type", promptDef.Type))
		return map[string]interface{}{"status": "ok", "name": promptDef.Name}, nil

	case "x-gomcp/prompts/unregister", "prompts/unregister":
		if !s.experimentalMethodsEnabled() {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
			return nil, errors.New("experimental methods disabled")
		}
		var params struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
			return nil, errors.New("param parse error")
		}
		s.rwMu.Lock()
		if _, ok := s.dynamicPrompts[params.Name]; !ok {
			s.rwMu.Unlock()
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Prompt not found", nil)
			return nil, errors.New("prompt not found")
		}
		delete(s.dynamicPrompts, params.Name)
		s.rwMu.Unlock()
		s.PublishNotification("notifications/prompts/list_changed", nil)
		s.logger.Info("Prompt unregistered", zap.String("name", params.Name))
		return map[string]interface{}{"status": "ok"}, nil

	case "x-gomcp/resources/register", "resources/register":
		*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
		return nil, errors.New("remote resource registration is not supported")

	case "x-gomcp/resources/unregister", "resources/unregister":
		*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
		return nil, errors.New("remote resource unregistration is not supported")

	default:
		if respErrPtr != nil {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
		}
		return nil, errors.New("method not found")
	}
}

func (s *Server) callDynamicTool(ctx context.Context, toolDef types.ToolDefinition, args map[string]interface{}, respErrPtr **types.ResponseError) (interface{}, error) {
	s.logger.Info("Calling dynamic tool", zap.String("name", toolDef.Name), zap.String("type", toolDef.Type))

	switch toolDef.Type {
	case "command":
		if toolDef.Command == nil {
			*respErrPtr = s.newError(types.CodeInternalError, "Command config missing for command type tool", nil)
			return nil, errors.New("command config missing")
		}
		return s.executeCommand(ctx, toolDef.Command, args, respErrPtr)
	case "http":
		if toolDef.HTTP == nil {
			*respErrPtr = s.newError(types.CodeInternalError, "HTTP config missing for http type tool", nil)
			return nil, errors.New("http config missing")
		}
		return s.executeHTTPRequest(ctx, toolDef.HTTP, args, respErrPtr)
	default:
		*respErrPtr = s.newError(types.CodeInvalidParams, "Unsupported dynamic tool type", nil)
		return nil, errors.New("unsupported dynamic tool type")
	}
}

func (s *Server) executeCommand(ctx context.Context, cmdConfig *types.CommandConfig, args map[string]interface{}, respErrPtr **types.ResponseError) (interface{}, error) {
	s.rwMu.RLock()
	policy := executor.Policy{
		AllowedCommands:  copyStringSet(s.allowedCommandPaths),
		HTTPClient:       s.httpClient,
		CommandTimeout:   s.commandTimeout,
		MaxResponseBytes: s.maxResponseBytes,
	}
	s.rwMu.RUnlock()
	output, err := executor.RunCommand(ctx, cmdConfig, args, policy)
	if err != nil {
		s.setExecutorError(respErrPtr, err)
		return nil, err
	}
	return output, nil
}

func (s *Server) executeHTTPRequest(ctx context.Context, httpConfig *types.HTTPConfig, args map[string]interface{}, respErrPtr **types.ResponseError) (interface{}, error) {
	s.rwMu.RLock()
	policy := executor.Policy{
		AllowedHTTPHosts: copyStringSet(s.allowedHTTPHosts),
		HTTPClient:       s.httpClient,
		CommandTimeout:   s.commandTimeout,
		MaxResponseBytes: s.maxResponseBytes,
	}
	s.rwMu.RUnlock()
	output, err := executor.RunHTTP(ctx, httpConfig, args, policy)
	if err != nil {
		s.setExecutorError(respErrPtr, err)
		return nil, err
	}
	return output, nil
}

func (s *Server) setExecutorError(responseError **types.ResponseError, err error) {
	code := types.CodeServerError
	var executionError *executor.Error
	if errors.As(err, &executionError) {
		if executionError.Kind == executor.ErrorConfiguration || executionError.Kind == executor.ErrorPolicy {
			code = types.CodeInvalidParams
		}
		*responseError = s.newError(code, executionError.Error(), executionError.Details)
		return
	}
	*responseError = s.newError(code, err.Error(), nil)
}

func copyStringSet(source map[string]struct{}) map[string]struct{} {
	copySet := make(map[string]struct{}, len(source))
	for value := range source {
		copySet[value] = struct{}{}
	}
	return copySet
}

func (s *Server) callDynamicPrompt(ctx context.Context, promptDef types.PromptDefinition, args map[string]interface{}, respErrPtr **types.ResponseError) (interface{}, error) {
	s.logger.Info("Calling dynamic prompt", zap.String("name", promptDef.Name), zap.String("type", promptDef.Type))

	switch promptDef.Type {
	case "command":
		if promptDef.Command == nil {
			*respErrPtr = s.newError(types.CodeInternalError, "Command config missing for command type prompt", nil)
			return nil, errors.New("command config missing")
		}
		output, err := s.executeCommand(ctx, promptDef.Command, args, respErrPtr)
		if err != nil {
			return nil, err
		}
		// Assuming command output is text for the prompt message
		msg := types.Message{
			Role:    "user",
			Content: types.Content{Type: "text", Text: fmt.Sprintf("%v", output)},
		}
		return map[string]interface{}{"description": promptDef.Description, "messages": []types.Message{msg}}, nil
	case "http":
		if promptDef.HTTP == nil {
			*respErrPtr = s.newError(types.CodeInternalError, "HTTP config missing for http type prompt", nil)
			return nil, errors.New("http config missing")
		}
		output, err := s.executeHTTPRequest(ctx, promptDef.HTTP, args, respErrPtr)
		if err != nil {
			return nil, err
		}
		// Assuming HTTP response is text for the prompt message
		msg := types.Message{
			Role:    "user",
			Content: types.Content{Type: "text", Text: fmt.Sprintf("%v", output)},
		}
		return map[string]interface{}{"description": promptDef.Description, "messages": []types.Message{msg}}, nil
	default:
		*respErrPtr = s.newError(types.CodeInvalidParams, "Unsupported dynamic prompt type", nil)
		return nil, errors.New("unsupported dynamic prompt type")
	}
}

func (s *Server) makeErrorResponse(id *json.RawMessage, code int, message string, data interface{}) types.Response {
	return types.Response{
		JSONRPC: "2.0",
		ID:      id,
		Error: &types.ResponseError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}

func (s *Server) newError(code int, message string, data interface{}) *types.ResponseError {
	return &types.ResponseError{Code: code, Message: message, Data: data}
}

func (s *Server) handleFunctionOutputs(outVals []reflect.Value, respErrPtr **types.ResponseError) (interface{}, error) {
	var errVal error = nil
	var result interface{} = nil
	if len(outVals) == 0 {
		return nil, nil
	}
	if len(outVals) == 1 {
		if outVals[0].IsValid() && outVals[0].Type().Implements(reflect.TypeOf((*error)(nil)).Elem()) {
			if !outVals[0].IsNil() {
				errVal = outVals[0].Interface().(error)
			}
		} else {
			result = outVals[0].Interface()
		}
	} else if len(outVals) == 2 {
		if !outVals[1].IsNil() {
			errVal = outVals[1].Interface().(error)
		}
		result = outVals[0].Interface()
	}
	if errVal != nil {
		if respErrPtr != nil {
			var customErr *types.CustomError
			if errors.As(errVal, &customErr) {
				*respErrPtr = s.newError(customErr.Code, customErr.Message, customErr.Data)
			} else {
				*respErrPtr = s.newError(types.CodeServerError, errVal.Error(), nil)
			}
		}
		return nil, errVal
	}
	return result, nil
}

func (s *Server) prepareFuncArgs(paramTypes []reflect.Type, argsMap map[string]interface{}, paramNames []string) ([]reflect.Value, error) {
	args := make([]reflect.Value, 0, len(paramTypes))
	for i, pType := range paramTypes {
		name := paramNames[i]
		val, ok := argsMap[name]
		if !ok {
			return nil, fmt.Errorf("missing required parameter \"%s\"", name)
		}
		argVal, err := util.ConvertType(val, pType)
		if err != nil {
			return nil, fmt.Errorf("parameter \"%s\" type error: %v", name, err)
		}
		args = append(args, argVal)
	}
	return args, nil
}

func (s *Server) healthCheckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}
}

func (s *Server) handleStreamRequest(ctx context.Context, req *types.Request, w http.ResponseWriter, flusher http.Flusher) {
	var respErr *types.ResponseError
	result, err := s.routeMethod(ctx, req, &respErr)

	if err != nil {
		if respErr == nil {
			respErr = s.newError(types.CodeInternalError, err.Error(), nil)
		}
		resp := s.makeErrorResponse(req.ID, respErr.Code, respErr.Message, respErr.Data)
		data, _ := json.Marshal(resp)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		return
	}

	value := reflect.ValueOf(result)
	if value.Kind() != reflect.Chan {
		resp := types.Response{ID: req.ID, JSONRPC: "2.0", Result: result}
		data, _ := json.Marshal(resp)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		return
	}
	if value.IsNil() || value.Type().ChanDir() == reflect.SendDir {
		resp := s.makeErrorResponse(req.ID, types.CodeInternalError, "Handler returned an unreadable channel", nil)
		data, _ := json.Marshal(resp)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		return
	}

	for {
		selected, item, ok := reflect.Select([]reflect.SelectCase{
			{Dir: reflect.SelectRecv, Chan: value},
			{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ctx.Done())},
		})
		if selected == 1 {
			return
		}
		if !ok {
			return
		}
		partialResp := types.Response{
			ID:      req.ID,
			JSONRPC: "2.0",
			Result:  item.Interface(),
		}
		data, _ := json.Marshal(partialResp)
		if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
			return
		}
		flusher.Flush()
	}
}
