package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/hawoond/gomcp/internal/types"
	"github.com/hawoond/gomcp/internal/util"
	"go.uber.org/zap"
)

type Resource struct {
	URITemplate string
	Description string
	Func        reflect.Value
	ParamCount  int
}

type Tool struct {
	Name            string
	Description     string
	Func            reflect.Value
	ParamTypes      []reflect.Type
	ParamNames      []string
	ParamStructType reflect.Type
	InputSchema     map[string]interface{}
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
	tasksMu                   sync.RWMutex
	validator                 *validator.Validate
	rwMu                      sync.RWMutex
	logger                    *zap.Logger
	EnableAuth                bool
	APIKey                    string
	eventSubscribers          map[chan []byte]bool
	subscribersMu             sync.RWMutex
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
	sessions                  map[string]string
	sessionsMu                sync.RWMutex
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
		validator:                 validator.New(),
		logger:                    logger,
		EnableAuth:                enableAuth,
		APIKey:                    apiKey,
		eventSubscribers:          make(map[chan []byte]bool),
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
		sessions:                  make(map[string]string),
	}
}

func (s *Server) AddResource(uriTemplate string, description string, handler interface{}) error {
	s.rwMu.Lock()
	defer s.rwMu.Unlock()
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
	s.logger.Info("Resource registered", zap.String("uriTemplate", uriTemplate))
	return nil
}

func (s *Server) AddTool(name string, description string, handler interface{}, paramStruct interface{}, paramNames ...string) error {
	s.rwMu.Lock()
	defer s.rwMu.Unlock()
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
	s.tools[name] = Tool{
		Name:            name,
		Description:     description,
		Func:            fnVal,
		ParamTypes:      util.FuncParamTypes(fnType),
		ParamNames:      finalParamNames,
		ParamStructType: paramStructType,
		InputSchema:     inputSchema,
		TaskSupport:     "optional",
	}
	s.logger.Info("Tool registered", zap.String("name", name))
	return nil
}

func (s *Server) AddPrompt(name string, description string, handler interface{}, paramStruct interface{}, paramNames ...string) error {
	s.rwMu.Lock()
	defer s.rwMu.Unlock()
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
			if encodeErr := encoder.Encode(respErr); encodeErr != nil {
				return encodeErr
			}
			continue
		}
		var request types.Request
		if err := json.Unmarshal(raw, &request); err != nil || request.JSONRPC != "2.0" || request.Method == "" {
			if err := encoder.Encode(s.makeErrorResponse(nil, types.CodeInvalidRequest, "Invalid Request", nil)); err != nil {
				return err
			}
			continue
		}
		if !initialized && request.Method != "initialize" {
			if err := encoder.Encode(s.makeErrorResponse(request.ID, types.CodeInvalidRequest, "initialize must be the first request", nil)); err != nil {
				return err
			}
			continue
		}
		if initialized && request.Method == "initialize" {
			if err := encoder.Encode(s.makeErrorResponse(request.ID, types.CodeInvalidRequest, "server is already initialized", nil)); err != nil {
				return err
			}
			continue
		}
		responses := s.handleMessage(ctx, raw)
		if request.Method == "initialize" && len(responses) == 1 && responses[0].Error == nil {
			initialized = true
		}
		for _, resp := range responses {
			if err := encoder.Encode(resp); err != nil {
				return err
			}
		}
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
	return mux
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
			w.Header().Set("Allow", "POST, DELETE")
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
		if !isInitialize {
			if status, message := s.validateSession(r); status != 0 {
				http.Error(w, message, status)
				return
			}
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

		responses := s.handleMessage(r.Context(), raw)
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
			sessionID := uuid.NewString()
			s.sessionsMu.Lock()
			s.sessions[sessionID] = protocolVersion
			s.sessionsMu.Unlock()
			w.Header().Set("MCP-Session-Id", sessionID)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(responses[0]); err != nil {
			s.logger.Error("write JSON-RPC response", zap.Error(err))
		}
	}
}

func (s *Server) serveNotificationStream(w http.ResponseWriter, r *http.Request) {
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
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	_, _ = fmt.Fprint(w, "event: ready\ndata:\n\n")
	flusher.Flush()

	notifications := make(chan []byte, 64)
	s.addSubscriber(notifications)
	defer s.removeSubscriber(notifications)
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case notification, open := <-notifications:
			if !open {
				return
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", notification); err != nil {
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
	sessionID := r.Header.Get("MCP-Session-Id")
	if sessionID == "" {
		return http.StatusBadRequest, "MCP-Session-Id is required"
	}
	s.sessionsMu.RLock()
	protocolVersion, ok := s.sessions[sessionID]
	s.sessionsMu.RUnlock()
	if !ok {
		return http.StatusNotFound, "MCP session not found"
	}
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
	s.sessionsMu.Lock()
	delete(s.sessions, sessionID)
	s.sessionsMu.Unlock()
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
	var resp types.Response
	resp.ID = req.ID
	resp.JSONRPC = "2.0"
	result, err := s.routeMethod(ctx, req, &resp.Error)
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
			"tools":     map[string]interface{}{"listChanged": false},
			"resources": map[string]interface{}{"subscribe": false, "listChanged": false},
			"prompts":   map[string]interface{}{"listChanged": false},
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

	case "tools/list":
		s.rwMu.RLock()
		defer s.rwMu.RUnlock()
		toolNames := make([]string, 0, len(s.tools))
		for name := range s.tools {
			toolNames = append(toolNames, name)
		}
		sort.Strings(toolNames)
		toolsList := make([]map[string]interface{}, 0, len(s.tools)+len(s.dynamicTools))
		for _, name := range toolNames {
			tool := s.tools[name]
			entry := map[string]interface{}{
				"name":        name,
				"description": tool.Description,
				"inputSchema": tool.InputSchema,
			}
			if tool.TaskSupport != "" {
				entry["execution"] = map[string]interface{}{"taskSupport": tool.TaskSupport}
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
			toolEntry := map[string]interface{}{
				"name":        name,
				"description": toolDef.Description,
			}
			if toolDef.InputSchema != nil {
				var schema map[string]interface{}
				json.Unmarshal(toolDef.InputSchema, &schema)
				toolEntry["inputSchema"] = schema
			}
			toolsList = append(toolsList, toolEntry)
		}

		result := map[string]interface{}{
			"tools": toolsList,
		}
		return result, nil

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
			task, err := s.startToolTask(tool, params.Arguments, params.Task.TTL)
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
		task, err := s.startToolTask(tool, params.Arguments, 0)
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
		task, err := s.getTask(params.TaskID)
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
		task, err := s.getTask(params.TaskID)
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
		result, err := s.getTaskResult(params.TaskID)
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
		tasks, nextCursor := s.listTasks(params.Cursor)
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
		task, err := s.cancelTask(params.TaskID)
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
		s.rwMu.RLock()
		defer s.rwMu.RUnlock()
		resources := append([]Resource(nil), s.resources...)
		sort.Slice(resources, func(i, j int) bool {
			return resources[i].URITemplate < resources[j].URITemplate
		})
		resourcesList := make([]map[string]interface{}, 0, len(resources))
		for _, res := range resources {
			resourcesList = append(resourcesList, map[string]interface{}{
				"name":        res.URITemplate,
				"uri":         res.URITemplate,
				"description": res.Description,
			})
		}
		result := map[string]interface{}{
			"resources": resourcesList,
		}
		return result, nil

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

	case "prompts/list":
		s.rwMu.RLock()
		defer s.rwMu.RUnlock()
		promptNames := make([]string, 0, len(s.prompts))
		for name := range s.prompts {
			promptNames = append(promptNames, name)
		}
		sort.Strings(promptNames)
		promptsList := make([]map[string]interface{}, 0, len(s.prompts)+len(s.dynamicPrompts))
		for _, name := range promptNames {
			prompt := s.prompts[name]
			arguments := make([]map[string]interface{}, 0, len(prompt.ParamNames))
			for _, paramName := range prompt.ParamNames {
				arguments = append(arguments, map[string]interface{}{
					"name":     paramName,
					"required": true,
				})
			}
			entry := map[string]interface{}{
				"name":        prompt.Name,
				"description": prompt.Description,
			}
			if len(arguments) > 0 {
				entry["arguments"] = arguments
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
			promptEntry := map[string]interface{}{
				"name":        name,
				"description": promptDef.Description,
			}
			promptsList = append(promptsList, promptEntry)
		}
		result := map[string]interface{}{
			"prompts": promptsList,
		}
		return result, nil

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

	case "tools/register":
		if !s.experimentalMethodsEnabled() {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
			return nil, errors.New("experimental methods disabled")
		}
		s.rwMu.Lock()
		defer s.rwMu.Unlock()
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

		s.dynamicTools[toolDef.Name] = toolDef
		s.logger.Info("Dynamic tool registered", zap.String("name", toolDef.Name), zap.String("type", toolDef.Type))
		return map[string]interface{}{"status": "ok", "name": toolDef.Name}, nil

	case "tools/unregister":
		if !s.experimentalMethodsEnabled() {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
			return nil, errors.New("experimental methods disabled")
		}
		s.rwMu.Lock()
		defer s.rwMu.Unlock()
		var params struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
			return nil, errors.New("param parse error")
		}
		if _, ok := s.dynamicTools[params.Name]; !ok {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Tool not found", nil)
			return nil, errors.New("tool not found")
		}
		delete(s.dynamicTools, params.Name)
		s.logger.Info("Tool unregistered", zap.String("name", params.Name))
		return map[string]interface{}{"status": "ok"}, nil

	case "prompts/register":
		if !s.experimentalMethodsEnabled() {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
			return nil, errors.New("experimental methods disabled")
		}
		s.rwMu.Lock()
		defer s.rwMu.Unlock()
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

		s.dynamicPrompts[promptDef.Name] = promptDef
		s.logger.Info("Dynamic prompt registered", zap.String("name", promptDef.Name), zap.String("type", promptDef.Type))
		return map[string]interface{}{"status": "ok", "name": promptDef.Name}, nil

	case "prompts/unregister":
		if !s.experimentalMethodsEnabled() {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
			return nil, errors.New("experimental methods disabled")
		}
		s.rwMu.Lock()
		defer s.rwMu.Unlock()
		var params struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
			return nil, errors.New("param parse error")
		}
		if _, ok := s.dynamicPrompts[params.Name]; !ok {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Prompt not found", nil)
			return nil, errors.New("prompt not found")
		}
		delete(s.dynamicPrompts, params.Name)
		s.logger.Info("Prompt unregistered", zap.String("name", params.Name))
		return map[string]interface{}{"status": "ok"}, nil

	case "resources/register":
		*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
		return nil, errors.New("remote resource registration is not supported")

	case "resources/unregister":
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
	resolvedPath, err := exec.LookPath(cmdConfig.Path)
	if err != nil {
		*respErrPtr = s.newError(types.CodeInvalidParams, "Command is not available", nil)
		return nil, err
	}
	s.rwMu.RLock()
	_, allowed := s.allowedCommandPaths[resolvedPath]
	timeout := s.commandTimeout
	maxOutputBytes := s.maxResponseBytes
	s.rwMu.RUnlock()
	if !allowed {
		err := fmt.Errorf("command %q is not allowlisted", resolvedPath)
		*respErrPtr = s.newError(types.CodeInvalidParams, err.Error(), nil)
		return nil, err
	}
	if cmdConfig.TimeoutMillis > 0 {
		configuredTimeout := time.Duration(cmdConfig.TimeoutMillis) * time.Millisecond
		if configuredTimeout < timeout {
			timeout = configuredTimeout
		}
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmdArgs := make([]string, 0, len(cmdConfig.Args)+len(args))
	cmdArgs = append(cmdArgs, cmdConfig.Args...)
	argNames := make([]string, 0, len(args))
	for name := range args {
		argNames = append(argNames, name)
	}
	sort.Strings(argNames)
	for _, name := range argNames {
		cmdArgs = append(cmdArgs, fmt.Sprintf("%v", args[name]))
	}

	output := newLimitedBuffer(maxOutputBytes)
	cmd := exec.CommandContext(commandCtx, resolvedPath, cmdArgs...)
	cmd.Stdout = output
	cmd.Stderr = output
	err = cmd.Run()
	if output.Exceeded() {
		err = errOutputLimitExceeded
	}
	if err != nil {
		*respErrPtr = s.newError(types.CodeServerError, "Command execution failed: "+err.Error(), output.String())
		return nil, err
	}
	return output.String(), nil
}

func (s *Server) executeHTTPRequest(ctx context.Context, httpConfig *types.HTTPConfig, args map[string]interface{}, respErrPtr **types.ResponseError) (interface{}, error) {
	targetURL, err := url.Parse(httpConfig.URL)
	if err != nil || (targetURL.Scheme != "http" && targetURL.Scheme != "https") || targetURL.Hostname() == "" {
		err = errors.New("invalid HTTP target URL")
		*respErrPtr = s.newError(types.CodeInvalidParams, err.Error(), nil)
		return nil, err
	}
	host := strings.ToLower(targetURL.Hostname())
	s.rwMu.RLock()
	_, allowed := s.allowedHTTPHosts[host]
	if !allowed {
		_, allowed = s.allowedHTTPHosts[strings.ToLower(targetURL.Host)]
	}
	baseClient := s.httpClient
	maxResponseBytes := s.maxResponseBytes
	s.rwMu.RUnlock()
	if !allowed {
		err = fmt.Errorf("HTTP host %q is not allowlisted", host)
		*respErrPtr = s.newError(types.CodeInvalidParams, err.Error(), nil)
		return nil, err
	}
	if err := validatePublicHost(ctx, host); err != nil {
		*respErrPtr = s.newError(types.CodeInvalidParams, err.Error(), nil)
		return nil, err
	}

	method := strings.ToUpper(httpConfig.Method)
	if method == "" {
		method = http.MethodPost
	}
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		err = fmt.Errorf("HTTP method %q is not allowed", method)
		*respErrPtr = s.newError(types.CodeInvalidParams, err.Error(), nil)
		return nil, err
	}

	var reqBody io.Reader
	if httpConfig.Body != "" {
		bodyContent := httpConfig.Body
		for k, v := range args {
			bodyContent = strings.ReplaceAll(bodyContent, "{"+k+"}", fmt.Sprintf("%v", v))
		}
		reqBody = strings.NewReader(bodyContent)
	} else if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		jsonArgs, marshalErr := json.Marshal(args)
		if marshalErr != nil {
			*respErrPtr = s.newError(types.CodeInternalError, "Failed to marshal arguments to JSON: "+marshalErr.Error(), nil)
			return nil, marshalErr
		}
		reqBody = bytes.NewReader(jsonArgs)
	}

	requestCtx := ctx
	cancel := func() {}
	if httpConfig.TimeoutMillis > 0 {
		requestCtx, cancel = context.WithTimeout(ctx, time.Duration(httpConfig.TimeoutMillis)*time.Millisecond)
	}
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, method, targetURL.String(), reqBody)
	if err != nil {
		*respErrPtr = s.newError(types.CodeInternalError, "Failed to create HTTP request: "+err.Error(), nil)
		return nil, err
	}
	for k, v := range httpConfig.Headers {
		if strings.EqualFold(k, "Host") {
			continue
		}
		req.Header.Set(k, v)
	}
	if (method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch) && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	client := *baseClient
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		*respErrPtr = s.newError(types.CodeServerError, "HTTP request failed: "+err.Error(), nil)
		return nil, err
	}
	defer resp.Body.Close()

	if httpConfig.MaxResponseBytes > 0 && httpConfig.MaxResponseBytes < maxResponseBytes {
		maxResponseBytes = httpConfig.MaxResponseBytes
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		*respErrPtr = s.newError(types.CodeServerError, "Failed to read HTTP response body: "+err.Error(), nil)
		return nil, err
	}
	if int64(len(respBody)) > maxResponseBytes {
		err = fmt.Errorf("HTTP response exceeds %d bytes", maxResponseBytes)
		*respErrPtr = s.newError(types.CodeServerError, err.Error(), nil)
		return nil, err
	}
	if resp.StatusCode >= 400 {
		err = fmt.Errorf("HTTP request failed with status %d", resp.StatusCode)
		*respErrPtr = s.newError(types.CodeServerError, err.Error(), string(respBody))
		return nil, err
	}
	return string(respBody), nil
}

func validatePublicHost(ctx context.Context, host string) error {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve HTTP host %q: %w", host, err)
	}
	if len(addresses) == 0 {
		return fmt.Errorf("HTTP host %q has no addresses", host)
	}
	for _, address := range addresses {
		ip := address.IP
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("HTTP host %q resolves to a non-public address", host)
		}
	}
	return nil
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

func (s *Server) addSubscriber(ch chan []byte) {
	s.subscribersMu.Lock()
	defer s.subscribersMu.Unlock()
	s.eventSubscribers[ch] = true
	s.logger.Info("Added new event subscriber")
}

func (s *Server) removeSubscriber(ch chan []byte) {
	s.subscribersMu.Lock()
	defer s.subscribersMu.Unlock()
	delete(s.eventSubscribers, ch)
	close(ch)
	s.logger.Info("Removed event subscriber")
}

func (s *Server) PublishNotification(method string, params interface{}) {
	s.subscribersMu.RLock()
	defer s.subscribersMu.RUnlock()

	notification := types.Request{
		JSONRPC: "2.0",
		Method:  method,
	}
	if params != nil {
		paramBytes, _ := json.Marshal(params)
		notification.Params = json.RawMessage(paramBytes)
	}
	notificationBytes, _ := json.Marshal(notification)

	s.logger.Info("Publishing notification", zap.String("method", method), zap.Int("subscriberCount", len(s.eventSubscribers)))
	for ch := range s.eventSubscribers {
		select {
		case ch <- notificationBytes:
		default:
			// Don't block if the channel is full
		}
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
