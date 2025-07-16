package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"sync"
	"syscall"

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
}

type Prompt struct {
	Name            string
	Description     string
	Func            reflect.Value
	ParamTypes      []reflect.Type
	ParamNames      []string
	ParamStructType reflect.Type
}

type Server struct {
	Name         string
	Version      string
	resources    []Resource
	tools        map[string]Tool
	prompts      map[string]Prompt
	tasks        map[string]*types.Task
	tasksMu      sync.RWMutex
	mu           sync.Mutex
	shuttingDown bool
	validator    *validator.Validate
	rwMu         sync.RWMutex
	logger       *zap.Logger
	EnableAuth   bool
	APIKey       string
}

func NewServer(name string, version string, enableAuth bool, apiKey string) *Server {
	logger, _ := zap.NewDevelopment()
	return &Server{
		Name:       name,
		Version:    version,
		resources:  []Resource{},
		tools:      make(map[string]Tool),
		prompts:    make(map[string]Prompt),
		tasks:      make(map[string]*types.Task),
		validator:  validator.New(),
		logger:     logger,
		EnableAuth: enableAuth,
		APIKey:     apiKey,
	}
}

func (s *Server) AddResource(uriTemplate string, description string, handler interface{}) error {
	s.rwMu.Lock()
	defer s.rwMu.Unlock()
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
	s.tools[name] = Tool{
		Name:            name,
		Description:     description,
		Func:            fnVal,
		ParamTypes:      util.FuncParamTypes(fnType),
		ParamNames:      finalParamNames,
		ParamStructType: paramStructType,
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

func (s *Server) RunStdio() error {
	s.logger.Info("Starting MCP server via STDIO", zap.String("name", s.Name), zap.String("version", s.Version))

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		s.logger.Info("Shutdown signal received - shutting down server...")
		s.shuttingDown = true
		cancel() // Signal context cancellation
	}()

	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("Server context cancelled, exiting STDIO loop.")
			return nil
		default:
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) || s.shuttingDown {
					s.logger.Info("STDIO input closed or server shutting down.")
					return nil
				}
				respErr := s.makeErrorResponse(nil, types.CodeParseError, "Parse error", nil)
				_ = encoder.Encode(respErr)
				continue
			}
			responses := s.handleMessage(raw)
			for _, resp := range responses {
				_ = encoder.Encode(resp)
			}
		}
	}
}

func (s *Server) ListenAndServe(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", s.authMiddleware(s.handleMcpRequest()))
	mux.HandleFunc("/health", s.healthCheckHandler())
	s.logger.Info("Starting MCP server with HTTP SSE", zap.String("addr", addr))
	return http.ListenAndServe(addr, mux)
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.EnableAuth {
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" || apiKey != s.APIKey {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	}
}

func (s *Server) handleMcpRequest() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
			return
		}
		wantsSSE := strings.Contains(r.Header.Get("Accept"), "text/event-stream")
		var raw json.RawMessage
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&raw); err != nil {
			respErr := s.makeErrorResponse(nil, types.CodeParseError, "Parse error", nil)
			respBytes, _ := json.Marshal(respErr)
			if wantsSSE {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprintf(w, "data: %s\n\n", respBytes)
			} else {
				http.Error(w, string(respBytes), http.StatusBadRequest)
			}
			return
		}

		var req types.Request
		isStream := false
		if wantsSSE {
			if err := json.Unmarshal(raw, &req); err == nil {
				if req.Method == "tools/call_stream" || req.Method == "prompts/get_stream" {
					isStream = true
				}
			}
		}

		if isStream {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
				return
			}
			s.handleStreamRequest(&req, w, flusher)
			return
		}

		responses := s.handleMessage(raw)
		if wantsSSE {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
				return
			}
			for _, resp := range responses {
				data, _ := json.Marshal(resp)
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
		} else {
			var out interface{}
			if len(responses) == 1 {
				out = responses[0]
			} else {
				out = responses
			}
			w.Header().Set("Content-Type", "application/json")
			enc := json.NewEncoder(w)
			_ = enc.Encode(out)
		}
	}
}

func (s *Server) handleMessage(raw json.RawMessage) []types.Response {
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
			resps := s.processRequest(&req)
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
		responses = s.processRequest(&req)
	}
	return responses
}

func (s *Server) processRequest(req *types.Request) []types.Response {
	if req.ID == nil {
		if req.Method == "notifications/initialized" {
			s.logger.Info("Received client initialization complete signal")
			return []types.Response{}
		}
		_, _ = s.routeMethod(req, nil)
		return []types.Response{}
	}
	var resp types.Response
	resp.ID = req.ID
	resp.JSONRPC = "2.0"
	result, err := s.routeMethod(req, &resp.Error)
	if err != nil {
		resp.Result = nil
	} else {
		resp.Result = result
		resp.Error = nil
	}
	return []types.Response{resp}
}

func (s *Server) routeMethod(req *types.Request, respErrPtr **types.ResponseError) (interface{}, error) {
	method := req.Method
	switch method {

	case "initialize":
		var params struct {
			ProtocolVersion string                 `json:"protocolVersion"`
			ClientInfo      map[string]interface{} `json:"clientInfo"`
			Capabilities    map[string]interface{} `json:"capabilities"`
		}
		_ = json.Unmarshal(req.Params, &params)
		s.logger.Info("Processing initialize request", zap.Any("client", params.ClientInfo), zap.String("protocolVersion", params.ProtocolVersion))
		serverCaps := map[string]interface{}{}
		if len(s.tools) > 0 {
			serverCaps["tools"] = map[string]interface{}{}
		}
		if len(s.resources) > 0 {
			serverCaps["resources"] = map[string]interface{}{}
		}
		if len(s.prompts) > 0 {
			serverCaps["prompts"] = map[string]interface{}{}
		}
		result := map[string]interface{}{
			"protocolVersion": params.ProtocolVersion,
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
		toolsList := []map[string]interface{}{}
		for name, tool := range s.tools {
			propMap := map[string]interface{}{}
			for i, pType := range tool.ParamTypes {
				prop := map[string]interface{}{}
				switch pType.Kind() {
				case reflect.Int, reflect.Int64, reflect.Float32, reflect.Float64:
					prop["type"] = "number"
				case reflect.Bool:
					prop["type"] = "boolean"
				default:
					prop["type"] = "string"
				}
				propMap[tool.ParamNames[i]] = prop
			}
			schema := map[string]interface{}{
				"type":       "object",
				"properties": propMap,
			}
			reqFields := []string{}
			for _, name := range tool.ParamNames {
				reqFields = append(reqFields, name)
			}
			schema["required"] = reqFields

			toolsList = append(toolsList, map[string]interface{}{
				"name":        name,
				"description": tool.Description,
				"inputSchema": schema,
			})
		}
		result := map[string]interface{}{
			"tools": toolsList,
		}
		return result, nil

	case "tools/call":
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
		tool, ok := s.tools[params.Name]
		if !ok {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Tool not found", nil)
			return nil, errors.New("tool not found")
		}

		if tool.ParamStructType != nil {
			paramInstance := reflect.New(tool.ParamStructType).Interface()
			jsonParams, _ := json.Marshal(params.Arguments)
			if err := json.Unmarshal(jsonParams, paramInstance); err != nil {
				*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params: "+err.Error(), nil)
				return nil, err
			}
			if err := s.validator.Struct(paramInstance); err != nil {
				*respErrPtr = s.newError(types.CodeInvalidParams, "Validation error: "+err.Error(), nil)
				return nil, err
			}
		}
		args, err := s.prepareFuncArgs(tool.ParamTypes, params.Arguments, tool.ParamNames)
		if err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params: "+err.Error(), nil)
			return nil, err
		}
		outVals := tool.Func.Call(args)
		return s.handleFunctionOutputs(outVals, respErrPtr)

	case "tools/call_async":
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
		tool, ok := s.tools[params.Name]
		if !ok {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Tool not found", nil)
			return nil, errors.New("tool not found")
		}

		taskID := uuid.New().String()
		task := &types.Task{ID: taskID, Status: types.TaskStatusRunning}
		s.tasksMu.Lock()
		s.tasks[taskID] = task
		s.tasksMu.Unlock()

		go func() {
			args, err := s.prepareFuncArgs(tool.ParamTypes, params.Arguments, tool.ParamNames)
			if err != nil {
				task.Status = types.TaskStatusFailed
				task.Error = s.newError(types.CodeInvalidParams, "Invalid params: "+err.Error(), nil)
				return
			}

			outVals := tool.Func.Call(args)
			result, err := s.handleFunctionOutputs(outVals, &task.Error)

			s.tasksMu.Lock()
			defer s.tasksMu.Unlock()
			if err != nil {
				task.Status = types.TaskStatusFailed
			} else {
				task.Status = types.TaskStatusCompleted
				task.Result = result
			}
		}()

		return map[string]interface{}{"taskId": taskID}, nil

	case "tools/get_result":
		s.tasksMu.RLock()
		defer s.tasksMu.RUnlock()
		var params struct {
			TaskID string `json:"taskId"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
			return nil, errors.New("param parse error")
		}
		task, ok := s.tasks[params.TaskID]
		if !ok {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Task not found", nil)
			return nil, errors.New("task not found")
		}
		return task, nil

	case "tools/call_stream":
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
		tool, ok := s.tools[params.Name]
		if !ok {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Tool not found", nil)
			return nil, errors.New("tool not found")
		}

		args, err := s.prepareFuncArgs(tool.ParamTypes, params.Arguments, tool.ParamNames)
		if err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params: "+err.Error(), nil)
			return nil, err
		}

		outVals := tool.Func.Call(args)
		return s.handleFunctionOutputs(outVals, respErrPtr)


	case "resources/list":
		s.rwMu.RLock()
		defer s.rwMu.RUnlock()
		resourcesList := []map[string]interface{}{}
		for _, res := range s.resources {
			resourcesList = append(resourcesList, map[string]interface{}{
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
		defer s.rwMu.RUnlock()
		var params struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params", nil)
			return nil, errors.New("param parse error")
		}
		uri := params.URI
		for _, res := range s.resources {
			vals, match := util.MatchURI(res.URITemplate, uri)
			if match {
				args := []reflect.Value{}
				for i, v := range vals {
					if res.Func.Type().In(i).Kind() == reflect.Int {
						var intVal int64
						fmt.Sscanf(v, "%d", &intVal)
						args = append(args, reflect.ValueOf(int(intVal)))
					} else if res.Func.Type().In(i).Kind() == reflect.Bool {
						var boolVal bool
						fmt.Sscanf(v, "%t", &boolVal)
						args = append(args, reflect.ValueOf(boolVal))
					} else {
						args = append(args, reflect.ValueOf(v))
					}
				}
				outVals := res.Func.Call(args)
				return s.handleFunctionOutputs(outVals, respErrPtr)
			}
		}
		*respErrPtr = s.newError(types.CodeInvalidParams, "Resource not found", nil)
		return nil, errors.New("resource not found")

	case "prompts/list":
		s.rwMu.RLock()
		defer s.rwMu.RUnlock()
		promptsList := []map[string]interface{}{}
		for _, prompt := range s.prompts {
			promptsList = append(promptsList, map[string]interface{}{
				"name":        prompt.Name,
				"description": prompt.Description,
			})
		}
		result := map[string]interface{}{
			"prompts": promptsList,
		}
		return result, nil

	case "prompts/get":
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
		if prompt.ParamStructType != nil {
			paramInstance := reflect.New(prompt.ParamStructType).Interface()
			jsonParams, _ := json.Marshal(params.Arguments)
			if err := json.Unmarshal(jsonParams, paramInstance); err != nil {
				*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params: "+err.Error(), nil)
				return nil, err
			}
			if err := s.validator.Struct(paramInstance); err != nil {
				*respErrPtr = s.newError(types.CodeInvalidParams, "Validation error: "+err.Error(), nil)
				return nil, err
			}
		}
		if !ok {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Prompt not found", nil)
			return nil, errors.New("prompt not found")
		}

		if prompt.ParamStructType != nil {
			paramInstance := reflect.New(prompt.ParamStructType).Interface()
			jsonParams, _ := json.Marshal(params.Arguments)
			if err := json.Unmarshal(jsonParams, paramInstance); err != nil {
				*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params: "+err.Error(), nil)
				return nil, err
			}
			if err := s.validator.Struct(paramInstance); err != nil {
				*respErrPtr = s.newError(types.CodeInvalidParams, "Validation error: "+err.Error(), nil)
				return nil, err
			}
		}
		args, err := s.prepareFuncArgs(prompt.ParamTypes, params.Arguments, prompt.ParamNames)
		if err != nil {
			*respErrPtr = s.newError(types.CodeInvalidParams, "Invalid params: "+err.Error(), nil)
			return nil, err
		}
		outVals := prompt.Func.Call(args)
		if len(outVals) == 0 {
			result := map[string]interface{}{
				"description": prompt.Description,
				"messages":    []types.Message{},
			}
			return result, nil
		}
		lastIdx := len(outVals) - 1
		var retErr error = nil
		var messages interface{}
		if prompt.Func.Type().NumOut() > 1 && outVals[lastIdx].Interface() != nil {
			retErr = outVals[lastIdx].Interface().(error)
		}
		mainVal := outVals[0]
		if retErr != nil {
			*respErrPtr = s.newError(types.CodeServerError, retErr.Error(), nil)
			return nil, retErr
		}
		switch mainVal.Interface().(type) {
		case string:
			text := mainVal.Interface().(string)
			msg := types.Message{
				Role:    "user",
				Content: types.Content{Type: "text", Text: text},
			}
			messages = []types.Message{msg}
		case []types.Message:
			messages = mainVal.Interface().([]types.Message)
		case []interface{}:
			arr := mainVal.Interface().([]interface{})
			var msgList []types.Message
			for _, m := range arr {
				if msg, ok := m.(types.Message); ok {
					msgList = append(msgList, msg)
				}
			}
			messages = msgList
		default:
			text := fmt.Sprintf("%v", mainVal.Interface())
			msg := types.Message{
				Role:    "user",
				Content: types.Content{Type: "text", Text: text},
			}
			messages = []types.Message{msg}
		}
		result := map[string]interface{}{
			"description": prompt.Description,
			"messages":    messages,
		}
		return result, nil

	default:
		if respErrPtr != nil {
			*respErrPtr = s.newError(types.CodeMethodNotFound, "Method not found", nil)
		}
		return nil, errors.New("method not found")
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
	args := []reflect.Value{}
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

func (s *Server) handleStreamRequest(req *types.Request, w http.ResponseWriter, flusher http.Flusher) {
	var respErr *types.ResponseError
	result, err := s.routeMethod(req, &respErr)

	if err != nil {
		resp := s.makeErrorResponse(req.ID, respErr.Code, respErr.Message, respErr.Data)
		data, _ := json.Marshal(resp)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		return
	}

	// Check if the result is a channel
	val := reflect.ValueOf(result)
	if val.Kind() != reflect.Chan {
		// Not a streaming response, just send the single result
		resp := types.Response{ID: req.ID, JSONRPC: "2.0", Result: result}
		data, _ := json.Marshal(resp)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		return
	}

	// It's a streaming response, listen on the channel
	for {
		item, ok := val.Recv()
		if !ok {
			// Channel closed, we are done.
			break
		}

		// Create a partial response
		partialResp := types.Response{
			ID:      req.ID,
			JSONRPC: "2.0",
			Result:  item.Interface(),
		}
		data, _ := json.Marshal(partialResp)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}
}
