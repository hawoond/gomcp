package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"sync"

	"github.com/hawoond/gomcp/internal/types"
	"github.com/hawoond/gomcp/internal/util"
)

type Resource struct {
	URITemplate string
	Description string
	Func        reflect.Value
	ParamCount  int
}

type Tool struct {
	Name        string
	Description string
	Func        reflect.Value
	ParamTypes  []reflect.Type
	ParamNames  []string
}

type Prompt struct {
	Name        string
	Description string
	Func        reflect.Value
	ParamTypes  []reflect.Type
	ParamNames  []string
}

type Server struct {
	Name         string
	Version      string
	resources    []Resource
	tools        map[string]Tool
	prompts      map[string]Prompt
	mu           sync.Mutex
	shuttingDown bool
}

func NewServer(name string, version string) *Server {
	return &Server{
		Name:      name,
		Version:   version,
		resources: []Resource{},
		tools:     make(map[string]Tool),
		prompts:   make(map[string]Prompt),
	}
}

func (s *Server) AddResource(uriTemplate string, description string, handler interface{}) error {
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
	log.Printf("Resource registered: %s", uriTemplate)
	return nil
}

func (s *Server) AddTool(name string, description string, handler interface{}) error {
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
	paramNames := []string{}
	for i := 0; i < paramCount; i++ {
		paramNames = append(paramNames, fmt.Sprintf("param%d", i+1))
	}
	s.tools[name] = Tool{
		Name:        name,
		Description: description,
		Func:        fnVal,
		ParamTypes:  util.FuncParamTypes(fnType),
		ParamNames:  paramNames,
	}
	log.Printf("Tool registered: %s", name)
	return nil
}

func (s *Server) AddPrompt(name string, description string, handler interface{}) error {
	fnVal := reflect.ValueOf(handler)
	fnType := fnVal.Type()
	if fnType.Kind() != reflect.Func {
		return fmt.Errorf("handler for prompt %s is not a function", name)
	}
	paramCount := fnType.NumIn()
	paramNames := []string{}
	for i := 0; i < paramCount; i++ {
		paramNames = append(paramNames, fmt.Sprintf("param%d", i+1))
	}
	s.prompts[name] = Prompt{
		Name:        name,
		Description: description,
		Func:        fnVal,
		ParamTypes:  util.FuncParamTypes(fnType),
		ParamNames:  paramNames,
	}
	log.Printf("Prompt registered: %s", name)
	return nil
}

func (s *Server) RunStdio() error {
	log.Printf("Starting MCP server via STDIO: %s (v%s)", s.Name, s.Version)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		log.Println("Shutdown signal received - shutting down server...")
		s.shuttingDown = true
		os.Exit(0)
	}()
	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if errors.Is(err, os.ErrClosed) || s.shuttingDown {
				return nil
			}
			if err.Error() == "EOF" {
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

func (s *Server) ListenAndServe(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
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
	})
	log.Printf("Starting MCP server with HTTP SSE (listening on %s)...", addr)
	return http.ListenAndServe(addr, mux)
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
			log.Printf("Received client initialization complete signal")
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
		log.Printf("Processing initialize request: client=%v, version=%s", params.ClientInfo, params.ProtocolVersion)
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
			*respErrPtr = s.newError(types.CodeServerError, errVal.Error(), nil)
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
