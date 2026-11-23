package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxChatBytes = 64 << 10
	// PCB's plan tool carries its selector catalog in its description (2.5 KiB
	// in 2026-11); the 64 KiB assignment stays the real bound. Equal to the
	// backend's chatJobRequestSchema limit.
	maxChatToolDescription = 8 << 10
	chatTimeout            = 180 * time.Second
)

type chatToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type chatMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	ToolCalls  []chatToolCall  `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
}

type chatTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		Strict      bool            `json:"strict"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type chatPayload struct {
	Model     string        `json:"model"`
	Messages  []chatMessage `json:"messages"`
	Tools     []chatTool    `json:"tools"`
	MaxTokens int           `json:"maxTokens"`
}

type chatAssignment struct {
	Type      string      `json:"type"`
	JobType   string      `json:"jobType"`
	JobID     string      `json:"jobId"`
	ExpiresAt time.Time   `json:"expiresAt"`
	Payload   chatPayload `json:"payload"`
}

type chatCompletion struct {
	Model   string `json:"model"`
	Choices []struct {
		Index        int         `json:"index"`
		FinishReason string      `json:"finish_reason"`
		Message      chatMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		Prompt     int `json:"prompt_tokens"`
		Completion int `json:"completion_tokens"`
		Total      int `json:"total_tokens"`
	} `json:"usage"`
}

// Chat never follows a local server redirect or an environment-configured proxy.
var localChatHTTP = func() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxResponseHeaderBytes = 64 << 10
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("CHAT_BACKEND_UNAVAILABLE")
		}
		if host == "localhost" {
			host = "127.0.0.1"
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("CHAT_BACKEND_UNAVAILABLE: loopback required")
		}
		dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		return dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
	}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}()

func localChatSettings(s LLMSettings) bool {
	u, err := url.Parse(s.BackendURL)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "http" && u.Scheme != "https") || strings.TrimRight(u.Path, "/") != "/v1" {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	return (host == "localhost" || (ip != nil && ip.IsLoopback())) &&
		validChatName(s.ChatModel, 200) && s.ChatContextTokens > 0 && s.ChatContextTokens <= 1<<20
}

func validChatName(s string, limit int) bool {
	return s != "" && len(s) <= limit && !strings.ContainsAny(s, "\r\n\x00")
}

func readChatBytes(r io.Reader, limit int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(limit+1)))
	if err != nil || len(b) > limit {
		return nil, errors.New("CHAT_RESPONSE_LIMIT: local response exceeded its limit or could not be read")
	}
	return b, nil
}

func decodeChatAssignment(data []byte, s LLMSettings, bytesPerToken float64) (chatAssignment, error) {
	var job chatAssignment
	if len(data) > maxChatBytes || decodeChatJSON(data, &job) != nil || job.Type != "job.assign" ||
		job.JobType != "LLM_CHAT_TOOLS" || !validChatName(job.JobID, 128) {
		return job, errors.New("CHAT_INVALID_REQUEST: use job.assign with jobType LLM_CHAT_TOOLS and a bounded payload")
	}
	if !localChatSettings(s) || job.Payload.Model != s.ChatModel {
		return job, errors.New("CHAT_MODEL_UNAVAILABLE: explicitly select an installed model and positive context cap in llm.txt")
	}
	if time.Until(job.ExpiresAt) <= 0 || time.Until(job.ExpiresAt) > 5*time.Minute {
		return job, errors.New("CHAT_EXPIRED: expiresAt must be in the next five minutes")
	}
	if err := validateChatPayload(job.Payload, s.ChatContextTokens, bytesPerToken); err != nil {
		return job, err
	}
	return job, nil
}

func decodeChatJSON(data []byte, v any) error {
	if err := checkChatJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

// encoding/json otherwise accepts duplicate members and replaces invalid text.
func checkChatJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON depth limit")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate JSON member")
				}
				seen[name] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("invalid object")
			}
		case json.Delim('['):
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("invalid array")
			}
		case json.Delim('}'), json.Delim(']'):
			return errors.New("invalid JSON delimiter")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

// requestTokens estimates a request's tokens from its serialized bytes at the
// model's measured ratio; below one byte a token it counts bytes.
func requestTokens(bytes int, bytesPerToken float64) int {
	return int(math.Ceil(float64(bytes) / max(bytesPerToken, 1)))
}

func validateChatPayload(p chatPayload, contextTokens int, bytesPerToken float64) error {
	bad := errors.New("CHAT_INVALID_REQUEST: use bounded text messages, strict function tools and a positive maxTokens")
	if len(p.Messages) == 0 || len(p.Messages) > 64 || len(p.Tools) > 20 || p.MaxTokens < 1 || p.MaxTokens > 8192 {
		return bad
	}
	data, err := json.Marshal(p)
	if err != nil || len(data) > maxChatBytes || requestTokens(len(data), bytesPerToken)+p.MaxTokens+1024 > contextTokens {
		return errors.New("CHAT_CONTEXT_LIMIT: narrow messages/tools or increase the explicit context cap")
	}
	names := map[string]bool{}
	for _, tool := range p.Tools {
		if tool.Type != "function" || !tool.Function.Strict || !validToolName(tool.Function.Name) || names[tool.Function.Name] || len(tool.Function.Description) > maxChatToolDescription {
			return bad
		}
		// Parameters pass through untouched; the browser runtime owns argument
		// validation and returns a recoverable refusal to the model.
		var params map[string]json.RawMessage
		if json.Unmarshal(tool.Function.Parameters, &params) != nil || params == nil {
			return bad
		}
		names[tool.Function.Name] = true
	}
	pending, seenCalls := map[string]bool{}, map[string]bool{}
	for _, m := range p.Messages {
		if !slices.Contains([]string{"system", "user", "assistant", "tool"}, m.Role) || len(m.Content) > 16<<10 || len(m.ToolCalls) > 8 {
			return bad
		}
		var text string
		if string(m.Content) != "null" && json.Unmarshal(m.Content, &text) != nil {
			return bad
		}
		if string(m.Content) == "null" && (m.Role != "assistant" || len(m.ToolCalls) == 0) {
			return bad
		}
		if m.Role == "tool" {
			if !pending[m.ToolCallID] || len(m.ToolCalls) != 0 {
				return bad
			}
			delete(pending, m.ToolCallID)
			continue
		}
		if len(pending) != 0 || m.ToolCallID != "" || (m.Role != "assistant" && len(m.ToolCalls) != 0) {
			return bad
		}
		for _, call := range m.ToolCalls {
			if seenCalls[call.ID] || !validChatCall(call, p.Tools) {
				return bad
			}
			seenCalls[call.ID], pending[call.ID] = true, true
		}
	}
	if len(pending) != 0 {
		return bad
	}
	return nil
}

func callLocalChat(ctx context.Context, s LLMSettings, p chatPayload) (chatCompletion, error) {
	var result chatCompletion
	var body []byte
	var err error
	if root, ok := ollamaRoot(ctx, s); ok {
		body, err = ollamaChat(ctx, root, s.ChatContextTokens, p)
	} else {
		body, err = postLocalChat(ctx, strings.TrimRight(s.BackendURL, "/")+"/chat/completions",
			map[string]any{"model": p.Model, "messages": p.Messages, "tools": p.Tools, "stream": false, "max_tokens": p.MaxTokens})
	}
	if err != nil {
		return result, err
	}
	if checkChatJSON(body) != nil || json.Unmarshal(body, &result) != nil || result.Model != p.Model || len(result.Choices) != 1 || result.Choices[0].Index != 0 {
		return result, errors.New("CHAT_INVALID_RESPONSE: expected one completion from the selected model")
	}
	choice := result.Choices[0]
	if choice.FinishReason == "length" {
		return result, errors.New("CHAT_TRUNCATED: the local model hit maxTokens before finishing")
	}
	if choice.Message.Role != "assistant" || !slices.Contains([]string{"stop", "tool_calls"}, choice.FinishReason) || len(choice.Message.ToolCalls) > 8 || len(choice.Message.Content) > 16<<10 {
		return result, errors.New("CHAT_INVALID_RESPONSE")
	}
	var text string
	if choice.Message.ToolCallID != "" || (string(choice.Message.Content) != "null" && json.Unmarshal(choice.Message.Content, &text) != nil) ||
		(len(choice.Message.ToolCalls) == 0 && string(choice.Message.Content) == "null") ||
		((choice.FinishReason == "tool_calls") != (len(choice.Message.ToolCalls) > 0)) || result.Usage.Prompt < 0 || result.Usage.Completion < 0 || result.Usage.Completion > p.MaxTokens || result.Usage.Total != result.Usage.Prompt+result.Usage.Completion {
		return result, errors.New("CHAT_INVALID_RESPONSE: invalid assistant completion or usage")
	}
	return result, nil
}

// postLocalChat sends one request to the local server and reads its reply.
func postLocalChat(ctx context.Context, endpoint string, request any) ([]byte, error) {
	data, err := json.Marshal(request)
	if err != nil || len(data) > maxChatBytes {
		return nil, errors.New("CHAT_INVALID_REQUEST")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("CHAT_BACKEND_UNAVAILABLE")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := localChatHTTP.Do(req)
	if err != nil {
		return nil, errors.New("CHAT_BACKEND_UNAVAILABLE: check the local server or cancellation/expiry")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CHAT_BACKEND_STATUS: local server returned %d", resp.StatusCode)
	}
	return readChatBytes(resp.Body, maxChatBytes)
}

// ollamaRoot reports whether the /v1 server is Ollama, and its root URL. Its
// /v1 endpoint takes no context size, so a declared context only applies
// through the native chat endpoint (docs.ollama.com/api/openai-compatibility).
// ponytail: one loopback GET per chat request; cache it if that ever shows.
func ollamaRoot(ctx context.Context, s LLMSettings) (string, bool) {
	root := strings.TrimSuffix(strings.TrimRight(s.BackendURL, "/"), "/v1")
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, root+"/api/version", nil)
	if err != nil {
		return "", false
	}
	resp, err := localChatHTTP.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	var answer struct {
		Version *string `json:"version"`
	}
	body, err := readChatBytes(resp.Body, 4<<10)
	return root, err == nil && resp.StatusCode == http.StatusOK && json.Unmarshal(body, &answer) == nil && answer.Version != nil
}

type ollamaToolCall struct {
	ID       string `json:"id,omitempty"`
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

type ollamaMessage struct {
	Role      string           `json:"role"`
	Content   string           `json:"content"`
	ToolCalls []ollamaToolCall `json:"tool_calls,omitempty"`
	ToolName  string           `json:"tool_name,omitempty"`
}

// ollamaChat runs one completion on Ollama's native chat endpoint with the
// declared context and returns it in the OpenAI completion shape the rest of
// the companion checks: calls get ids and string arguments, private reasoning
// is dropped, usage comes from the native counts.
func ollamaChat(ctx context.Context, root string, contextTokens int, p chatPayload) ([]byte, error) {
	messages := make([]ollamaMessage, len(p.Messages))
	toolOf := map[string]string{}
	for i, m := range p.Messages {
		var text string
		_ = json.Unmarshal(m.Content, &text) // null stays ""
		messages[i] = ollamaMessage{Role: m.Role, Content: text, ToolName: toolOf[m.ToolCallID]}
		for _, call := range m.ToolCalls {
			native := ollamaToolCall{ID: call.ID}
			native.Function.Name = call.Function.Name
			native.Function.Arguments = json.RawMessage(call.Function.Arguments)
			messages[i].ToolCalls = append(messages[i].ToolCalls, native)
			toolOf[call.ID] = call.Function.Name
		}
	}
	body, err := postLocalChat(ctx, root+"/api/chat", map[string]any{
		"model": p.Model, "messages": messages, "tools": p.Tools, "stream": false,
		"options": map[string]any{"num_ctx": contextTokens, "num_predict": p.MaxTokens},
	})
	if err != nil {
		return nil, err
	}
	var reply struct {
		Model   string `json:"model"`
		Message struct {
			Role      string           `json:"role"`
			Content   string           `json:"content"`
			ToolCalls []ollamaToolCall `json:"tool_calls"`
		} `json:"message"`
		DoneReason string `json:"done_reason"`
		Prompt     int    `json:"prompt_eval_count"`
		Completion int    `json:"eval_count"`
	}
	if checkChatJSON(body) != nil || json.Unmarshal(body, &reply) != nil {
		return nil, errors.New("CHAT_INVALID_RESPONSE: expected one completion from the selected model")
	}
	message := map[string]any{"role": reply.Message.Role, "content": reply.Message.Content}
	finish := "stop"
	switch {
	case reply.DoneReason == "length":
		finish = "length"
	case len(reply.Message.ToolCalls) > 0:
		finish = "tool_calls"
		calls := make([]chatToolCall, len(reply.Message.ToolCalls))
		for i, native := range reply.Message.ToolCalls {
			calls[i] = chatToolCall{ID: native.ID, Type: "function"}
			if !validChatName(native.ID, 128) {
				id := make([]byte, 8)
				_, _ = rand.Read(id)
				calls[i].ID = "call_" + hex.EncodeToString(id)
			}
			calls[i].Function.Name = native.Function.Name
			calls[i].Function.Arguments = string(native.Function.Arguments)
		}
		message["tool_calls"] = calls
		if reply.Message.Content == "" {
			message["content"] = nil
		}
	}
	return json.Marshal(map[string]any{
		"model":   reply.Model,
		"choices": []any{map[string]any{"index": 0, "finish_reason": finish, "message": message}},
		"usage":   map[string]int{"prompt_tokens": reply.Prompt, "completion_tokens": reply.Completion, "total_tokens": reply.Prompt + reply.Completion},
	})
}

// invalidRoundRetries bounds how often a round with no valid call is answered
// with its tool errors and asked again inside one job.
const invalidRoundRetries = 2

// runLocalChat answers one chat job. A call the local model gets wrong never
// fails the job on its own: the model sees why as that call's tool error. A
// round with valid calls returns them, and its refused calls rejoin the round
// when a later job of the turn replays it; a round with none is answered at
// once and asked again.
func runLocalChat(ctx context.Context, s LLMSettings, p chatPayload) (json.RawMessage, error) {
	p.Messages = withRefusedCalls(p.Messages)
	for retry := 0; ; retry++ {
		result, err := callLocalChat(ctx, s, p)
		if err != nil {
			return nil, err
		}
		message := &result.Choices[0].Message
		var valid, refused []chatToolCall
		var refusals []chatMessage
		seen := map[string]bool{}
		for _, call := range message.ToolCalls {
			reason := callRefusal(call, p.Tools)
			if reason == "" && seen[call.ID] {
				reason = "its id repeats another call of the same round"
			}
			if reason == "" {
				seen[call.ID] = true
				valid = append(valid, call)
				continue
			}
			stand := refusedStandIn(call)
			refused = append(refused, stand)
			refusals = append(refusals, toolText(stand.ID, "Not run: "+reason+". Call again with an offered tool and a JSON object of arguments."))
		}
		switch {
		case len(refused) == 0:
		case len(valid) > 0:
			message.ToolCalls = valid
			keepRefusedCalls(valid, refused, refusals)
		case retry < invalidRoundRetries:
			p.Messages = append(slices.Clip(p.Messages), chatMessage{Role: "assistant", Content: message.Content, ToolCalls: refused})
			p.Messages = append(p.Messages, refusals...)
			continue
		default:
			return nil, fmt.Errorf("CHAT_INVALID_TOOL_CALL: the local model's calls were refused %d times in a row", retry+1)
		}
		normalized, err := json.Marshal(result)
		if err != nil || len(normalized) > 60<<10 {
			return nil, errors.New("CHAT_RESPONSE_LIMIT: normalized completion exceeded 60 KiB")
		}
		return normalized, nil
	}
}

func toolText(callID, text string) chatMessage {
	content, _ := json.Marshal(text)
	return chatMessage{Role: "tool", Content: content, ToolCallID: callID}
}

// refusedStandIn is a refused call as the model is shown it again: a fresh id
// and empty arguments, so the replayed round is valid for the local server.
func refusedStandIn(call chatToolCall) chatToolCall {
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	stand := chatToolCall{ID: "refused-" + hex.EncodeToString(id), Type: "function"}
	stand.Function.Name = "invalid_tool_name"
	if validToolName(call.Function.Name) {
		stand.Function.Name = call.Function.Name
	}
	stand.Function.Arguments = "{}"
	return stand
}

// refusedRounds keeps a mixed round's refused calls, under each of its valid
// call ids, because the browser runs and replays only the valid calls. Chat
// jobs of one turn never move device, so the next job of the turn lands here.
// ponytail: in-memory and capped; a restart drops the notes, and the model
// then simply does not see the old refusal again.
var refusedRounds = struct {
	sync.Mutex
	byCall map[string]refusedRound
}{byCall: map[string]refusedRound{}}

type refusedRound struct {
	calls     []chatToolCall
	refusals  []chatMessage
	expiresAt time.Time
}

const refusedRoundsCap = 1024

func keepRefusedCalls(valid, refused []chatToolCall, refusals []chatMessage) {
	refusedRounds.Lock()
	defer refusedRounds.Unlock()
	now := time.Now()
	for id, round := range refusedRounds.byCall {
		if now.After(round.expiresAt) {
			delete(refusedRounds.byCall, id)
		}
	}
	round := refusedRound{calls: refused, refusals: refusals, expiresAt: now.Add(time.Hour)}
	for _, call := range valid {
		if len(refusedRounds.byCall) < refusedRoundsCap {
			refusedRounds.byCall[call.ID] = round
		}
	}
}

// withRefusedCalls puts each kept refusal back into the round it came from,
// with its tool error right after the round.
func withRefusedCalls(messages []chatMessage) []chatMessage {
	refusedRounds.Lock()
	defer refusedRounds.Unlock()
	out := make([]chatMessage, 0, len(messages))
	for _, m := range messages {
		out = append(out, m)
		if m.Role != "assistant" {
			continue
		}
		for _, call := range m.ToolCalls {
			if round, ok := refusedRounds.byCall[call.ID]; ok {
				out[len(out)-1].ToolCalls = append(slices.Clip(m.ToolCalls), round.calls...)
				out = append(out, round.refusals...)
				break
			}
		}
	}
	return out
}

// chatProbeMaxTokens leaves room for a thinking model (qwen3) to reason
// before its tool call; at 128 qwen3:8b spent the whole budget reasoning.
const chatProbeMaxTokens = 1024

// maxBytesPerToken caps the measured ratio: a cached probe prompt reports few
// tokens, and a ratio too high would let a request past the context.
const maxBytesPerToken = 3.0

// probeLocalChat runs one scripted tool round on the selected model and
// returns the request bytes its tokenizer packs into a token (1 when the
// server reports no usage); the error says why chat stays unavailable.
func probeLocalChat(ctx context.Context, s LLMSettings, installed []string) (float64, error) {
	if !localChatSettings(s) || !slices.Contains(installed, s.ChatModel) {
		return 0, errors.New("chat_model is not installed")
	}
	probeCtx, cancel := context.WithTimeout(ctx, chatTimeout)
	defer cancel()
	var p chatPayload
	_ = json.Unmarshal([]byte(`{"messages":[{"role":"user","content":"Call dtx_probe once with ok true. Do not answer with text."}],"tools":[{"type":"function","function":{"name":"dtx_probe","description":"Confirm tool support.","strict":true,"parameters":{"type":"object","properties":{"ok":{"type":"boolean","const":true}},"required":["ok"],"additionalProperties":false}}}]}`), &p)
	p.Model = s.ChatModel
	p.MaxTokens = chatProbeMaxTokens
	if err := validateChatPayload(p, s.ChatContextTokens, 1); err != nil {
		return 0, err
	}
	result, err := callLocalChat(probeCtx, s, p)
	if err != nil {
		return 0, err
	}
	if len(result.Choices[0].Message.ToolCalls) != 1 {
		return 0, errors.New("the model answered without exactly one tool call")
	}
	call := result.Choices[0].Message.ToolCalls[0]
	var args struct {
		OK bool `json:"ok"`
	}
	if call.Function.Name != "dtx_probe" || decodeChatJSON([]byte(call.Function.Arguments), &args) != nil || !args.OK {
		return 0, errors.New("the model's tool call did not match the probe")
	}
	if result.Usage.Prompt <= 0 {
		return 1, nil
	}
	sent, _ := json.Marshal(p)
	ratio := math.Floor(float64(len(sent))/float64(result.Usage.Prompt)*10) / 10
	return min(max(ratio, 1), maxBytesPerToken), nil
}

func validToolName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// A call must name an advertised tool and carry a JSON object of at most 8 KiB.
// Argument types are the browser runtime's to check.
func validChatCall(call chatToolCall, tools []chatTool) bool {
	return callRefusal(call, tools) == ""
}

// callRefusal says why a call cannot run, in words the model can act on; empty
// when it can.
func callRefusal(call chatToolCall, tools []chatTool) string {
	if call.Type != "function" || !validChatName(call.ID, 128) {
		return "the call has no function type or no usable id"
	}
	if len(call.Function.Arguments) > 8192 {
		return "its arguments are larger than 8 KiB"
	}
	var args map[string]json.RawMessage
	if decodeChatJSON([]byte(call.Function.Arguments), &args) != nil || args == nil {
		return "its arguments are not a JSON object"
	}
	if !slices.ContainsFunc(tools, func(tool chatTool) bool { return tool.Function.Name == call.Function.Name }) {
		names := make([]string, len(tools))
		for i, tool := range tools {
			names[i] = tool.Function.Name
		}
		name := call.Function.Name
		if len(name) > 64 {
			name = name[:64]
		}
		return fmt.Sprintf("%q is not an offered tool (offered: %s)", name, strings.Join(names, ", "))
	}
	return ""
}
