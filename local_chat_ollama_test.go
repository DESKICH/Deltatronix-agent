package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Ollama's /v1 endpoint takes no context size, so a declared 40960 ran at the
// server default and silently cut the prompt (C1). On Ollama the companion
// uses the native chat endpoint and passes the declared context there.
func TestOllamaChatRunsWithTheDeclaredContext(t *testing.T) {
	var sent struct {
		Model    string `json:"model"`
		Stream   *bool  `json:"stream"`
		Messages []struct {
			Role      string `json:"role"`
			Content   string `json:"content"`
			ToolName  string `json:"tool_name"`
			ToolCalls []struct {
				Function struct {
					Name      string          `json:"name"`
					Arguments json.RawMessage `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
		Tools   []chatTool `json:"tools"`
		Options struct {
			NumCtx     int `json:"num_ctx"`
			NumPredict int `json:"num_predict"`
		} `json:"options"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/version":
			io.WriteString(w, `{"version":"0.12.6"}`)
		case "/api/chat":
			if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
				t.Error(err)
			}
			io.WriteString(w, `{"model":"qwen3:8b","message":{"role":"assistant","content":"","thinking":"U7 next.","tool_calls":[{"function":{"name":"inspect_component","arguments":{"reference":"U7"}}}]},"done":true,"done_reason":"stop","prompt_eval_count":812,"eval_count":40}`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var p chatPayload
	if err := json.Unmarshal([]byte(`{"model":"qwen3:8b","maxTokens":2048,
		"messages":[{"role":"user","content":"Inspect U3 then U7."},
			{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"inspect_component","arguments":"{\"reference\":\"U3\"}"}}]},
			{"role":"tool","content":"U3 is a regulator.","tool_call_id":"c1"}],
		"tools":[{"type":"function","function":{"name":"inspect_component","strict":true,"parameters":{"type":"object","properties":{"reference":{"type":"string"}}}}}]}`), &p); err != nil {
		t.Fatal(err)
	}
	settings := LLMSettings{BackendURL: server.URL + "/v1", ChatModel: "qwen3:8b", ChatContextTokens: 40960}
	result, err := callLocalChat(context.Background(), settings, p)
	if err != nil {
		t.Fatalf("native chat failed: %v", err)
	}

	if sent.Options.NumCtx != 40960 || sent.Options.NumPredict != 2048 || sent.Stream == nil || *sent.Stream || sent.Model != "qwen3:8b" {
		t.Errorf("request must carry the declared context and output cap, unstreamed: %+v", sent.Options)
	}
	if len(sent.Messages) != 3 || len(sent.Tools) != 1 {
		t.Fatalf("messages or tools lost: %+v", sent)
	}
	call := sent.Messages[1].ToolCalls
	if len(call) != 1 || call[0].Function.Name != "inspect_component" || string(call[0].Function.Arguments) != `{"reference":"U3"}` {
		t.Errorf("a past call must carry its arguments as an object: %+v", call)
	}
	if sent.Messages[2].Role != "tool" || sent.Messages[2].ToolName != "inspect_component" || sent.Messages[2].Content != "U3 is a regulator." {
		t.Errorf("a tool result must name its tool: %+v", sent.Messages[2])
	}

	choice := result.Choices[0]
	if result.Model != "qwen3:8b" || choice.FinishReason != "tool_calls" || len(choice.Message.ToolCalls) != 1 {
		t.Fatalf("the reply must come back in the completion shape: %+v", result)
	}
	got := choice.Message.ToolCalls[0]
	if got.ID == "" || got.Type != "function" || got.Function.Name != "inspect_component" || got.Function.Arguments != `{"reference":"U7"}` {
		t.Errorf("a new call needs an id and string arguments: %+v", got)
	}
	if string(choice.Message.Content) != "null" || strings.Contains(string(choice.Message.Content), "U7 next") {
		t.Errorf("an empty answer beside calls is null, and private reasoning is dropped: %s", choice.Message.Content)
	}
	if result.Usage.Prompt != 812 || result.Usage.Completion != 40 || result.Usage.Total != 852 {
		t.Errorf("usage must come from the native counts: %+v", result.Usage)
	}
}

// A native reply that stops at its output cap is a truncated answer.
func TestOllamaChatLengthStopIsTruncated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/version" {
			io.WriteString(w, `{"version":"0.12.6"}`)
			return
		}
		io.WriteString(w, `{"model":"qwen3:8b","message":{"role":"assistant","content":"Half an ans"},"done":true,"done_reason":"length","prompt_eval_count":10,"eval_count":16}`)
	}))
	defer server.Close()
	p := chatPayload{Model: "qwen3:8b", MaxTokens: 16, Messages: []chatMessage{{Role: "user", Content: json.RawMessage(`"hi"`)}}}
	settings := LLMSettings{BackendURL: server.URL + "/v1", ChatModel: "qwen3:8b", ChatContextTokens: 4096}
	if _, err := callLocalChat(context.Background(), settings, p); err == nil || !strings.HasPrefix(err.Error(), "CHAT_TRUNCATED") {
		t.Fatalf("want CHAT_TRUNCATED, got %v", err)
	}
}

// The probe measures how many request bytes the model's tokenizer packs into a
// token, so admission counts tokens, not bytes (C9). The ratio is clamped: a
// cached prompt reports few tokens and must not inflate it.
func TestChatProbeMeasuresBytesPerToken(t *testing.T) {
	for _, tc := range []struct {
		promptTokens int
		want         func(float64) bool
	}{
		{promptTokens: 0, want: func(r float64) bool { return r == 1 }},
		{promptTokens: 1, want: func(r float64) bool { return r == maxBytesPerToken }},
		{promptTokens: 200, want: func(r float64) bool { return r > 1 && r < maxBytesPerToken }},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"model": "qwen3:8b",
				"choices": []any{map[string]any{"index": 0, "finish_reason": "tool_calls", "message": map[string]any{
					"role": "assistant", "content": nil,
					"tool_calls": []any{map[string]any{"id": "p", "type": "function", "function": map[string]any{"name": "dtx_probe", "arguments": `{"ok":true}`}}},
				}}},
				"usage": map[string]any{"prompt_tokens": tc.promptTokens, "completion_tokens": 5, "total_tokens": tc.promptTokens + 5},
			})
		}))
		settings := LLMSettings{BackendURL: server.URL + "/v1", ChatModel: "qwen3:8b", ChatContextTokens: 40960}
		ratio, err := probeLocalChat(context.Background(), settings, []string{"qwen3:8b"})
		server.Close()
		if err != nil || !tc.want(ratio) {
			t.Errorf("prompt_tokens %d: ratio %v, err %v", tc.promptTokens, ratio, err)
		}
	}
}

// Admission counts tokens at the measured ratio: a request of more bytes than
// the context holds fits when its tokens do.
func TestChatAdmissionCountsTokensAtTheMeasuredRatio(t *testing.T) {
	p := chatPayload{Model: "m", MaxTokens: 1024, Messages: []chatMessage{{Role: "user", Content: json.RawMessage(`"` + strings.Repeat("word ", 1200) + `"`)}}}
	if err := validateChatPayload(p, 6000, 1); err == nil || !strings.HasPrefix(err.Error(), "CHAT_CONTEXT_LIMIT") {
		t.Fatalf("6 KB at one byte a token must not fit 6000 tokens: %v", err)
	}
	if err := validateChatPayload(p, 6000, 3); err != nil {
		t.Fatalf("6 KB at three bytes a token fits 6000 tokens: %v", err)
	}
}
