package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A thinking model (qwen3) spends its first few hundred tokens reasoning; with
// too small a budget the probe sees finish_reason "length" and no tool call.
func TestChatProbeLeavesRoomForThinkingModels(t *testing.T) {
	const reasoningTokens = 300
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			MaxTokens int `json:"max_tokens"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if req.MaxTokens < reasoningTokens+20 {
			fmt.Fprintf(w, `{"model":"qwen3:8b","choices":[{"index":0,"finish_reason":"length","message":{"role":"assistant","content":""}}],"usage":{"prompt_tokens":144,"completion_tokens":%d,"total_tokens":%d}}`, req.MaxTokens, 144+req.MaxTokens)
			return
		}
		fmt.Fprintf(w, `{"model":"qwen3:8b","choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"dtx_probe","arguments":"{\"ok\":true}"}}]}}],"usage":{"prompt_tokens":144,"completion_tokens":%d,"total_tokens":%d}}`, reasoningTokens+10, 144+reasoningTokens+10)
	}))
	defer server.Close()
	settings := LLMSettings{BackendURL: server.URL + "/v1", ChatModel: "qwen3:8b", ChatContextTokens: 40960}
	if _, err := probeLocalChat(context.Background(), settings, []string{"qwen3:8b"}); err != nil {
		t.Fatalf("probe refused a thinking model: %v", err)
	}
}
