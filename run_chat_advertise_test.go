package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket/wsjson"
)

// The capabilities frame names the companion's version, so the editor can say
// "update the agent" instead of showing a code an old companion sends (C3),
// and the chat model's measured bytes per token (C9).
func TestCapabilitiesNameVersionAndBytesPerToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/models" {
			io.WriteString(w, `{"data":[{"id":"fixture-chat:7b"}]}`)
			return
		}
		io.WriteString(w, `{"model":"fixture-chat:7b","choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"id":"p","type":"function","function":{"name":"dtx_probe","arguments":"{\"ok\":true}"}}]}}],"usage":{"prompt_tokens":150,"completion_tokens":5,"total_tokens":155}}`)
	}))
	t.Cleanup(model.Close)
	conn := connectPairedChat(t, ctx, model.URL+"/v1", "fixture-chat:7b", 8192).Conn
	var frame struct {
		Type    string `json:"type"`
		Version string `json:"version"`
		Chat    struct {
			Model         string  `json:"model"`
			ContextTokens int     `json:"contextTokens"`
			BytesPerToken float64 `json:"bytesPerToken"`
		} `json:"chat"`
	}
	if err := wsjson.Read(ctx, conn, &frame); err != nil {
		t.Fatal(err)
	}
	if frame.Type != "capabilities" || frame.Version != version || frame.Chat.Model != "fixture-chat:7b" ||
		frame.Chat.BytesPerToken <= 1 || frame.Chat.BytesPerToken > maxBytesPerToken {
		t.Fatalf("capabilities frame: %+v", frame)
	}
}

// After a reconnect the backend restores llm.chat before the companion's tool
// probe ends; a job in that window is told to wait, not that the model lost
// tool support (C5).
func TestChatJobDuringTheProbeSaysProbePending(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/models" {
			io.WriteString(w, `{"data":[{"id":"fixture-chat:7b"}]}`)
			return
		}
		select { // the probe is still thinking
		case <-release:
		case <-r.Context().Done():
		}
		http.Error(w, "gone", http.StatusServiceUnavailable)
	}))
	t.Cleanup(model.Close)
	conn := connectPairedChat(t, ctx, model.URL+"/v1", "fixture-chat:7b", 8192).Conn
	writeChatFixtureJob(t, ctx, conn, "during-probe")
	reply := readComputeReply(t, ctx, conn)
	if reply.Type != "job.result" || reply.JobID != "during-probe" || reply.OK || !strings.HasPrefix(reply.Error, "CHAT_PROBE_PENDING") {
		raw, _ := json.Marshal(reply)
		t.Fatalf("want CHAT_PROBE_PENDING, got %s", raw)
	}
}
