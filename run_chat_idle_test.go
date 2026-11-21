package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// #4191 L3-08: an idle companion lists models on every tick but runs the tool
// probe (real inference) once per connection, and nothing else.
func TestPairedChatIdleMakesNoInferenceCall(t *testing.T) {
	previous := reprobeEvery
	reprobeEvery = 20 * time.Millisecond
	t.Cleanup(func() { reprobeEvery = previous })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	var lists, inferences atomic.Int32
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
			lists.Add(1)
			io.WriteString(w, `{"data":[{"id":"fixture-vision:4b"},{"id":"fixture-chat:7b"}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
			inferences.Add(1)
			io.WriteString(w, `{"model":"fixture-chat:7b","choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"id":"probe-ok","type":"function","function":{"name":"dtx_probe","arguments":"{\"ok\":true}"}}]}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(model.Close)
	conn := connectPairedChat(t, ctx, model.URL+"/v1", "fixture-chat:7b", 8192).Conn
	if reply := readComputeReply(t, ctx, conn); !strings.Contains(strings.Join(reply.Capabilities, " "), "llm.chat") {
		t.Fatalf("chat was not advertised: %v", reply.Capabilities)
	}
	listed := lists.Load()
	for lists.Load() < listed+5 {
		select {
		case <-ctx.Done():
			t.Fatalf("idle loop did not keep listing models: %d lists", lists.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if n := inferences.Load(); n != 1 {
		t.Fatalf("idle companion ran %d inference calls; want only the one tool probe", n)
	}
}

// #4191 L3-12: a text answer cut off by the output limit is not a result.
func TestPairedChatRefusesLengthTruncatedAnswer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	model := chatModelServer(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"model":"fixture-chat:7b","choices":[{"index":0,"finish_reason":"length","message":{"role":"assistant","content":"R1 pins 1 and"}}],"usage":{"prompt_tokens":32,"completion_tokens":128,"total_tokens":160}}`)
	})
	conn := connectPairedChat(t, ctx, model.URL+"/v1", "fixture-chat:7b", 8192).Conn
	readComputeReply(t, ctx, conn)
	writeChatFixtureJob(t, ctx, conn, "cut-off")
	reply := readChatResult(t, ctx, conn, "cut-off")
	if reply.OK || !strings.HasPrefix(reply.Error, "CHAT_TRUNCATED") || len(reply.Result) != 0 {
		t.Fatalf("truncated answer was accepted: ok=%v error=%q", reply.OK, reply.Error)
	}
}
