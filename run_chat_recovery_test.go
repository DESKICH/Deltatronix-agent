package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket/wsjson"
)

// W2 (#3395): a call the local model gets wrong is the model's to fix, not the
// job's failure. These scenarios drive the companion over its paired socket.

type modelCall struct {
	Messages []chatMessage `json:"messages"`
}

// scriptedChatModel answers each job request with the next reply and records
// what the model was shown.
func scriptedChatModel(t *testing.T, replies ...string) (url string, seen func() []modelCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []modelCall
	srv := chatModelServer(t, func(w http.ResponseWriter, r *http.Request) {
		var call modelCall
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &call); err != nil {
			t.Error(err)
		}
		mu.Lock()
		n := len(calls)
		calls = append(calls, call)
		mu.Unlock()
		if n >= len(replies) {
			t.Errorf("unexpected model request %d", n+1)
			http.Error(w, "no more replies", 500)
			return
		}
		io.WriteString(w, replies[n])
	})
	return srv.URL + "/v1", func() []modelCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]modelCall(nil), calls...)
	}
}

func toolReply(calls ...[3]string) string {
	list := make([]any, len(calls))
	for i, c := range calls {
		list[i] = map[string]any{"id": c[0], "type": "function", "function": map[string]any{"name": c[1], "arguments": c[2]}}
	}
	data, _ := json.Marshal(map[string]any{
		"model": "fixture-chat:7b",
		"choices": []any{map[string]any{"index": 0, "finish_reason": "tool_calls",
			"message": map[string]any{"role": "assistant", "content": nil, "tool_calls": list}}},
		"usage": map[string]any{"prompt_tokens": 32, "completion_tokens": 12, "total_tokens": 44},
	})
	return string(data)
}

func resultCalls(t *testing.T, reply computeReply) []chatToolCall {
	t.Helper()
	if !reply.OK {
		t.Fatalf("job failed: %s", reply.Error)
	}
	var result chatCompletion
	if err := json.Unmarshal(reply.Result, &result); err != nil {
		t.Fatal(err)
	}
	return result.Choices[0].Message.ToolCalls
}

func toolErrorsIn(messages []chatMessage) []string {
	var out []string
	for _, m := range messages {
		var text string
		if m.Role == "tool" && json.Unmarshal(m.Content, &text) == nil && strings.HasPrefix(text, "Not run") {
			out = append(out, text)
		}
	}
	return out
}

const inspectArgs = `{"reference":"U7"}`

func TestPairedChatAnswersAnAllInvalidRoundAndAsksAgain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	url, seen := scriptedChatModel(t,
		toolReply([3]string{"bad-1", "inspect_part", inspectArgs}, [3]string{"bad-2", "inspect_component", `"U7"`}),
		toolReply([3]string{"good", "inspect_component", inspectArgs}),
	)
	conn := connectPairedChat(t, ctx, url, "fixture-chat:7b", 8192).Conn
	readComputeReply(t, ctx, conn)
	writeChatFixtureJob(t, ctx, conn, "all-invalid")
	calls := resultCalls(t, readChatResult(t, ctx, conn, "all-invalid"))
	if len(calls) != 1 || calls[0].ID != "good" {
		t.Fatalf("want the corrected call only, got %+v", calls)
	}
	requests := seen()
	if len(requests) != 2 {
		t.Fatalf("want one retry, got %d model requests", len(requests))
	}
	errs := toolErrorsIn(requests[1].Messages)
	if len(errs) != 2 || !strings.Contains(errs[0], `"inspect_part" is not an offered tool`) ||
		!strings.Contains(errs[0], "inspect_component") || !strings.Contains(errs[1], "not a JSON object") {
		t.Fatalf("the model must see each refusal as its call's tool error: %q", errs)
	}
}

func TestPairedChatKeepsValidCallsAndReplaysRefusedOnesNextJob(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	url, seen := scriptedChatModel(t,
		toolReply([3]string{"mixed-good", "inspect_component", inspectArgs}, [3]string{"mixed-bad", "inspect_component", strings.Repeat("x", 9000)}),
		`{"model":"fixture-chat:7b","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"U7 is a regulator."}}],"usage":{"prompt_tokens":40,"completion_tokens":5,"total_tokens":45}}`,
	)
	conn := connectPairedChat(t, ctx, url, "fixture-chat:7b", 8192).Conn
	readComputeReply(t, ctx, conn)
	writeChatFixtureJob(t, ctx, conn, "mixed")
	calls := resultCalls(t, readChatResult(t, ctx, conn, "mixed"))
	if len(calls) != 1 || calls[0].ID != "mixed-good" {
		t.Fatalf("want the valid call kept alone, got %+v", calls)
	}
	// The browser runs the valid call and sends the round back with its result.
	if err := wsjson.Write(ctx, conn, map[string]any{
		"type": "job.assign", "jobType": "LLM_CHAT_TOOLS", "jobId": "mixed-next",
		"expiresAt": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano),
		"payload": map[string]any{
			"model": "fixture-chat:7b", "maxTokens": 128,
			"messages": []any{
				map[string]any{"role": "user", "content": "Inspect U7."},
				map[string]any{"role": "assistant", "content": nil, "tool_calls": calls},
				map[string]any{"role": "tool", "tool_call_id": "mixed-good", "content": `{"reference":"U7","value":"LDO"}`},
			},
			"tools": json.RawMessage(`[{"type":"function","function":{"name":"inspect_component","strict":true,"parameters":{"type":"object","properties":{"reference":{"type":"string"}},"required":["reference"],"additionalProperties":false}}}]`),
		},
	}); err != nil {
		t.Fatal(err)
	}
	if reply := readChatResult(t, ctx, conn, "mixed-next"); !reply.OK {
		t.Fatalf("follow-up job failed: %s", reply.Error)
	}
	next := seen()[1].Messages
	if len(next) != 4 || len(next[1].ToolCalls) != 2 || next[2].Role != "tool" || next[2].ToolCallID != next[1].ToolCalls[1].ID {
		t.Fatalf("the refused call must rejoin its round with its tool error: %+v", next)
	}
	if errs := toolErrorsIn(next); len(errs) != 1 || !strings.Contains(errs[0], "larger than 8 KiB") {
		t.Fatalf("want the size refusal, got %q", errs)
	}
}

func TestPairedChatFailsOnlyAfterRepeatedInvalidRounds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	bad := toolReply([3]string{"bad", "nope", `{}`})
	url, seen := scriptedChatModel(t, bad, bad, bad)
	conn := connectPairedChat(t, ctx, url, "fixture-chat:7b", 8192).Conn
	readComputeReply(t, ctx, conn)
	writeChatFixtureJob(t, ctx, conn, "stubborn")
	reply := readChatResult(t, ctx, conn, "stubborn")
	if reply.OK || !strings.HasPrefix(reply.Error, "CHAT_INVALID_TOOL_CALL") || len(seen()) != 3 {
		t.Fatalf("want CHAT_INVALID_TOOL_CALL after two retries: ok=%v error=%q requests=%d", reply.OK, reply.Error, len(seen()))
	}
}

// The device took the job but its model ran out of time: that is not the
// backend's CHAT_EXPIRED (never picked up).
func TestPairedChatSlowModelIsALocalTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	model, _, _ := blockingChatModel(t)
	conn := connectPairedChat(t, ctx, model.URL+"/v1", "fixture-chat:7b", 8192).Conn
	readComputeReply(t, ctx, conn)
	if err := wsjson.Write(ctx, conn, map[string]any{
		"type": "job.assign", "jobType": "LLM_CHAT_TOOLS", "jobId": "slow",
		"expiresAt": time.Now().Add(1500 * time.Millisecond).UTC().Format(time.RFC3339Nano),
		"payload":   map[string]any{"model": "fixture-chat:7b", "messages": []any{map[string]any{"role": "user", "content": "Inspect U7."}}, "tools": []any{}, "maxTokens": 128},
	}); err != nil {
		t.Fatal(err)
	}
	reply := readChatResult(t, ctx, conn, "slow")
	if reply.OK || !strings.HasPrefix(reply.Error, "CHAT_LOCAL_TIMEOUT") {
		t.Fatalf("want CHAT_LOCAL_TIMEOUT, got ok=%v error=%q", reply.OK, reply.Error)
	}
}
