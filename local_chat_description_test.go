package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestChatToolDescriptionBound(t *testing.T) {
	payload := func(description string) chatPayload {
		var p chatPayload
		raw := `{"model":"m","messages":[{"role":"user","content":"Plan it."}],"maxTokens":64,"tools":[{"type":"function","function":{"name":"pcb_coordinator_propose_plan","strict":true,"parameters":{"type":"object"}}}]}`
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			t.Fatal(err)
		}
		p.Tools[0].Function.Description = description
		return p
	}
	// PCB's plan tool description is 2529 bytes.
	if err := validateChatPayload(payload(strings.Repeat("x", 2529)), 131072, 1); err != nil {
		t.Fatalf("plan tool refused: %v", err)
	}
	if err := validateChatPayload(payload(strings.Repeat("x", maxChatToolDescription+1)), 131072, 1); err == nil {
		t.Fatal("over-limit description accepted")
	}
}
