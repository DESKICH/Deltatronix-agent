package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deltatronix/dtx-agent/internal/packruntime"
)

func packHTTPFixture(t *testing.T) (Config, *packRunnerSelection, packHTTPPolicy, []byte) {
	t.Helper()
	cfg, _ := approvedPackRunner(t)
	selection, err := loadPackRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"schemaVersion":1}`)
	sum := sha256.Sum256(raw)
	policy := packHTTPPolicy{JobID: "job-a", Attempt: 1, Input: packruntime.EvaluationInput{UserID: "caller-a", ProjectID: "project-a", PackID: "pack-a", Version: 1, SnapshotID: "snapshot-a", ContentHash: hex.EncodeToString(sum[:]), ByteSize: int64(len(raw))}}
	assignment := map[string]any{"contractVersion": 1, "action": "pack.evaluate_snapshot", "fence": packruntime.EvaluationFence{JobID: policy.JobID, Attempt: 1, LeaseID: "12345678-1234-1234-1234-123456789abc", AgentID: cfg.AgentID, RuntimeID: selection.trust.ArtifactID, ExpiresAt: time.Now().Add(10 * time.Second).UnixMilli()}, "input": policy.Input, "task": map[string]any{"taskVersion": 1, "domainId": "pack", "resource": map[string]any{"kind": "PACK", "id": "pack-a", "revision": "1"}, "goal": "Evaluate this saved Pack snapshot without saving.", "approvedBrief": []any{}, "constraints": map[string]any{"action": "pack.evaluate_snapshot", "projectId": "project-a"}, "inputArtifacts": []any{map[string]any{"kind": "pack_snapshot", "id": "snapshot-a", "revision": 1, "contentHash": policy.Input.ContentHash}}}}
	data, err := json.Marshal(assignment)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, selection, policy, data
}
func TestPackHTTPRequiresExactLoopbackAndPairing(t *testing.T) {
	cfg := Config{APIURL: "http://127.0.0.1:1234", AgentID: "agent-a", AgentToken: "synthetic"}
	if _, err := packFixtureBase(cfg); err != nil {
		t.Fatal(err)
	}
	for _, base := range []string{"https://api.deltatronix.io", "http://localhost:1234", "http://127.0.0.1:1234/other", "http://user@127.0.0.1:1234", "http://127.0.0.1:1234?scope=other", "http://127.0.0.1:1234/#other", "file:///tmp/input"} {
		bad := cfg
		bad.APIURL = base
		if _, err := packFixtureBase(bad); err == nil {
			t.Fatalf("unapproved URL accepted: %s", base)
		}
	}
	cfg.AgentToken = ""
	if _, err := packFixtureBase(cfg); err == nil {
		t.Fatal("unpaired fixture accepted")
	}
	t.Setenv("DTX_AGENT_CONFIG_DIR", "")
	var out bytes.Buffer
	if err := runPackHTTPFixture(context.Background(), []string{"--policy", "missing"}, &out); err == nil || out.Len() != 0 {
		t.Fatal("ordinary user profile admitted")
	}
}
func TestPackHTTPRenewalKeepsIdentityAndAdoptsOnlyValidExpiry(t *testing.T) {
	cfg, selection, policy, data := packHTTPFixture(t)
	assignment, _, err := packHTTPAssignment(data, policy, cfg, selection, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*packruntime.EvaluationFence){"job": func(f *packruntime.EvaluationFence) { f.JobID = "foreign" }, "attempt": func(f *packruntime.EvaluationFence) { f.Attempt++ }, "lease": func(f *packruntime.EvaluationFence) { f.LeaseID = "aaaaaaaa-1234-1234-1234-123456789abc" }, "agent": func(f *packruntime.EvaluationFence) { f.AgentID = "foreign" }, "runtime": func(f *packruntime.EvaluationFence) { f.RuntimeID = "pack-readonly-v1-" + strings.Repeat("b", 64) }, "expired": func(f *packruntime.EvaluationFence) { f.ExpiresAt = time.Now().Add(-time.Second).UnixMilli() }, "shortened": func(f *packruntime.EvaluationFence) { f.ExpiresAt-- }, "unbounded": func(f *packruntime.EvaluationFence) { f.ExpiresAt = time.Now().Add(time.Hour).UnixMilli() }} {
		t.Run(name, func(t *testing.T) {
			changed := assignment
			change(&changed.Fence)
			encoded, _ := json.Marshal(changed)
			if _, _, err := packHTTPAssignment(encoded, policy, cfg, selection, &assignment.Fence); err == nil {
				t.Fatal("renewal expanded scope or changed fence")
			}
		})
	}
	renewed := assignment
	renewed.Fence.ExpiresAt += 1000
	encoded, _ := json.Marshal(renewed)
	_, approval, err := packHTTPAssignment(encoded, policy, cfg, selection, &assignment.Fence)
	if err != nil || approval.Fence.ExpiresAt != renewed.Fence.ExpiresAt {
		t.Fatal("fresh exact fence not adopted", err)
	}
}
func installPackHTTPProfile(t *testing.T, api string) (Config, packRunnerConfig, packHTTPPolicy, string) {
	t.Helper()
	cfg, approval := approvedPackRunner(t)
	cfg.APIURL = api
	approval.APIURL = api
	writePackApproval(t, approval)
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	selection, err := loadPackRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"schemaVersion":1}`)
	sum := sha256.Sum256(raw)
	policy := packHTTPPolicy{JobID: "job-a", Attempt: 1, Input: packruntime.EvaluationInput{UserID: "caller-a", ProjectID: "project-a", PackID: "pack-a", Version: 1, SnapshotID: "snapshot-a", ContentHash: hex.EncodeToString(sum[:]), ByteSize: int64(len(raw))}}
	bytes, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err = os.WriteFile(path, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := validatePackHTTPPolicy(bytes, selection); err != nil {
		t.Fatal(err)
	}
	return cfg, approval, policy, path
}
func TestPackHTTPNoRedirectOrBlindClaimRetry(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusUnauthorized, http.StatusConflict} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			targetCalls := 0
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls++; w.WriteHeader(200) }))
			defer target.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/compute/pack-jobs/job-a/claim" || r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer synthetic" {
					t.Error("unexpected paired known-job request")
				}
				w.Header().Set("Location", target.URL)
				w.WriteHeader(status)
			}))
			defer server.Close()
			_, _, _, path := installPackHTTPProfile(t, server.URL)
			var out bytes.Buffer
			if err := runPackHTTPFixture(context.Background(), []string{"--policy", path}, &out); err == nil || out.Len() != 0 {
				t.Fatal("failed request emitted result")
			}
			if calls != 1 || targetCalls != 0 {
				t.Fatal("claim retried or credentials redirected", calls, targetCalls)
			}
		})
	}
}
func TestPackHTTPBadAssignmentNeverFetchesSnapshot(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"contractVersion":1,"action":"pack.evaluate_snapshot","fence":{},"input":{},"task":{}}`))
	}))
	defer server.Close()
	_, _, _, path := installPackHTTPProfile(t, server.URL)
	var out bytes.Buffer
	if err := runPackHTTPFixture(context.Background(), []string{"--policy", path}, &out); err == nil || calls != 1 || out.Len() != 0 {
		t.Fatal("bad metadata reached byte handoff", err, calls)
	}
}
