package packruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func assignmentFixture(t *testing.T) ([]byte, []byte, Principal, AssignmentApproval, Trust) {
	t.Helper()
	snapshot := []byte(`{"schemaVersion":1}`)
	sum := sha256.Sum256(snapshot)
	approval := AssignmentApproval{EvaluationFence{"job-a", 1, "lease-a", "agent-a", "pack-readonly-v1-" + strings.Repeat("a", 64), time.Now().Add(time.Minute).UnixMilli()}, EvaluationInput{"caller-a", "project-a", "pack-a", 7, "snapshot-a", hex.EncodeToString(sum[:]), int64(len(snapshot))}}
	task := map[string]any{"taskVersion": 1, "domainId": "pack", "resource": map[string]any{"kind": "PACK", "id": "pack-a", "revision": "7"}, "goal": "Evaluate this saved Pack snapshot without saving.", "approvedBrief": []any{}, "constraints": map[string]any{"action": "pack.evaluate_snapshot", "projectId": "project-a"}, "inputArtifacts": []any{map[string]any{"kind": "pack_snapshot", "id": "snapshot-a", "revision": 7, "contentHash": approval.Input.ContentHash}}}
	taskJSON, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(evaluationAssignment{1, "pack.evaluate_snapshot", approval.Fence, approval.Input, taskJSON})
	if err != nil {
		t.Fatal(err)
	}
	return data, snapshot, Principal{"user", "caller-a"}, approval, Trust{ArtifactID: approval.Fence.RuntimeID}
}
func TestAssignmentBindsIndependentCurrentFenceInputAndRuntime(t *testing.T) {
	data, snapshot, caller, approval, trust := assignmentFixture(t)
	if _, err := validateAssignment(data, snapshot, caller, approval, trust); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*AssignmentApproval){"lease": func(p *AssignmentApproval) { p.Fence.LeaseID = "changed" }, "attempt": func(p *AssignmentApproval) { p.Fence.Attempt++ }, "agent": func(p *AssignmentApproval) { p.Fence.AgentID = "foreign" }, "actor": func(p *AssignmentApproval) { p.Input.UserID = "foreign" }, "project": func(p *AssignmentApproval) { p.Input.ProjectID = "foreign" }, "pack": func(p *AssignmentApproval) { p.Input.PackID = "foreign" }, "version": func(p *AssignmentApproval) { p.Input.Version++ }, "snapshot": func(p *AssignmentApproval) { p.Input.SnapshotID = "changed" }, "runtime": func(p *AssignmentApproval) { p.Fence.RuntimeID = "pack-readonly-v1-" + strings.Repeat("b", 64) }, "expiry": func(p *AssignmentApproval) { p.Fence.ExpiresAt++ }, "length": func(p *AssignmentApproval) { p.Input.ByteSize++ }} {
		t.Run(name, func(t *testing.T) {
			changed := approval
			change(&changed)
			if _, err := validateAssignment(data, snapshot, caller, changed, trust); err == nil {
				t.Fatal("mismatched approved pins accepted")
			}
		})
	}
	if _, err := validateAssignment(data, snapshot, Principal{"company", caller.ID}, approval, trust); err == nil {
		t.Fatal("foreign caller accepted")
	}
	if _, err := validateAssignment(data, append(snapshot, 0), caller, approval, trust); err == nil {
		t.Fatal("changed bytes accepted")
	}
	if _, err := validateAssignment(data, snapshot, caller, approval, Trust{ArtifactID: "unapproved"}); err == nil {
		t.Fatal("queued runtime became trust")
	}
}
func TestAssignmentRequiresExactTaskAndBoundedEnvelope(t *testing.T) {
	data, snapshot, caller, approval, trust := assignmentFixture(t)
	for _, bad := range []string{strings.Replace(string(data), `"revision":7`, `"revision":8`, 1), strings.Replace(string(data), `"revision":"7"`, `"revision":"epoch:7"`, 1), strings.Replace(string(data), `"approvedBrief":[]`, `"approvedBrief":[{}]`, 1), strings.Replace(string(data), `"goal":"Evaluate this saved Pack snapshot without saving."`, `"goal":"Save"`, 1), strings.Replace(string(data), `"taskVersion":1`, `"extra":true,"taskVersion":1`, 1), string(data) + " {}", strings.Repeat(" ", fixtureMetadataBytes+1)} {
		if _, err := validateAssignment([]byte(bad), snapshot, caller, approval, trust); err == nil {
			t.Fatal("changed task/oversized envelope accepted")
		}
	}
}
func TestAssignmentExpiredOrCancelledNeverStagesOrExecutes(t *testing.T) {
	_, _, caller, approval, trust := assignmentFixture(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunAssignment(cancelled, nil, "does-not-exist", "does-not-exist", caller, approval, trust); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	approval.Fence.ExpiresAt = time.Now().Add(-time.Second).UnixMilli()
	if _, err := RunAssignment(context.Background(), nil, "does-not-exist", "does-not-exist", caller, approval, trust); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
func TestFixtureHistoricalArtifactWithoutRevisionAndExactNumericRevision(t *testing.T) {
	dir, caller, scope, task := fixtureInput(t)
	if _, _, err := loadFixture(dir, caller); err != nil {
		t.Fatal("historical fixture refused", err)
	}
	scope["revision"] = "7"
	task["resource"].(map[string]any)["revision"] = "7"
	task["inputArtifacts"].([]any)[0].(map[string]any)["revision"] = 7
	writeInput(t, dir, scope, task)
	if _, _, err := loadFixture(dir, caller); err != nil {
		t.Fatal("exact numeric revision refused", err)
	}
	task["inputArtifacts"].([]any)[0].(map[string]any)["revision"] = 8
	writeInput(t, dir, scope, task)
	if _, _, err := loadFixture(dir, caller); err == nil {
		t.Fatal("mismatched optional artifact revision accepted")
	}
}
func TestAssignmentMalformedRefusesBeforeRuntimeOpenAndCleans(t *testing.T) {
	data, snapshot, caller, approval, trust := assignmentFixture(t)
	directory := t.TempDir()
	owned := t.TempDir()
	t.Setenv("TMPDIR", owned)
	for name, bytes := range map[string][]byte{"assignment.json": data, "snapshot.json": append(snapshot, 0)} {
		if err := os.WriteFile(filepath.Join(directory, name), bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RunAssignment(context.Background(), nil, "missing-runtime", directory, caller, approval, trust); err == nil || !strings.Contains(err.Error(), "snapshot bytes differ") {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(owned)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed assignment left private files", err)
	}
}

func TestAssignmentVersionZeroStillRequiresPresentNumericVersion(t *testing.T) {
	data, snapshot, caller, approval, trust := assignmentFixture(t)
	data = []byte(strings.ReplaceAll(strings.ReplaceAll(string(data), `"version":7`, `"version":0`), `"revision":7`, `"revision":0`))
	data = []byte(strings.ReplaceAll(string(data), `"revision":"7"`, `"revision":"0"`))
	approval.Input.Version = 0
	if _, err := validateAssignment(data, snapshot, caller, approval, trust); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(string(data), `"version":0,`, "", 1), strings.Replace(string(data), `"version":0`, `"version":null`, 1)} {
		if _, err := validateAssignment([]byte(bad), snapshot, caller, approval, trust); err == nil {
			t.Fatal("absent/null saved version became zero")
		}
	}
}
