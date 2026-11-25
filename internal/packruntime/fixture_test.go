package packruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deltatronix/dtx-agent/internal/boundedoutput"
)

func fixtureInput(t *testing.T) (string, Principal, map[string]any, map[string]any) {
	t.Helper()
	directory := t.TempDir()
	caller := Principal{Kind: "user", ID: "caller-a"}
	snapshot := []byte(`{"schemaVersion":1}`)
	h := sha256.Sum256(snapshot)
	hash := hex.EncodeToString(h[:])
	scope := map[string]any{"principal": caller, "projectId": "project-a", "resourceId": "pack-a", "revision": "epoch-a:7", "snapshot": map[string]any{"id": "snapshot-a", "contentHash": hash, "file": "snapshot.json"}, "assets": []any{}}
	task := map[string]any{"taskVersion": 1, "domainId": "pack", "resource": map[string]any{"kind": "PACK", "id": "pack-a", "revision": "epoch-a:7"}, "goal": "Evaluate only", "approvedBrief": []any{}, "constraints": map[string]any{"action": "pack.evaluate_snapshot", "projectId": "project-a"}, "inputArtifacts": []any{map[string]any{"kind": "pack_snapshot", "id": "snapshot-a", "contentHash": hash}}}
	writeInput(t, directory, scope, task)
	if err := os.WriteFile(filepath.Join(directory, "snapshot.json"), snapshot, 0600); err != nil {
		t.Fatal(err)
	}
	return directory, caller, scope, task
}
func writeInput(t *testing.T, dir string, scope, task map[string]any) {
	t.Helper()
	for name, v := range map[string]any{"scope.json": scope, "task.json": task} {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
func TestFixtureInputIsDetachedAndBoundToIndependentCaller(t *testing.T) {
	directory, caller, _, _ := fixtureInput(t)
	scope, files, err := loadFixture(directory, caller)
	if err != nil {
		t.Fatal(err)
	}
	if scope.Revision != "epoch-a:7" {
		t.Fatal(scope)
	}
	if err := os.WriteFile(filepath.Join(directory, "snapshot.json"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if string(files["snapshot.json"]) != `{"schemaVersion":1}` {
		t.Fatal("snapshot not detached")
	}
}
func TestFixtureInputRejectsAuthorityAndByteExpansion(t *testing.T) {
	for name, mutate := range map[string]func(Principal, map[string]any, map[string]any) Principal{
		"principal kind": func(p Principal, s, task map[string]any) Principal { p.Kind = "company"; return p },
		"principal id":   func(p Principal, s, task map[string]any) Principal { p.ID = "foreign"; return p },
		"invalid caller": func(p Principal, s, task map[string]any) Principal { p.ID = "caller:extra"; return p },
		"assets": func(p Principal, s, task map[string]any) Principal {
			s["assets"] = []any{map[string]any{"id": "asset"}}
			return p
		},
		"traversal": func(p Principal, s, task map[string]any) Principal {
			s["snapshot"].(map[string]any)["file"] = "../snapshot.json"
			return p
		},
		"hash": func(p Principal, s, task map[string]any) Principal {
			s["snapshot"].(map[string]any)["contentHash"] = strings.Repeat("b", 64)
			return p
		},
		"project":  func(p Principal, s, task map[string]any) Principal { s["projectId"] = "foreign"; return p },
		"resource": func(p Principal, s, task map[string]any) Principal { s["resourceId"] = "foreign"; return p },
		"revision": func(p Principal, s, task map[string]any) Principal { s["revision"] = "stale"; return p },
		"action": func(p Principal, s, task map[string]any) Principal {
			task["constraints"].(map[string]any)["action"] = "pack.save"
			return p
		},
		"snapshot id": func(p Principal, s, task map[string]any) Principal {
			s["snapshot"].(map[string]any)["id"] = "foreign"
			return p
		},
		"signal": func(p Principal, s, task map[string]any) Principal { task["signal"] = map[string]any{}; return p },
		"brief": func(p Principal, s, task map[string]any) Principal {
			task["approvedBrief"] = []any{map[string]any{"kind": "note"}}
			return p
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, caller, scope, task := fixtureInput(t)
			caller = mutate(caller, scope, task)
			writeInput(t, dir, scope, task)
			if _, _, err := loadFixture(dir, caller); err == nil {
				t.Fatal("expanded fixture authority accepted")
			}
		})
	}
}
func TestFixtureInputRefusesSymlinkAndOversizedMetadata(t *testing.T) {
	dir, caller, _, _ := fixtureInput(t)
	scope := filepath.Join(dir, "scope.json")
	data, err := os.ReadFile(scope)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(outside, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(scope); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, scope); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadFixture(dir, caller); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Remove(scope); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scope, make([]byte, fixtureMetadataBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadFixture(dir, caller); err == nil {
		t.Fatal("oversized metadata accepted")
	}
}
func fixtureResult(t *testing.T, scope readScope) []byte {
	t.Helper()
	result := map[string]any{"taskVersion": 1, "domainId": "pack", "status": "waiting_for_input", "revision": scope.Revision, "skillPins": []any{}, "checkpoints": []any{map[string]any{"stepId": "evaluate-snapshot", "role": "pack_native_evaluation", "receipts": []any{map[string]any{"toolCallId": "evaluate-snapshot", "tool": "pack_evaluate_snapshot", "version": 1, "status": "readOnly", "revision": scope.Revision, "summary": "Evaluated snapshot " + scope.Snapshot.ID + " (" + scope.Snapshot.ContentHash + "); 0 engine issue(s). No save or final readiness verification."}}}}}
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestFixtureResultRefusesStaleWritableAndTrailingEvidence(t *testing.T) {
	dir, caller, _, _ := fixtureInput(t)
	scope, _, err := loadFixture(dir, caller)
	if err != nil {
		t.Fatal(err)
	}
	data := fixtureResult(t, scope)
	if err := validateFixtureResult(data, scope); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(string(data), "readOnly", "applied", 1), strings.ReplaceAll(string(data), scope.Revision, "stale"), strings.Replace(string(data), "pack_evaluate_snapshot", "pack_save", 1), strings.Replace(string(data), `"taskVersion":1`, `"readinessReport":{},"taskVersion":1`, 1), string(data) + " {}"} {
		if validateFixtureResult([]byte(bad), scope) == nil {
			t.Fatal("invalid result accepted")
		}
	}
}

// Unit-only child exercises process ownership. Actual Deno proof is separate and optional.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "--root=job" && strings.HasPrefix(os.Args[2], "--principal=user:unit-") {
		mode := strings.TrimPrefix(os.Args[2], "--principal=user:unit-")
		signal.Ignore(os.Interrupt)
		switch mode {
		case "env":
			if len(os.Environ()) != 0 {
				os.Exit(2)
			}
			fmt.Print("{}")
			os.Exit(0)
		case "stdout":
			fmt.Print(strings.Repeat("x", fixtureResultBytes+1))
		case "stderr":
			fmt.Fprint(os.Stderr, strings.Repeat("x", (16<<10)+1))
		case "block":
			if err := os.WriteFile("started", []byte("interrupt-ignored"), 0600); err != nil {
				os.Exit(3)
			}
		default:
			os.Exit(2)
		}
		// A regression must still self-clean the unit child instead of orphaning it.
		time.Sleep(5 * time.Second)
		os.Exit(9)
	}
	os.Exit(m.Run())
}
func TestFixtureChildHasEmptyEnvAndBoundedTermination(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DTX_PARENT_SECRET_MARKER", "must-not-reach-child")
	data, err := executeFixture(context.Background(), executable, t.TempDir(), Principal{Kind: "user", ID: "unit-env"})
	if err != nil || string(data) != "{}" {
		t.Fatal(string(data), err)
	}
	for _, mode := range []string{"stdout", "stderr", "block"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			start := time.Now()
			directory := t.TempDir()
			_, err := executeFixture(ctx, executable, directory, Principal{Kind: "user", ID: "unit-" + mode})
			expected := boundedoutput.ErrLimit
			if mode == "block" {
				expected = context.DeadlineExceeded
				if marker, e := os.ReadFile(filepath.Join(directory, "started")); e != nil || string(marker) != "interrupt-ignored" {
					t.Fatal("blocking child did not start with interrupt ignored", e)
				}
			}
			if !errors.Is(err, expected) || time.Since(start) > 3*time.Second {
				t.Fatalf("child not bounded/reaped: %v (%s)", err, time.Since(start))
			}
		})
	}
}

func TestRunFixtureRefusesUnreviewedRuntimeAndRemovesPrivateCopies(t *testing.T) {
	dir, caller, _, _ := fixtureInput(t)
	d, trust, binary, _ := fixture(t)
	executable := filepath.Join(t.TempDir(), "not-executed")
	if err := os.WriteFile(executable, binary, 0600); err != nil {
		t.Fatal(err)
	}
	owned := t.TempDir()
	t.Setenv("TMPDIR", owned)
	if _, err := RunFixture(context.Background(), encoded(t, d), executable, dir, caller, trust); err == nil || !strings.Contains(err.Error(), "reviewed portable worker") {
		t.Fatal("unreviewed source accepted", err)
	}
	changed := append(append([]byte{}, binary...), 0)
	if err := os.WriteFile(executable, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RunFixture(context.Background(), encoded(t, d), executable, dir, caller, trust); err == nil || !strings.Contains(err.Error(), "hash/size mismatch") {
		t.Fatal("changed executable accepted", err)
	}
	entries, err := os.ReadDir(owned)
	if err != nil || len(entries) != 0 {
		t.Fatal("private failed run not cleaned", err)
	}
}

func TestRunFixtureUsesExactSignedWorkerHostAndCoreTuple(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("fixture process supervision requires POSIX")
	}
	dir, caller, _, _ := fixtureInput(t)
	scope, _, err := loadFixture(dir, caller)
	if err != nil {
		t.Fatal(err)
	}
	reply := fixtureResult(t, scope)
	worker := []byte("#!/bin/sh\nprintf '%s\\n' '" + string(reply) + "'\n")
	executable := filepath.Join(t.TempDir(), "fixture-worker")
	if err := os.WriteFile(executable, worker, 0600); err != nil {
		t.Fatal(err)
	}
	_, baseTrust, _, key := fixture(t)
	for _, test := range []struct {
		version, commit string
		approved        bool
	}{
		{LegacyPackCoreVersion, PortableWorkerHostCommit, true},
		{"0.1.1", PortableWorkerHostCommit011, true},
		{LegacyPackCoreVersion, PortableWorkerHostCommit011, false},
		{"0.1.1", PortableWorkerHostCommit, false},
	} {
		t.Run(test.version+"/"+test.commit[:7], func(t *testing.T) {
			descriptor, err := Build(strings.NewReader(string(worker)), runtime.GOOS+"-"+runtime.GOARCH, test.commit, test.version, baseTrust.KeyID, key)
			if err != nil {
				t.Fatal(err)
			}
			trust := baseTrust
			trust.ArtifactID, trust.Platform = descriptor.ArtifactID, descriptor.Platform
			result, err := RunFixture(context.Background(), encoded(t, descriptor), executable, dir, caller, trust)
			if !test.approved {
				if err == nil || !strings.Contains(err.Error(), "reviewed portable worker") || result != nil {
					t.Fatalf("crossed source/version tuple executed: %v", err)
				}
			} else if err != nil || string(result) != string(reply) {
				t.Fatalf("approved synthetic fixture did not execute: %v", err)
			}
		})
	}
}
