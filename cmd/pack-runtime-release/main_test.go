package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deltatronix/dtx-agent/internal/packruntime"
)

func keys(t *testing.T, dir string) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	privatePath, publicPath := filepath.Join(dir, "test-private.pem"), filepath.Join(dir, "test-public.pem")
	for path, b := range map[string][]byte{privatePath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: secret}), publicPath: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})} {
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return privatePath, publicPath
}
func signAndVerify(t *testing.T, binary, dir, packCoreVersion string) (packruntime.Descriptor, string, string) {
	t.Helper()
	private, public := keys(t, dir)
	var out bytes.Buffer
	sign := []string{"sign", "--binary", binary, "--platform", runtime.GOOS + "-" + runtime.GOARCH, "--worker-host-commit", packruntime.PortableWorkerHostCommit, "--key-id", "ephemeral-local-test", "--private-key", private}
	if packCoreVersion != "" {
		sign = append(sign, "--pack-core-version", packCoreVersion)
	}
	if err := run(context.Background(), sign, &out); err != nil {
		t.Fatal(err)
	}
	var d packruntime.Descriptor
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	descriptor := filepath.Join(dir, "descriptor.json")
	if err := os.WriteFile(descriptor, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	verify := []string{"verify", "--binary", binary, "--descriptor", descriptor, "--platform", runtime.GOOS + "-" + runtime.GOARCH, "--key-id", "ephemeral-local-test", "--public-key", public, "--artifact-id", d.ArtifactID}
	if err := run(context.Background(), verify, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "companion trust/configuration unchanged") {
		t.Fatal("verification overstated")
	}
	for _, args := range [][]string{verify[:len(verify)-2], append(append([]string{}, verify...), "--url=https://untrusted.test"), append(append([]string{}, verify...), "extra")} {
		if err := run(context.Background(), args, &out); err == nil {
			t.Fatal("unreviewed controls/selection accepted")
		}
	}
	return d, descriptor, public
}
func TestOfflineReleaseToolSignsAndVerifies(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "pack-readonly")
	if err := os.WriteFile(binary, []byte("local fixture, not executed"), 0600); err != nil {
		t.Fatal(err)
	}
	legacy, _, _ := signAndVerify(t, binary, dir, "")
	if legacy.PackCoreVersion != packruntime.LegacyPackCoreVersion {
		t.Fatal("legacy signing invocation changed")
	}
	next, _, _ := signAndVerify(t, binary, t.TempDir(), "0.1.1")
	if next.PackCoreVersion != "0.1.1" || next.ArtifactID == legacy.ArtifactID {
		t.Fatal("signer did not bind the selected reviewed Pack core")
	}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"sign", "--pack-core-version", "0.1.2", "--binary", "unused-binary", "--platform", runtime.GOOS + "-" + runtime.GOARCH, "--key-id", "unused-key", "--private-key", "unused-key"}, &out); err == nil || !strings.Contains(err.Error(), "unsupported Pack core version") || out.Len() != 0 {
		t.Fatal("unknown engine version reached local files or produced a descriptor")
	}
}
func TestOfflineReleaseToolRejectsNonRegularInputs(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "binary")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, link} {
		if _, err := packruntime.RegularFile(path); err == nil {
			t.Fatal("nonregular release input accepted")
		}
	}
}

// The supplied binary is independently compiled from exact UI #157 source in scratch.
// Ordinary unit runs do not pretend that a generic executable proves the real Pack adapter.
func TestActualCompiledPackWorkerRelease(t *testing.T) {
	binary, root := os.Getenv("PACK_RUNTIME_FIXTURE_BINARY"), os.Getenv("PACK_RUNTIME_FIXTURE_ROOT")
	if binary == "" || root == "" {
		t.Skip("requires ephemeral actual UI #157 compiled Pack fixture")
	}

	d, descriptor, public := signAndVerify(t, binary, t.TempDir(), "")
	if d.Executable.Size < 1<<20 {
		t.Fatal("expected actual compiled Deno worker")
	}
	snapshot := filepath.Join(root, "snapshot.json")
	before, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	ownedTemp := t.TempDir()
	t.Setenv("TMPDIR", ownedTemp)
	args := []string{"run-fixture", "--binary", binary, "--descriptor", descriptor, "--platform", runtime.GOOS + "-" + runtime.GOARCH, "--key-id", "ephemeral-local-test", "--public-key", public, "--artifact-id", d.ArtifactID, "--input-directory", root, "--principal", "user:caller-a"}
	var out bytes.Buffer
	if err := run(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Status      string `json:"status"`
		Checkpoints []struct {
			Receipts []struct {
				Status string `json:"status"`
			} `json:"receipts"`
		} `json:"checkpoints"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "waiting_for_input" || len(result.Checkpoints) != 1 || len(result.Checkpoints[0].Receipts) != 1 || result.Checkpoints[0].Receipts[0].Status != "readOnly" {
		t.Fatal("supervisor did not return actual read-only evidence")
	}
	after, err := os.ReadFile(snapshot)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("saved fixture changed")
	}
	foreign := append([]string{}, args...)
	foreign[len(foreign)-1] = "company:caller-a"
	out.Reset()
	if err := run(context.Background(), foreign, &out); err == nil || out.Len() != 0 {
		t.Fatal("foreign caller obtained result")
	}
	if err := os.WriteFile(snapshot, append(append([]byte{}, before...), 0), 0600); err != nil {
		t.Fatal(err)
	}
	defer os.WriteFile(snapshot, before, 0600)
	if err := run(context.Background(), args, &out); err == nil || out.Len() != 0 {
		t.Fatal("tampered snapshot obtained result")
	}
	if err := os.WriteFile(snapshot, before, 0600); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(cancelled, args, &out); !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatal("cancelled fixture admitted", err)
	}
	entries, err := os.ReadDir(ownedTemp)
	if err != nil || len(entries) != 0 {
		t.Fatal("private run directory not removed", err)
	}
	t.Logf("Actual portable UI29 worker passed signed one-shot host; %s (%d bytes); readOnly, foreign/tamper/cancel refusal, source unchanged and private run cleaned", d.ArtifactID, d.Executable.Size)
}

func TestActualCompiledPackAssignment(t *testing.T) {
	binary, root := os.Getenv("PACK_RUNTIME_FIXTURE_BINARY"), os.Getenv("PACK_RUNTIME_FIXTURE_ROOT")
	if binary == "" || root == "" {
		t.Skip("requires ephemeral actual UI #157 compiled Pack fixture")
	}
	d, descriptor, public := signAndVerify(t, binary, t.TempDir(), "")
	if d.Executable.Size < 1<<20 {
		t.Fatal("expected actual compiled Deno worker")
	}
	snapshot, err := os.ReadFile(filepath.Join(root, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(snapshot)
	approval := packruntime.AssignmentApproval{Fence: packruntime.EvaluationFence{JobID: "job-a", Attempt: 1, LeaseID: "lease-a", AgentID: "agent-a", RuntimeID: d.ArtifactID, ExpiresAt: time.Now().Add(time.Minute).UnixMilli()}, Input: packruntime.EvaluationInput{UserID: "caller-a", ProjectID: "project-a", PackID: "pack-a", Version: 7, SnapshotID: "snapshot-a", ContentHash: hex.EncodeToString(sum[:]), ByteSize: int64(len(snapshot))}}
	task := map[string]any{"taskVersion": 1, "domainId": "pack", "resource": map[string]any{"kind": "PACK", "id": "pack-a", "revision": "7"}, "goal": "Evaluate this saved Pack snapshot without saving.", "approvedBrief": []any{}, "constraints": map[string]any{"action": "pack.evaluate_snapshot", "projectId": "project-a"}, "inputArtifacts": []any{map[string]any{"kind": "pack_snapshot", "id": "snapshot-a", "revision": 7, "contentHash": approval.Input.ContentHash}}}
	assignment := map[string]any{"contractVersion": 1, "action": "pack.evaluate_snapshot", "fence": approval.Fence, "input": approval.Input, "task": task}
	input := t.TempDir()
	approvedDir := t.TempDir()
	approvalPath := filepath.Join(approvedDir, "approval.json")
	write := func(path string, v any) {
		t.Helper()
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(approvalPath, approval)
	write(filepath.Join(input, "assignment.json"), assignment)
	if err := os.WriteFile(filepath.Join(input, "snapshot.json"), snapshot, 0600); err != nil {
		t.Fatal(err)
	}
	owned := t.TempDir()
	t.Setenv("TMPDIR", owned)
	args := []string{"run-assignment", "--binary", binary, "--descriptor", descriptor, "--platform", runtime.GOOS + "-" + runtime.GOARCH, "--key-id", "ephemeral-local-test", "--public-key", public, "--artifact-id", d.ArtifactID, "--input-directory", input, "--principal", "user:caller-a", "--approval", approvalPath}
	var out bytes.Buffer
	if err := run(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	var result struct {
		ContractVersion int                         `json:"contractVersion"`
		Fence           packruntime.EvaluationFence `json:"fence"`
		Input           packruntime.EvaluationInput `json:"input"`
		Result          struct {
			Status      string `json:"status"`
			Revision    string `json:"revision"`
			Checkpoints []struct {
				Receipts []struct {
					Status string `json:"status"`
				} `json:"receipts"`
			} `json:"checkpoints"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ContractVersion != 1 || result.Fence != approval.Fence || result.Input != approval.Input || result.Result.Status != "waiting_for_input" || result.Result.Revision != "7" || len(result.Result.Checkpoints) != 1 || len(result.Result.Checkpoints[0].Receipts) != 1 || result.Result.Checkpoints[0].Receipts[0].Status != "readOnly" {
		t.Fatal("assignment result lost exact fence/input/read-only receipt")
	}
	for name, change := range map[string]func(){"lease": func() { changed := approval.Fence; changed.LeaseID = "stale"; assignment["fence"] = changed }, "attempt": func() { changed := approval.Fence; changed.Attempt++; assignment["fence"] = changed }, "runtime": func() {
		changed := approval.Fence
		changed.RuntimeID = "pack-readonly-v1-" + strings.Repeat("b", 64)
		assignment["fence"] = changed
	}, "principal": func() { changed := approval.Input; changed.UserID = "foreign"; assignment["input"] = changed }, "snapshot": func() {
		if err := os.WriteFile(filepath.Join(input, "snapshot.json"), append(append([]byte{}, snapshot...), 0), 0600); err != nil {
			t.Fatal(err)
		}
	}} {
		t.Run(name, func(t *testing.T) {
			assignment["fence"] = approval.Fence
			assignment["input"] = approval.Input
			change()
			write(filepath.Join(input, "assignment.json"), assignment)
			out.Reset()
			if err := run(context.Background(), args, &out); err == nil || out.Len() != 0 {
				t.Fatal("changed assignment obtained result")
			}
			if err := os.WriteFile(filepath.Join(input, "snapshot.json"), snapshot, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	after, err := os.ReadFile(filepath.Join(root, "snapshot.json"))
	if err != nil || !bytes.Equal(snapshot, after) {
		t.Fatal("saved source changed", err)
	}
	entries, err := os.ReadDir(owned)
	if err != nil || len(entries) != 0 {
		t.Fatal("assignment private runs not removed", err)
	}
	t.Logf("Actual signed portable worker consumed Backend #1069 v1 assignment, echoed exact pins, readOnly; changed lease/attempt/runtime/principal/snapshot refused; saved source unchanged and private runs cleaned")
}
