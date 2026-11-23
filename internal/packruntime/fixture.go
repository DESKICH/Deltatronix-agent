package packruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/deltatronix/dtx-agent/internal/boundedoutput"
)

// Only the reviewed portable UI #157 build is supported by this local fixture caller.
const PortableWorkerHostCommit = "29d7f3cf0a57dd825e499760b6d36adb4842d249"
const fixtureWall = 5 * time.Second
const fixtureMetadataBytes = 64 << 10
const fixtureSnapshotBytes = 16 << 20
const fixtureResultBytes = 64 << 10

type Principal struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type snapshotScope struct {
	ID          string `json:"id"`
	ContentHash string `json:"contentHash"`
	File        string `json:"file"`
}
type readScope struct {
	Principal  Principal         `json:"principal"`
	ProjectID  string            `json:"projectId"`
	ResourceID string            `json:"resourceId"`
	Revision   string            `json:"revision"`
	Snapshot   snapshotScope     `json:"snapshot"`
	Assets     []json.RawMessage `json:"assets"`
}
type readTask struct {
	TaskVersion int    `json:"taskVersion"`
	DomainID    string `json:"domainId"`
	Resource    struct {
		Kind     string `json:"kind"`
		ID       string `json:"id"`
		Revision string `json:"revision"`
	} `json:"resource"`
	Goal          string            `json:"goal"`
	ApprovedBrief []json.RawMessage `json:"approvedBrief"`
	Constraints   struct {
		Action    string `json:"action"`
		ProjectID string `json:"projectId"`
	} `json:"constraints"`
	InputArtifacts []struct {
		Kind        string `json:"kind"`
		ID          string `json:"id"`
		ContentHash string `json:"contentHash"`
	} `json:"inputArtifacts"`
}

func strictJSON(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func text(value string) bool {
	return len(value) > 0 && len(value) <= 128 && !strings.ContainsAny(value, "\x00\r\n")
}
func validPrincipal(p Principal) bool {
	return (p.Kind == "user" || p.Kind == "company") && text(p.ID) && !strings.Contains(p.ID, ":")
}

// RegularFile refuses symlink/special inputs and replacement between lstat/open.
// Contents are detached into the private run directory before execution.
func RegularFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("fixture input must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		f.Close()
		return nil, errors.New("fixture input changed while opening")
	}
	return f, nil
}

// ReadRegularFile detaches one bounded regular local release/fixture input.
func ReadRegularFile(path string, max int64) ([]byte, error) {
	f, err := RegularFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("fixture input exceeds limit")
	}
	return data, nil
}
func loadFixture(input string, caller Principal) (readScope, map[string][]byte, error) {
	var scope readScope
	var task readTask
	if !validPrincipal(caller) {
		return scope, nil, errors.New("invalid fixture caller")
	}
	files := map[string][]byte{}
	for _, name := range []string{"scope.json", "task.json", "snapshot.json"} {
		limit := int64(fixtureMetadataBytes)
		if name == "snapshot.json" {
			limit = fixtureSnapshotBytes
		}
		data, err := ReadRegularFile(filepath.Join(input, name), limit)
		if err != nil {
			return scope, nil, err
		}
		files[name] = data
	}
	if strictJSON(files["scope.json"], &scope) != nil || strictJSON(files["task.json"], &task) != nil {
		return scope, nil, errors.New("invalid fixture scope/task")
	}
	if scope.Principal != caller || !text(scope.ProjectID) || !text(scope.ResourceID) || !text(scope.Revision) || !text(scope.Snapshot.ID) || !sha.MatchString(scope.Snapshot.ContentHash) || scope.Snapshot.File != "snapshot.json" || scope.Assets == nil || len(scope.Assets) != 0 {
		return scope, nil, errors.New("fixture requires exact caller and an asset-free saved scope")
	}
	h := sha256.Sum256(files["snapshot.json"])
	if hex.EncodeToString(h[:]) != scope.Snapshot.ContentHash {
		return scope, nil, errors.New("fixture snapshot hash mismatch")
	}
	if task.TaskVersion != 1 || task.DomainID != "pack" || task.Resource.Kind != "PACK" || task.Resource.ID != scope.ResourceID || task.Resource.Revision != scope.Revision || len(strings.TrimSpace(task.Goal)) == 0 || len(task.Goal) > 16384 || task.ApprovedBrief == nil || len(task.ApprovedBrief) != 0 || task.Constraints.Action != "pack.evaluate_snapshot" || task.Constraints.ProjectID != scope.ProjectID || len(task.InputArtifacts) != 1 {
		return scope, nil, errors.New("fixture task does not match read-only saved scope")
	}
	artifact := task.InputArtifacts[0]
	if artifact.Kind != "pack_snapshot" || artifact.ID != scope.Snapshot.ID || artifact.ContentHash != scope.Snapshot.ContentHash {
		return scope, nil, errors.New("fixture task snapshot mismatch")
	}
	return scope, files, nil
}

// RunFixture is an offline operator tool, not a pairing/authorization or sandbox attestation.
// Trust must be independently selected by the local release reviewer. A reviewed Deno
// executable supplies the baked job-only read/deny-net/env/run/write permission profile.
func RunFixture(ctx context.Context, descriptor []byte, binary, input string, caller Principal, trust Trust) (result json.RawMessage, err error) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil, errors.New("fixture process supervision currently requires macOS or Linux")
	}
	ctx, stop := context.WithTimeout(ctx, fixtureWall)
	defer stop()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scope, files, err := loadFixture(input, caller)
	if err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp("", "dtx-pack-fixture-run-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanup := os.RemoveAll(directory); cleanup != nil {
			result = nil
			err = errors.Join(err, cleanup)
		}
	}()
	executable := filepath.Join(directory, "pack-readonly")
	source, err := RegularFile(binary)
	if err != nil {
		return nil, err
	}
	target, err := os.OpenFile(executable, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		source.Close()
		return nil, err
	}
	n, copyErr := io.Copy(target, io.LimitReader(source, MaxExecutableBytes+1))
	err = errors.Join(copyErr, source.Close(), target.Close())
	if err != nil {
		return nil, err
	}
	if n > MaxExecutableBytes {
		return nil, errors.New("fixture executable exceeds limit")
	}
	copy, err := RegularFile(executable)
	if err != nil {
		return nil, err
	}
	d, err := Verify(descriptor, copy, trust)
	err = errors.Join(err, copy.Close())
	if err != nil {
		return nil, err
	}
	if d.WorkerHostCommit != PortableWorkerHostCommit || d.Platform != runtime.GOOS+"-"+runtime.GOARCH {
		return nil, errors.New("fixture requires reviewed portable worker for this platform")
	}
	if err := os.Chmod(executable, 0500); err != nil {
		return nil, err
	}
	job := filepath.Join(directory, "job")
	if err := os.Mkdir(job, 0700); err != nil {
		return nil, err
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(job, name), data, 0400); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := executeFixture(ctx, executable, directory, caller)
	if err != nil {
		return nil, err
	}
	if err := validateFixtureResult(data, scope); err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimSpace(data)), nil
}

func executeFixture(ctx context.Context, executable, directory string, caller Principal) ([]byte, error) {
	work, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	overflow := func() { cancel(boundedoutput.ErrLimit) }
	stdout := &boundedoutput.Buffer{Max: fixtureResultBytes, Overflow: overflow}
	stderr := &boundedoutput.Buffer{Max: 16 << 10, Overflow: overflow}
	command := exec.CommandContext(work, executable, "--root=job", "--principal="+caller.Kind+":"+caller.ID)
	command.Dir = directory
	command.Env = []string{}
	command.Stdout = stdout
	command.Stderr = stderr
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 250 * time.Millisecond
	err := command.Run()
	if cause := context.Cause(work); cause != nil {
		return nil, cause
	}
	if err != nil {
		return nil, fmt.Errorf("local Pack fixture failed: %w", err)
	}
	return stdout.Bytes(), nil
}
func validateFixtureResult(data []byte, scope readScope) error {
	var result struct {
		TaskVersion int               `json:"taskVersion"`
		DomainID    string            `json:"domainId"`
		Status      string            `json:"status"`
		Revision    string            `json:"revision"`
		SkillPins   []json.RawMessage `json:"skillPins"`
		Checkpoints []struct {
			StepID   string `json:"stepId"`
			Role     string `json:"role"`
			Receipts []struct {
				ToolCallID string `json:"toolCallId"`
				Tool       string `json:"tool"`
				Version    int    `json:"version"`
				Status     string `json:"status"`
				Revision   string `json:"revision"`
				Summary    string `json:"summary"`
			} `json:"receipts"`
		} `json:"checkpoints"`
	}
	if strictJSON(data, &result) != nil || result.TaskVersion != 1 || result.DomainID != "pack" || result.Status != "waiting_for_input" || result.Revision != scope.Revision || result.SkillPins == nil || len(result.SkillPins) != 0 || len(result.Checkpoints) != 1 {
		return errors.New("fixture returned invalid read-only result")
	}
	checkpoint := result.Checkpoints[0]
	if checkpoint.StepID != "evaluate-snapshot" || checkpoint.Role != "pack_native_evaluation" || len(checkpoint.Receipts) != 1 {
		return errors.New("fixture returned invalid read-only checkpoint")
	}
	receipt := checkpoint.Receipts[0]
	if receipt.ToolCallID != "evaluate-snapshot" || receipt.Tool != "pack_evaluate_snapshot" || receipt.Version != 1 || receipt.Status != "readOnly" || receipt.Revision != scope.Revision || len(strings.TrimSpace(receipt.Summary)) == 0 || len(receipt.Summary) > 1024 {
		return errors.New("fixture returned invalid read-only receipt")
	}
	return nil
}
