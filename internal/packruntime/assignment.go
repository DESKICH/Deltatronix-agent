package packruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// PRIVATE v1 wire shared with Backend #1069. These fields carry identity, not
// authority: the caller must supply independently approved current assignment
// pins, never derive approval from the queued assignment or registration.
type EvaluationFence struct {
	JobID     string `json:"jobId"`
	Attempt   int64  `json:"attempt"`
	LeaseID   string `json:"leaseId"`
	AgentID   string `json:"agentId"`
	RuntimeID string `json:"runtimeId"`
	ExpiresAt int64  `json:"expiresAt"`
}
type EvaluationInput struct {
	UserID      string `json:"userId"`
	ProjectID   string `json:"projectId"`
	PackID      string `json:"packId"`
	Version     int64  `json:"version"`
	SnapshotID  string `json:"snapshotId"`
	ContentHash string `json:"contentHash"`
	ByteSize    int64  `json:"byteSize"`
}
type AssignmentApproval struct {
	Fence EvaluationFence `json:"fence"`
	Input EvaluationInput `json:"input"`
}
type evaluationAssignment struct {
	ContractVersion int             `json:"contractVersion"`
	Action          string          `json:"action"`
	Fence           EvaluationFence `json:"fence"`
	Input           EvaluationInput `json:"input"`
	Task            json.RawMessage `json:"task"`
}
type evaluationResult struct {
	ContractVersion int             `json:"contractVersion"`
	Action          string          `json:"action"`
	Fence           EvaluationFence `json:"fence"`
	Input           EvaluationInput `json:"input"`
	Result          json.RawMessage `json:"result"`
}

var wireID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
var runtimeID = regexp.MustCompile(`^pack-readonly-v1-[a-f0-9]{64}$`)

const maxSafeInteger int64 = 9007199254740991

func validateAssignmentMetadata(data []byte, caller Principal, approved AssignmentApproval, trust Trust) (evaluationAssignment, error) {
	var assignment evaluationAssignment
	if len(data) > fixtureMetadataBytes || strictJSON(data, &assignment) != nil {
		return assignment, errors.New("invalid bounded Pack assignment")
	}
	// Saved version zero is valid; absent/null must not silently become zero.
	var shape struct {
		Input struct {
			Version *int64 `json:"version"`
		} `json:"input"`
	}
	if json.Unmarshal(data, &shape) != nil || shape.Input.Version == nil {
		return assignment, errors.New("assignment requires explicit saved version")
	}
	f, i := approved.Fence, approved.Input
	for _, id := range []string{f.JobID, f.LeaseID, f.AgentID, i.UserID, i.ProjectID, i.PackID, i.SnapshotID} {
		if !wireID.MatchString(id) {
			return assignment, errors.New("invalid approved assignment identity")
		}
	}
	if caller.Kind != "user" || caller.ID != i.UserID || f.Attempt < 1 || f.Attempt > maxSafeInteger || f.ExpiresAt <= 0 || f.ExpiresAt > maxSafeInteger || i.Version < 0 || i.Version > maxSafeInteger || i.ByteSize <= 0 || i.ByteSize > fixtureSnapshotBytes || !sha.MatchString(i.ContentHash) || f.RuntimeID != trust.ArtifactID || !runtimeID.MatchString(f.RuntimeID) {
		return assignment, errors.New("invalid approved assignment scope/runtime")
	}
	if assignment.ContractVersion != 1 || assignment.Action != "pack.evaluate_snapshot" || assignment.Fence != f || assignment.Input != i {
		return assignment, errors.New("assignment differs from independently approved current pins")
	}
	var task readTask
	if strictJSON(assignment.Task, &task) != nil || task.Goal != "Evaluate this saved Pack snapshot without saving." || len(task.InputArtifacts) != 1 || task.InputArtifacts[0].Revision == nil || *task.InputArtifacts[0].Revision != i.Version {
		return assignment, errors.New("assignment task version or goal differs")
	}
	scope := assignmentScope(i)
	if err := validateReadTask(task, scope); err != nil {
		return assignment, err
	}
	return assignment, nil
}
func validateAssignmentSnapshot(snapshot []byte, input EvaluationInput) error {
	sum := sha256.Sum256(snapshot)
	if int64(len(snapshot)) != input.ByteSize || hex.EncodeToString(sum[:]) != input.ContentHash {
		return errors.New("assignment snapshot bytes differ")
	}
	return nil
}

func assignmentScope(i EvaluationInput) readScope {
	return readScope{Principal: Principal{Kind: "user", ID: i.UserID}, ProjectID: i.ProjectID, ResourceID: i.PackID, Revision: strconv.FormatInt(i.Version, 10), Snapshot: snapshotScope{ID: i.SnapshotID, ContentHash: i.ContentHash, File: "snapshot.json"}, Assets: []json.RawMessage{}}
}

// RunAssignment is a consumed offline boundary, not a lease claim or dispatch
// endpoint. Approval must come from an independent trusted local operator today;
// future transport must revalidate authenticated current state before using it.
// Deadline/output/permissions reuse RunFixture. Memory is bounded by existing
// input/output limits, not an OS memory sandbox or resource attestation.
func RunAssignment(ctx context.Context, descriptor []byte, binary, input string, caller Principal, approved AssignmentApproval, trust Trust) (result json.RawMessage, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, stop := context.WithTimeout(ctx, fixtureWall)
	defer stop()
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(approved.Fence.ExpiresAt))
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := ReadRegularFile(filepath.Join(input, "assignment.json"), fixtureMetadataBytes)
	if err != nil {
		return nil, err
	}
	assignment, err := validateAssignmentMetadata(data, caller, approved, trust)
	if err != nil {
		return nil, err
	}
	snapshot, err := ReadRegularFile(filepath.Join(input, "snapshot.json"), fixtureSnapshotBytes)
	if err != nil {
		return nil, err
	}
	if err := validateAssignmentSnapshot(snapshot, assignment.Input); err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp("", "dtx-pack-assignment-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanup := os.RemoveAll(directory); cleanup != nil {
			result = nil
			err = errors.Join(err, cleanup)
		}
	}()
	scope, err := json.Marshal(assignmentScope(assignment.Input))
	if err != nil {
		return nil, err
	}
	for name, bytes := range map[string][]byte{"scope.json": scope, "task.json": assignment.Task, "snapshot.json": snapshot} {
		if err := os.WriteFile(filepath.Join(directory, name), bytes, 0400); err != nil {
			return nil, err
		}
	}
	result, err = RunFixture(ctx, descriptor, binary, directory, caller, trust)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(evaluationResult{1, assignment.Action, assignment.Fence, assignment.Input, result})
	if err != nil {
		return nil, err
	}
	if len(encoded) > fixtureResultBytes {
		return nil, errors.New("Pack assignment result exceeds envelope limit")
	}
	return encoded, nil
}
