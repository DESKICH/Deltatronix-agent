package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/deltatronix/dtx-agent/internal/packruntime"
)

// Local fixture policy is independent of the paired server's job payload. No
// default remote approval, daemon polling or automatically trusted task exists.
type packHTTPPolicy struct {
	JobID   string                      `json:"jobId"`
	Attempt int64                       `json:"attempt"`
	Input   packruntime.EvaluationInput `json:"input"`
}

const packHTTPMetadataBytes = 64 << 10

var packHTTPID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
var packHTTPHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var packHTTPLease = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func decodePackHTTP(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if dec.Decode(new(any)) != io.EOF {
		return errors.New("invalid Pack fixture JSON")
	}
	return nil
}
func packFixtureBase(cfg Config, approvedAPI string) (string, error) {
	u, err := url.Parse(cfg.APIURL)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return "", errors.New("Pack HTTP fixture requires loopback or explicitly approved canonical HTTPS API")
	}
	base := strings.TrimRight(u.String(), "/")
	ip := net.ParseIP(u.Hostname())
	local := ip != nil && ip.IsLoopback() && approvedAPI == ""
	approved := approvedAPI == defaultAPI && base == defaultAPI
	if !local && !approved {
		return "", errors.New("Pack HTTP fixture requires loopback or explicitly approved canonical HTTPS API")
	}
	if cfg.AgentID == "" || cfg.AgentToken == "" {
		return "", errors.New("Pack HTTP fixture requires existing isolated pairing")
	}
	return base, nil
}
func validatePackHTTPPolicy(data []byte, selection *packRunnerSelection) (packHTTPPolicy, error) {
	var policy packHTTPPolicy
	if len(data) > packHTTPMetadataBytes || decodePackHTTP(data, &policy) != nil {
		return policy, errors.New("invalid independent Pack HTTP fixture policy")
	}
	var shape struct {
		Input struct {
			Version *int64 `json:"version"`
		} `json:"input"`
	}
	if json.Unmarshal(data, &shape) != nil || shape.Input.Version == nil {
		return policy, errors.New("Pack fixture policy requires explicit saved version")
	}
	for _, id := range []string{policy.JobID, policy.Input.UserID, policy.Input.ProjectID, policy.Input.PackID, policy.Input.SnapshotID} {
		if !packHTTPID.MatchString(id) {
			return policy, errors.New("invalid Pack fixture identity")
		}
	}
	if policy.Attempt < 1 || policy.Attempt > 9007199254740991 || policy.Input.Version < 0 || policy.Input.Version > 9007199254740991 || policy.Input.ByteSize <= 0 || policy.Input.ByteSize > 16<<20 || !packHTTPHash.MatchString(policy.Input.ContentHash) || !slices.Contains(selection.registration.ProjectIDs, policy.Input.ProjectID) || !packruntime.IsReviewedPortableWorker(selection.verified) {
		return policy, errors.New("Pack fixture policy or reviewed runtime unavailable")
	}
	return policy, nil
}
func packHTTPAssignment(data []byte, policy packHTTPPolicy, cfg Config, selection *packRunnerSelection, previous *packruntime.EvaluationFence) (packruntime.EvaluationAssignment, packruntime.AssignmentApproval, error) {
	var assignment packruntime.EvaluationAssignment
	if len(data) > packHTTPMetadataBytes || decodePackHTTP(data, &assignment) != nil {
		return assignment, packruntime.AssignmentApproval{}, errors.New("invalid bounded Pack HTTP assignment")
	}
	f := assignment.Fence
	if f.JobID != policy.JobID || f.Attempt != policy.Attempt || f.AgentID != cfg.AgentID || f.RuntimeID != selection.trust.ArtifactID || !packHTTPLease.MatchString(f.LeaseID) || f.ExpiresAt <= time.Now().UnixMilli() || f.ExpiresAt > time.Now().Add(time.Minute).UnixMilli() {
		return assignment, packruntime.AssignmentApproval{}, errors.New("Pack HTTP assignment differs from approved current fixture")
	}
	if previous != nil && (f.JobID != previous.JobID || f.Attempt != previous.Attempt || f.LeaseID != previous.LeaseID || f.AgentID != previous.AgentID || f.RuntimeID != previous.RuntimeID || f.ExpiresAt < previous.ExpiresAt) {
		return assignment, packruntime.AssignmentApproval{}, errors.New("Pack renewal changed identity or shortened expiry")
	}
	approval := packruntime.AssignmentApproval{Fence: f, Input: policy.Input}
	validated, err := packruntime.ValidateAssignmentMetadata(data, packruntime.Principal{Kind: "user", ID: policy.Input.UserID}, approval, selection.trust)
	return validated, approval, err
}

type pairedPackHTTP struct {
	client   *http.Client
	endpoint string
	token    string
	input    packruntime.EvaluationInput
}

func (control *pairedPackHTTP) request(ctx context.Context, method, path, lease string, body []byte, status int, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, control.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+control.token)
	if path == "/input" {
		req.Header.Set("Accept-Encoding", "identity")
	}
	if lease != "" {
		req.Header.Set("X-Pack-Lease", lease)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := control.client.Do(req)
	if err != nil {
		return nil, errors.New("Pack fixture request failed; no automatic retry")
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		return nil, fmt.Errorf("Pack fixture request refused (%d); no automatic retry", response.StatusCode)
	}
	coding := strings.TrimSpace(strings.Join(response.Header.Values("Content-Encoding"), ","))
	if response.Uncompressed || (coding != "" && !strings.EqualFold(coding, "identity")) {
		return nil, errors.New("Pack fixture refuses encoded responses")
	}
	noStore := false
	for _, directive := range strings.Split(response.Header.Get("Cache-Control"), ",") {
		if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
			noStore = true
		}
	}
	if !noStore {
		return nil, errors.New("Pack fixture response must be no-store")
	}
	if path == "/input" && response.ContentLength >= 0 && response.ContentLength != control.input.ByteSize {
		return nil, errors.New("Pack fixture input length differs")
	}
	bytes, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(bytes)) > limit {
		return nil, errors.New("Pack fixture response exceeds limit")
	}
	if path == "/input" {
		if err := packruntime.ValidateSnapshotBytes(bytes, control.input); err != nil {
			return nil, err
		}
	}
	return bytes, nil
}

func runPackHTTPFixture(ctx context.Context, args []string, out io.Writer) (err error) {
	// Requiring an explicit profile prevents this experimental command from
	// accidentally claiming work with the user's ordinary desktop credentials.
	if os.Getenv("DTX_AGENT_CONFIG_DIR") == "" {
		return errors.New("Pack HTTP fixture requires explicit isolated DTX_AGENT_CONFIG_DIR")
	}
	flags := flag.NewFlagSet("pack-http-fixture", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policyPath := flags.String("policy", "", "independently approved local known-job/input policy JSON")
	approvedAPI := flags.String("approve-api", "", "explicit canonical HTTPS API approval; must match isolated profile")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *policyPath == "" {
		return errors.New("use pack-http-fixture --policy <independent-local-policy.json>")
	}
	cfg, err := loadConfig()
	if err != nil {
		return errors.New("isolated fixture pairing unavailable")
	}
	base, err := packFixtureBase(cfg, *approvedAPI)
	if err != nil {
		return err
	}
	selection, err := loadPackRunner(cfg)
	if err != nil || selection == nil {
		return errors.New("independently approved signed Pack runtime unavailable")
	}
	data, err := packruntime.ReadRegularFile(*policyPath, packHTTPMetadataBytes)
	if err != nil {
		return err
	}
	policy, err := validatePackHTTPPolicy(data, selection)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, DisableCompression: true}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("Pack HTTP fixture refuses redirects")
	}}
	defer client.CloseIdleConnections()
	control := pairedPackHTTP{client: client, endpoint: base + "/compute/pack-jobs/" + policy.JobID, token: cfg.AgentToken, input: policy.Input}
	claimed, err := control.request(ctx, http.MethodPost, "/claim", "", nil, 200, packHTTPMetadataBytes)
	if err != nil {
		return err
	}
	assignment, _, err := packHTTPAssignment(claimed, policy, cfg, selection, nil)
	if err != nil {
		return err
	}
	snapshot, err := control.request(ctx, http.MethodGet, "/input", assignment.Fence.LeaseID, nil, 200, policy.Input.ByteSize)
	if err != nil {
		return err
	}
	renewed, err := control.request(ctx, http.MethodPost, "/renew", assignment.Fence.LeaseID, nil, 200, packHTTPMetadataBytes)
	if err != nil {
		return err
	}
	current, approval, err := packHTTPAssignment(renewed, policy, cfg, selection, &assignment.Fence)
	if err != nil {
		return err
	}
	directory, err := os.MkdirTemp("", "dtx-pack-http-fixture-")
	if err != nil {
		return err
	}
	defer func() {
		if cleanup := os.RemoveAll(directory); cleanup != nil {
			err = errors.Join(err, cleanup)
		}
	}()
	for name, bytes := range map[string][]byte{"assignment.json": renewed, "snapshot.json": snapshot} {
		if err := os.WriteFile(filepath.Join(directory, name), bytes, 0400); err != nil {
			return err
		}
	}
	result, err := packruntime.RunAssignment(ctx, selection.descriptor, selection.binary, directory, packruntime.Principal{Kind: "user", ID: policy.Input.UserID}, approval, selection.trust)
	if err != nil {
		return err
	}
	if time.Now().UnixMilli() >= current.Fence.ExpiresAt {
		return errors.New("Pack fixture lease expired before result submission")
	}
	if _, err := control.request(ctx, http.MethodPost, "/result", current.Fence.LeaseID, result, 204, 0); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(result))
	return err
}
