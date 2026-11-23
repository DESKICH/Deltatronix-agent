// Package packruntime describes a signed read-only Pack executable for offline release review.
// It does not configure companion trust, authorize tasks or attest process confinement.
package packruntime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/deltatronix/dtx-agent/internal/runtimeartifact"
)

const MaxExecutableBytes int64 = 128 << 20
const MaxDescriptorBytes = 64 << 10

var sha = regexp.MustCompile(`^[a-f0-9]{64}$`)
var commit = regexp.MustCompile(`^[a-f0-9]{40}$`)
var keyName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

type Signature struct {
	Algorithm   string `json:"algorithm"`
	KeyID       string `json:"keyId"`
	ValueBase64 string `json:"valueBase64"`
}
type Executable struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Descriptor struct {
	SchemaVersion    int        `json:"schemaVersion"`
	ArtifactID       string     `json:"artifactId"`
	Domain           string     `json:"domain"`
	Action           string     `json:"action"`
	Platform         string     `json:"platform"`
	DenoVersion      string     `json:"denoVersion"`
	PackCoreVersion  string     `json:"packCoreVersion"`
	WorkerHostCommit string     `json:"workerHostCommit"`
	Executable       Executable `json:"executable"`
	Signature        Signature  `json:"signature"`
}

// Trust is supplied by the release reviewer, not by queued data or the descriptor.
// No production Pack key or release selection is installed by this package.
type Trust struct{ KeyID, PublicKeyPEM, ArtifactID, Platform string }

func executableDigest(binary io.Reader) (Executable, error) {
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(binary, MaxExecutableBytes+1))
	if err != nil {
		return Executable{}, err
	}
	if n == 0 || n > MaxExecutableBytes {
		return Executable{}, errors.New("Pack executable exceeds release size limit")
	}
	return Executable{Name: "pack-readonly", SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}, nil
}
func unsigned(d Descriptor) (map[string]any, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	delete(m, "signature")
	return m, nil
}
func artifactID(d Descriptor) (string, error) {
	m, err := unsigned(d)
	if err != nil {
		return "", err
	}
	delete(m, "artifactId")
	b, err := runtimeartifact.CanonicalJSON(m)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return "pack-readonly-v1-" + hex.EncodeToString(h[:]), nil
}
func validate(d Descriptor) error {
	if d.SchemaVersion != 1 || d.Domain != "pack" || d.Action != "pack.evaluate_snapshot" || d.DenoVersion != "2.9.8" || d.PackCoreVersion != "0.1.0" || !commit.MatchString(d.WorkerHostCommit) || d.Executable.Name != "pack-readonly" || !sha.MatchString(d.Executable.SHA256) || d.Executable.Size <= 0 || d.Executable.Size > MaxExecutableBytes {
		return errors.New("unsupported Pack release descriptor")
	}
	switch d.Platform {
	case "darwin-arm64", "darwin-amd64", "linux-arm64", "linux-amd64", "windows-amd64":
	default:
		return errors.New("unsupported Pack release platform")
	}
	id, err := artifactID(d)
	if err != nil || d.ArtifactID != id {
		return errors.New("Pack artifact identity mismatch")
	}
	return nil
}

// Build signs exact binary identity and the reviewed source/version tuple. A signer is
// responsible for reproducing those bytes; this function does not claim to inspect a binary.
func Build(binary io.Reader, platform, workerHostCommit, keyID string, key ed25519.PrivateKey) (Descriptor, error) {
	if !keyName.MatchString(keyID) || len(key) != ed25519.PrivateKeySize {
		return Descriptor{}, errors.New("invalid Pack release signing key")
	}
	file, err := executableDigest(binary)
	if err != nil {
		return Descriptor{}, err
	}
	d := Descriptor{SchemaVersion: 1, Domain: "pack", Action: "pack.evaluate_snapshot", Platform: platform, DenoVersion: "2.9.8", PackCoreVersion: "0.1.0", WorkerHostCommit: workerHostCommit, Executable: file}
	d.ArtifactID, err = artifactID(d)
	if err != nil {
		return Descriptor{}, err
	}
	if err := validate(d); err != nil {
		return Descriptor{}, err
	}
	m, err := unsigned(d)
	if err != nil {
		return Descriptor{}, err
	}
	b, err := runtimeartifact.CanonicalJSON(m)
	if err != nil {
		return Descriptor{}, err
	}
	d.Signature = Signature{Algorithm: "ed25519", KeyID: keyID, ValueBase64: base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))}
	return d, nil
}

// Verify checks release-owner pins before a bounded streaming digest. It never executes,
// installs or downloads the executable, nor accepts task-supplied trust material.
func Verify(data []byte, binary io.Reader, trust Trust) (Descriptor, error) {
	if len(data) == 0 || len(data) > MaxDescriptorBytes || !keyName.MatchString(trust.KeyID) || trust.ArtifactID == "" || trust.Platform == "" {
		return Descriptor{}, errors.New("Pack release trust and bounded descriptor required")
	}
	var d Descriptor
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Descriptor{}, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return Descriptor{}, errors.New("trailing Pack descriptor data")
	}
	if err := validate(d); err != nil {
		return Descriptor{}, err
	}
	if d.ArtifactID != trust.ArtifactID || d.Platform != trust.Platform {
		return Descriptor{}, errors.New("Pack release does not match reviewed selection")
	}
	if _, err := runtimeartifact.Verify(data, trust.KeyID, trust.PublicKeyPEM); err != nil {
		return Descriptor{}, err
	}
	file, err := executableDigest(binary)
	if err != nil {
		return Descriptor{}, err
	}
	if file != d.Executable {
		return Descriptor{}, errors.New("Pack executable hash/size mismatch")
	}
	return d, nil
}
