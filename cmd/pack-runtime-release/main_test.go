package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
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
func signAndVerify(t *testing.T, binary, dir string) packruntime.Descriptor {
	t.Helper()
	private, public := keys(t, dir)
	var out bytes.Buffer
	if err := run([]string{"sign", "--binary", binary, "--platform", "darwin-arm64", "--worker-host-commit", "b143bc8b21789d34ff5f18723449781af37a8128", "--key-id", "ephemeral-local-test", "--private-key", private}, &out); err != nil {
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
	verify := []string{"verify", "--binary", binary, "--descriptor", descriptor, "--platform", "darwin-arm64", "--key-id", "ephemeral-local-test", "--public-key", public, "--artifact-id", d.ArtifactID}
	if err := run(verify, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "companion trust/configuration unchanged") {
		t.Fatal("verification overstated")
	}
	for _, args := range [][]string{verify[:len(verify)-2], append(append([]string{}, verify...), "--url=https://untrusted.test"), append(append([]string{}, verify...), "extra")} {
		if err := run(args, &out); err == nil {
			t.Fatal("unreviewed controls/selection accepted")
		}
	}
	return d
}
func TestOfflineReleaseToolSignsAndVerifies(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "pack-readonly")
	if err := os.WriteFile(binary, []byte("local fixture, not executed"), 0600); err != nil {
		t.Fatal(err)
	}
	signAndVerify(t, binary, dir)
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
		if _, err := regular(path); err == nil {
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
	d := signAndVerify(t, binary, t.TempDir())
	if d.Executable.Size < 1<<20 {
		t.Fatal("expected actual Deno compiled runtime, not script fixture")
	}
	snapshot := filepath.Join(root, "snapshot.json")
	before, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "--root="+root, "--principal=user:caller-a")
	command.Env = []string{"PATH=" + os.Getenv("PATH")}
	data, err := command.Output()
	if err != nil {
		t.Fatalf("actual Pack worker: %v", err)
	}
	var result struct {
		Status      string `json:"status"`
		Checkpoints []struct {
			Receipts []struct {
				Status string `json:"status"`
			} `json:"receipts"`
		} `json:"checkpoints"`
		ReadinessReport json.RawMessage `json:"readinessReport"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "waiting_for_input" || len(result.Checkpoints) != 1 || len(result.Checkpoints[0].Receipts) != 1 || result.Checkpoints[0].Receipts[0].Status != "readOnly" || len(result.ReadinessReport) != 0 {
		t.Fatal("actual worker did not return only a read-only evaluation receipt")
	}
	after, err := os.ReadFile(snapshot)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("saved fixture changed")
	}
	t.Logf("Actual compiled UI #157 binary signed/verified with ephemeral local key: %s (%d bytes); read-only receipt; input unchanged", d.ArtifactID, d.Executable.Size)
}
