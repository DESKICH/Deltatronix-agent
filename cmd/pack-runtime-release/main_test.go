package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

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
func signAndVerify(t *testing.T, binary, dir string) (packruntime.Descriptor, string, string) {
	t.Helper()
	private, public := keys(t, dir)
	var out bytes.Buffer
	if err := run(context.Background(), []string{"sign", "--binary", binary, "--platform", runtime.GOOS + "-" + runtime.GOARCH, "--worker-host-commit", packruntime.PortableWorkerHostCommit, "--key-id", "ephemeral-local-test", "--private-key", private}, &out); err != nil {
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

	d, descriptor, public := signAndVerify(t, binary, t.TempDir())
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
