package packruntime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"strings"
	"testing"
)

func fixture(t *testing.T) (Descriptor, Trust, []byte, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binary := []byte("local executable fixture, not a production runtime")
	d, err := Build(bytes.NewReader(binary), "darwin-arm64", strings.Repeat("a", 40), LegacyPackCoreVersion, "local-test", key)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return d, Trust{KeyID: "local-test", PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), ArtifactID: d.ArtifactID, Platform: d.Platform}, binary, key
}
func encoded(t *testing.T, d Descriptor) []byte {
	t.Helper()
	b, e := json.Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestSignedDescriptorBindsExactBytesAndScopedTuple(t *testing.T) {
	d, trust, binary, _ := fixture(t)
	got, err := Verify(encoded(t, d), bytes.NewReader(binary), trust)
	if err != nil || got != d {
		t.Fatalf("verify: %v", err)
	}
	for name, change := range map[string]func(*Descriptor){
		"domain":          func(d *Descriptor) { d.Domain = "shape" },
		"action":          func(d *Descriptor) { d.Action = "pack.save" },
		"core":            func(d *Descriptor) { d.PackCoreVersion = "0.2.0" },
		"deno":            func(d *Descriptor) { d.DenoVersion = "2.9.9" },
		"source":          func(d *Descriptor) { d.WorkerHostCommit = strings.Repeat("b", 40) },
		"executable path": func(d *Descriptor) { d.Executable.Name = "../pack-readonly" },
		"platform":        func(d *Descriptor) { d.Platform = "linux-amd64" },
		"hash":            func(d *Descriptor) { d.Executable.SHA256 = strings.Repeat("b", 64) },
		"size":            func(d *Descriptor) { d.Executable.Size++ },
		"artifact":        func(d *Descriptor) { d.ArtifactID = "other" },
		"signer":          func(d *Descriptor) { d.Signature.KeyID = "unreviewed" },
		"algorithm":       func(d *Descriptor) { d.Signature.Algorithm = "none" },
		"signature":       func(d *Descriptor) { d.Signature.ValueBase64 = "AAAA" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := d
			change(&changed)
			if _, err := Verify(encoded(t, changed), bytes.NewReader(binary), trust); err == nil {
				t.Fatal("changed descriptor accepted")
			}
		})
	}
	for _, changed := range [][]byte{append(append([]byte{}, binary...), 0), binary[:len(binary)-1], bytes.Repeat([]byte{'x'}, len(binary))} {
		if _, err := Verify(encoded(t, d), bytes.NewReader(changed), trust); err == nil {
			t.Fatal("changed binary accepted")
		}
	}
}
func TestArtifactIdentityIncludesSourceAndPlatform(t *testing.T) {
	d, _, binary, key := fixture(t)
	for _, input := range [][2]string{{"linux-amd64", strings.Repeat("a", 40)}, {"darwin-arm64", strings.Repeat("b", 40)}} {
		other, err := Build(bytes.NewReader(binary), input[0], input[1], LegacyPackCoreVersion, "local-test", key)
		if err != nil || other.ArtifactID == d.ArtifactID {
			t.Fatalf("identity not scoped: %v", err)
		}
	}
}

func TestNewPackCoreVersionBindsExactArtifactSelection(t *testing.T) {
	legacy, trust, binary, key := fixture(t)
	next, err := Build(bytes.NewReader(binary), legacy.Platform, legacy.WorkerHostCommit, "0.1.1", trust.KeyID, key)
	if err != nil || next.ArtifactID == legacy.ArtifactID || next.PackCoreVersion != "0.1.1" {
		t.Fatalf("new release did not bind its version: %v", err)
	}
	if _, err := Verify(encoded(t, next), unreadable{t}, trust); err == nil {
		t.Fatal("new core accepted under legacy artifact approval")
	}
	trust.ArtifactID = next.ArtifactID
	got, err := Verify(encoded(t, next), bytes.NewReader(binary), trust)
	if err != nil || got != next {
		t.Fatalf("new signed release did not verify: %v", err)
	}
	if _, err := Verify(encoded(t, next), strings.NewReader("changed binary"), trust); err == nil {
		t.Fatal("new release accepted a changed executable")
	}
	next.Signature.ValueBase64 = legacy.Signature.ValueBase64
	if _, err := Verify(encoded(t, next), unreadable{t}, trust); err == nil {
		t.Fatal("new release accepted a legacy signature")
	}
	for _, version := range []string{"", "0.1.2", "0.2.0", "latest"} {
		if _, err := Build(unreadable{t}, legacy.Platform, legacy.WorkerHostCommit, version, trust.KeyID, key); err == nil {
			t.Fatalf("built unsupported core %q", version)
		}
	}
}

type unreadable struct{ t *testing.T }

func (r unreadable) Read([]byte) (int, error) {
	r.t.Fatal("read binary before authenticating selection")
	return 0, io.EOF
}
func TestSelectionAndSignatureRefuseBeforeReadingExecutable(t *testing.T) {
	d, trust, _, _ := fixture(t)
	for name, change := range map[string]func(*Trust){
		"missing selection": func(p *Trust) { p.ArtifactID = "" },
		"wrong selection":   func(p *Trust) { p.ArtifactID = "other" },
		"wrong platform":    func(p *Trust) { p.Platform = "linux-arm64" },
		"wrong key ID":      func(p *Trust) { p.KeyID = "other" },
		"malformed key":     func(p *Trust) { p.PublicKeyPEM = "not a key" },
		"other trusted key": func(p *Trust) { _, other, _, _ := fixture(t); p.PublicKeyPEM = other.PublicKeyPEM },
	} {
		t.Run(name, func(t *testing.T) {
			p := trust
			change(&p)
			if _, err := Verify(encoded(t, d), unreadable{t}, p); err == nil {
				t.Fatal("untrusted release accepted")
			}
		})
	}
}
func TestStrictDescriptorHasNoTransferOrExecutionControls(t *testing.T) {
	d, trust, _, _ := fixture(t)
	base := encoded(t, d)
	for _, data := range [][]byte{append(append([]byte{}, base...), []byte(` {}`)...), bytes.Replace(base, []byte(`"schemaVersion":1`), []byte(`"url":"https://untrusted.test","schemaVersion":1`), 1), bytes.Repeat([]byte{'x'}, MaxDescriptorBytes+1)} {
		if _, err := Verify(data, unreadable{t}, trust); err == nil {
			t.Fatal("extra execution controls or unbounded/trailing JSON accepted")
		}
	}
}
func TestBuildBoundsAndRejectsUnsupportedSource(t *testing.T) {
	_, _, _, key := fixture(t)
	for _, input := range []struct {
		binary           io.Reader
		platform, source string
	}{
		{bytes.NewReader(nil), "darwin-arm64", strings.Repeat("a", 40)},
		{io.LimitReader(zeroReader{}, MaxExecutableBytes+1), "darwin-arm64", strings.Repeat("a", 40)},
		{strings.NewReader("x"), "unsupported", strings.Repeat("a", 40)},
		{strings.NewReader("x"), "darwin-arm64", "branch-main"},
	} {
		if _, err := Build(input.binary, input.platform, input.source, LegacyPackCoreVersion, "local-test", key); err == nil {
			t.Fatal("invalid release input accepted")
		}
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
