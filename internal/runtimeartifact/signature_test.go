package runtimeartifact

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func TestCanonicalRepresentationPreservesNativeSigningRules(t *testing.T) {
	b, err := CanonicalJSON(map[string]any{"z": json.Number("9007199254740993"), "a": map[string]any{"text": "<>&π"}})
	if err != nil || string(b) != `{"a":{"text":"<>&π"},"z":9007199254740993}` {
		t.Fatalf("native signing preimage changed: %s %v", b, err)
	}
}
func TestSignatureUsesOwnerKeyAndOriginalNumericPrecision(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	public := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	m := map[string]any{"exact": json.Number("9007199254740993"), "scope": "<pack>"}
	signed, err := CanonicalJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	m["signature"] = map[string]any{"keyId": "fixture-owner", "algorithm": "ed25519", "valueBase64": base64.StdEncoding.EncodeToString(ed25519.Sign(key, signed))}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(data, "fixture-owner", public)
	if err != nil || got["exact"] != json.Number("9007199254740993") {
		t.Fatalf("valid owner signature refused: %v", err)
	}
	for _, p := range []struct{ id, key string }{{"other", public}, {"fixture-owner", "malformed PEM"}} {
		if _, err := Verify(data, p.id, p.key); err == nil {
			t.Fatal("untrusted owner accepted")
		}
	}
	altered := []byte(strings.Replace(string(data), "9007199254740993", "9007199254740992", 1))
	if _, err := Verify(altered, "fixture-owner", public); err == nil {
		t.Fatal("changed number accepted")
	}
}
