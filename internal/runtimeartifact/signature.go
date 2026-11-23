// Package runtimeartifact owns the existing native release signing representation.
package runtimeartifact

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
)

// CanonicalJSON sorts map keys recursively without HTML escaping, matching the release signer.
func CanonicalJSON(v any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), nil
}

// Verify uses only the caller's trusted release key, never a key from the manifest.
func Verify(data []byte, keyID, publicKeyPEM string) (map[string]any, error) {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	signatureObject, ok := m["signature"].(map[string]any)
	if !ok || signatureObject["keyId"] != keyID || signatureObject["algorithm"] != "ed25519" {
		return nil, errors.New("unknown native release key or signature")
	}
	signature, ok := signatureObject["valueBase64"].(string)
	if !ok {
		return nil, errors.New("missing native release signature")
	}
	delete(m, "signature")
	signed, err := CanonicalJSON(m)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("invalid native release key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(publicKey, signed, sig) {
		return nil, errors.New("invalid native runtime signature")
	}
	return m, nil
}
