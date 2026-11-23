// pack-runtime-release is an offline release-review tool, not a companion task route.
// It deliberately has no network access, default signing key or daemon configuration.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/deltatronix/dtx-agent/internal/packruntime"
)

func regular(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("release input must be a regular file")
	}
	return os.Open(path)
}
func bounded(path string, limit int64) ([]byte, error) {
	f, err := regular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("release input exceeds limit")
	}
	return b, nil
}
func run(args []string, out io.Writer) error {
	if len(args) == 0 || (args[0] != "sign" && args[0] != "verify") {
		return errors.New("use sign or verify; see README offline Pack release review")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	binary := fs.String("binary", "", "exact locally built executable")
	platform := fs.String("platform", "", "reviewed platform, e.g. darwin-arm64")
	keyID := fs.String("key-id", "", "release-owner key ID")
	var private, source, descriptor, public, artifact *string
	if args[0] == "sign" {
		private = fs.String("private-key", "", "release-owner PKCS8 Ed25519 PEM file")
		source = fs.String("worker-host-commit", "", "reviewed full worker-host source commit")
	} else {
		descriptor = fs.String("descriptor", "", "signed descriptor file")
		public = fs.String("public-key", "", "independently reviewed Ed25519 PEM file")
		artifact = fs.String("artifact-id", "", "independently reviewed immutable selection")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *binary == "" || *platform == "" || *keyID == "" {
		return errors.New("explicit binary, platform and release-owner key ID required")
	}
	f, err := regular(*binary)
	if err != nil {
		return err
	}
	defer f.Close()
	if args[0] == "sign" {
		if *private == "" || *source == "" {
			return errors.New("explicit signing key and source commit required")
		}
		b, err := bounded(*private, 8192)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return errors.New("invalid release signing key PEM")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return errors.New("invalid release signing key")
		}
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return errors.New("release signing key must be Ed25519")
		}
		d, err := packruntime.Build(f, *platform, *source, *keyID, key)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(d)
	}
	if *descriptor == "" || *public == "" || *artifact == "" {
		return errors.New("descriptor and independently reviewed public key/artifact pins required")
	}
	data, err := bounded(*descriptor, packruntime.MaxDescriptorBytes)
	if err != nil {
		return err
	}
	key, err := bounded(*public, 8192)
	if err != nil {
		return err
	}
	d, err := packruntime.Verify(data, f, packruntime.Trust{KeyID: *keyID, PublicKeyPEM: string(key), ArtifactID: *artifact, Platform: *platform})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Verified %s under supplied offline release-review pins; companion trust/configuration unchanged.\n", d.ArtifactID)
	return err
}
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "pack-runtime-release:", err)
		os.Exit(1)
	}
}
