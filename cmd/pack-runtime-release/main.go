// pack-runtime-release is an offline release-review tool, not a companion task route.
// It has no downloader, default signing key or daemon configuration. The optional
// fixture runner executes only an independently verified local portable worker.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/deltatronix/dtx-agent/internal/packruntime"
)

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || (args[0] != "sign" && args[0] != "verify" && args[0] != "run-fixture" && args[0] != "run-assignment") {
		return errors.New("use sign, verify, run-fixture or run-assignment; see README offline Pack release review")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	binary := fs.String("binary", "", "exact locally built executable")
	platform := fs.String("platform", "", "reviewed platform, e.g. darwin-arm64")
	keyID := fs.String("key-id", "", "release-owner key ID")
	var private, source, coreVersion, descriptor, public, artifact, input, principal, approval *string
	if args[0] == "sign" {
		private = fs.String("private-key", "", "release-owner PKCS8 Ed25519 PEM file")
		source = fs.String("worker-host-commit", "", "reviewed full worker-host source commit")
		coreVersion = fs.String("pack-core-version", packruntime.LegacyPackCoreVersion, "reviewed Pack core version in the compiled worker")
	} else {
		descriptor = fs.String("descriptor", "", "signed descriptor file")
		public = fs.String("public-key", "", "independently reviewed Ed25519 PEM file")
		artifact = fs.String("artifact-id", "", "independently reviewed immutable selection")
	}
	if args[0] == "run-fixture" || args[0] == "run-assignment" {
		input = fs.String("input-directory", "", "trusted asset-free scope/task/snapshot fixture directory")
		principal = fs.String("principal", "", "independent local fixture caller: user:<id> or company:<id>")
	}
	if args[0] == "run-assignment" {
		approval = fs.String("approval", "", "independently approved local current fence/input JSON; not queued metadata")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *binary == "" || *platform == "" || *keyID == "" {
		return errors.New("explicit binary, platform and release-owner key ID required")
	}
	if coreVersion != nil && !packruntime.SupportsPackCoreVersion(*coreVersion) {
		return errors.New("unsupported Pack core version")
	}
	var f *os.File
	var err error
	if args[0] != "run-fixture" && args[0] != "run-assignment" {
		f, err = packruntime.RegularFile(*binary)
		if err != nil {
			return err
		}
		defer f.Close()
	}

	if args[0] == "sign" {
		if *private == "" || *source == "" {
			return errors.New("explicit signing key and source commit required")
		}
		b, err := packruntime.ReadRegularFile(*private, 8192)
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
		d, err := packruntime.Build(f, *platform, *source, *coreVersion, *keyID, key)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(d)
	}
	if *descriptor == "" || *public == "" || *artifact == "" {
		return errors.New("descriptor and independently reviewed public key/artifact pins required")
	}
	data, err := packruntime.ReadRegularFile(*descriptor, packruntime.MaxDescriptorBytes)
	if err != nil {
		return err
	}
	key, err := packruntime.ReadRegularFile(*public, 8192)
	if err != nil {
		return err
	}
	trust := packruntime.Trust{KeyID: *keyID, PublicKeyPEM: string(key), ArtifactID: *artifact, Platform: *platform}
	if args[0] == "run-fixture" || args[0] == "run-assignment" {
		if *input == "" || *principal == "" {
			return errors.New("explicit trusted fixture directory and independent caller required")
		}
		kind, id, ok := strings.Cut(*principal, ":")
		if !ok {
			return errors.New("invalid local fixture caller")
		}
		var result json.RawMessage
		if args[0] == "run-assignment" {
			if approval == nil || *approval == "" {
				return errors.New("independent local assignment approval required")
			}
			approvalJSON, readErr := packruntime.ReadRegularFile(*approval, 64<<10)
			if readErr != nil {
				return readErr
			}
			var pins packruntime.AssignmentApproval
			dec := json.NewDecoder(bytes.NewReader(approvalJSON))
			dec.DisallowUnknownFields()
			if dec.Decode(&pins) != nil || dec.Decode(new(any)) != io.EOF {
				return errors.New("invalid independent local assignment approval")
			}
			var required struct {
				Input struct {
					Version *int64 `json:"version"`
				} `json:"input"`
			}
			if json.Unmarshal(approvalJSON, &required) != nil || required.Input.Version == nil {
				return errors.New("approval requires explicit saved numeric version")
			}
			result, err = packruntime.RunAssignment(ctx, data, *binary, *input, packruntime.Principal{Kind: kind, ID: id}, pins, trust)
		} else {
			result, err = packruntime.RunFixture(ctx, data, *binary, *input, packruntime.Principal{Kind: kind, ID: id}, trust)
		}
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(result))
		return err
	}
	d, err := packruntime.Verify(data, f, trust)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Verified %s under supplied offline release-review pins; companion trust/configuration unchanged.\n", d.ArtifactID)
	return err
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "pack-runtime-release:", err)
		os.Exit(1)
	}
}
