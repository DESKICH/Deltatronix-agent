package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/deltatronix/dtx-agent/internal/runtimeartifact"
)

const nativeReleasePublicKey = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAU4pbMm0KUIuKkVLCERYuit0E2SfeDP+vou0VJNkWfFY=\n-----END PUBLIC KEY-----\n"
const nativeReleaseKeyID = "shape-native-release-2026-11"

func hashNative(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

// Shared signing representation; release keys remain scoped to their domain owner.
func canonicalNativeJSON(v any) ([]byte, error) { return runtimeartifact.CanonicalJSON(v) }

func verifyNativeManifest(data []byte) (map[string]any, error) {
	return runtimeartifact.Verify(data, nativeReleaseKeyID, nativeReleasePublicKey)
}

func nativeFetch(ctx context.Context, target, token string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("too many redirects")
		}
		req.Header.Del("Authorization")
		if req.URL.Scheme != "https" {
			return errors.New("insecure artifact redirect")
		}
		return nil
	}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("native download status %d", resp.StatusCode)
	}
	if resp.ContentLength > max {
		return nil, errors.New("native download exceeds limit")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("native download exceeds limit")
	}
	return data, nil
}

func nativeAPIURL(cfg Config, path string) string { return strings.TrimRight(cfg.APIURL, "/") + path }

func unpackNativeArchive(data []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, 256<<20))
	total := int64(0)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(h.Name, "./")
		if name == "" || filepath.IsAbs(name) || strings.Contains(name, "\\") || filepath.Clean(name) != name || strings.HasPrefix(name, "../") {
			return errors.New("unsafe native archive path")
		}
		if h.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(filepath.Join(dest, name), 0755); err != nil {
				return err
			}
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return errors.New("native archive contains nonregular entry")
		}
		total += h.Size
		if h.Size < 0 || total > 256<<20 {
			return errors.New("native archive exceeds limit")
		}
		if name != "shape-native" && name != "replicad_single.wasm" && !strings.HasPrefix(name, "LICENSES/") && name != "NOTICE" && name != "provenance.json" {
			return fmt.Errorf("unexpected native archive entry %s", name)
		}
		path := filepath.Join(dest, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if name == "shape-native" {
			mode = 0755
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(f, tr, h.Size)
		closeErr := f.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return err
		}
	}
	for _, name := range []string{"shape-native", "replicad_single.wasm"} {
		info, err := os.Stat(filepath.Join(dest, name))
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("native archive missing %s", name)
		}
	}
	return nil
}
