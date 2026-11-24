package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The companion updates itself from this repository's GitHub Releases. Releases
// are not code-signed yet, so the only check is the SHA-256 the release workflow
// publishes in SHA256SUMS: it proves the download is the file the workflow
// built, not who built it. A release without that file, or a file that does not
// match it, is never installed.
const (
	releaseRepo  = "Deltatronix/Deltatronix-agent"
	noUpdateEnv  = "DTX_AGENT_NO_UPDATE"
	maxAssetSize = 256 << 20
)

// Vars so a test can tick quickly.
var (
	updateCheckEvery = 6 * time.Hour
	idlePollEvery    = 30 * time.Second
)

var releaseTag = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

type updater struct {
	api, downloads string // GitHub's repo API base and release download base
	client         *http.Client
	exe            string // the running binary, replaced in place
	asset          string // this build's file in a release
	current        string // version.go's version
}

// releaseAsset names this build's file, as the release workflow publishes it.
func releaseAsset(goos, goarch string, gui bool) string {
	name := "dtx-agent-" + goos + "-" + goarch
	if !gui {
		name += "-headless"
	}
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// newerVersion reports whether a plain release tag (vX.Y.Z) is newer than current.
func newerVersion(current, tag string) bool {
	next := releaseTag.FindStringSubmatch(tag)
	have := releaseTag.FindStringSubmatch("v" + current)
	if next == nil || have == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		n, _ := strconv.Atoi(next[i])
		h, _ := strconv.Atoi(have[i])
		if n != h {
			return n > h
		}
	}
	return false
}

// autoUpdate checks for a newer release at start and every updateCheckEvery,
// and installs it when no job is running. Any failure keeps this version running.
// restart gets the installed binary's path: it is resolved before the swap,
// because Windows may report the running image under its moved-aside name.
func autoUpdate(ctx context.Context, restart func(exe string) error) {
	if v := os.Getenv(noUpdateEnv); v != "" && v != "0" {
		log.Printf("auto-update: off (%s)", noUpdateEnv)
		return
	}
	exe, err := selfPath()
	if err != nil {
		log.Printf("auto-update: off, cannot locate this binary: %v", err)
		return
	}
	_ = os.Remove(exe + ".old") // the binary a Windows update moved aside
	u := updater{
		api:       "https://api.github.com/repos/" + releaseRepo,
		downloads: "https://github.com/" + releaseRepo + "/releases/download",
		client:    &http.Client{Timeout: 10 * time.Minute},
		exe:       exe,
		asset:     releaseAsset(runtime.GOOS, runtime.GOARCH, guiBuild),
		current:   version,
	}
	log.Printf("auto-update: on for %s %s (turn off with --no-update or %s=1)", u.asset, version, noUpdateEnv)
	for {
		if err := u.updateOnce(ctx, claimIdleJobSlot, restart); err != nil && ctx.Err() == nil {
			log.Printf("auto-update: %v; still running %s", err, version)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(updateCheckEvery):
		}
	}
}

// updateOnce installs the latest release if it is newer: download and verify
// first, then wait for an idle job slot, swap the binary and restart.
func (u updater) updateOnce(ctx context.Context, claim func() (func(), bool), restart func(exe string) error) error {
	tag, err := u.latestTag(ctx)
	if err != nil || !newerVersion(u.current, tag) {
		return err
	}
	staged, err := u.stage(ctx, tag)
	if err != nil {
		return err
	}
	defer os.Remove(staged) // gone once renamed into place
	var release func()
	for {
		var idle bool
		if release, idle = claim(); idle {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(idlePollEvery):
		}
	}
	log.Printf("auto-update: installing dtx-agent %s (was %s) and restarting", tag, u.current)
	if err := replaceExecutable(runtime.GOOS, u.exe, staged); err != nil {
		release()
		return fmt.Errorf("installing %s: %w", tag, err)
	}
	if err := restart(u.exe); err != nil {
		release()
		return fmt.Errorf("installed %s, but restarting failed (it starts next launch): %w", tag, err)
	}
	return nil
}

func (u updater) get(ctx context.Context, url string, limit int64) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dtx-agent/"+u.current)
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(resp.Body, limit), resp.Body}, nil
}

// latestTag is GitHub's newest published release (never a draft or prerelease).
func (u updater) latestTag(ctx context.Context) (string, error) {
	body, err := u.get(ctx, u.api+"/releases/latest", 1<<20)
	if err != nil {
		return "", err
	}
	defer body.Close()
	var latest struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(body).Decode(&latest); err != nil {
		return "", fmt.Errorf("reading the latest release: %w", err)
	}
	return latest.TagName, nil
}

// stage downloads this build's asset of tag next to the binary and returns its
// path only if it matches the release's published SHA-256.
func (u updater) stage(ctx context.Context, tag string) (string, error) {
	want, err := u.publishedSum(ctx, tag)
	if err != nil {
		return "", err
	}
	body, err := u.get(ctx, u.downloads+"/"+tag+"/"+u.asset, maxAssetSize+1)
	if err != nil {
		return "", err
	}
	defer body.Close()
	// Same directory, so the swap is a rename on one filesystem.
	f, err := os.CreateTemp(filepath.Dir(u.exe), ".dtx-agent-update-*")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), body)
	if err == nil && n > maxAssetSize {
		err = fmt.Errorf("%s is larger than %d bytes", u.asset, maxAssetSize)
	}
	if err == nil && hex.EncodeToString(h.Sum(nil)) != want {
		err = fmt.Errorf("%s %s does not match its published SHA-256; not installing it", u.asset, tag)
	}
	if err == nil {
		err = f.Chmod(0o755)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// publishedSum reads this asset's line of the release's SHA256SUMS
// (`sha256sum` output: "<hex>  <name>").
func (u updater) publishedSum(ctx context.Context, tag string) (string, error) {
	body, err := u.get(ctx, u.downloads+"/"+tag+"/SHA256SUMS", 64<<10)
	if err != nil {
		return "", fmt.Errorf("release %s has no readable SHA256SUMS, so it cannot be verified: %w", tag, err)
	}
	defer body.Close()
	lines := bufio.NewScanner(body)
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == u.asset {
			if b, err := hex.DecodeString(fields[0]); err != nil || len(b) != sha256.Size {
				return "", fmt.Errorf("release %s lists a malformed SHA-256 for %s", tag, u.asset)
			}
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("release %s publishes no SHA-256 for %s", tag, u.asset)
}

// replaceExecutable swaps staged into exe's place. A rename is atomic on Unix;
// Windows will not replace a running .exe but lets it be renamed aside, so the
// old binary moves to exe.old (removed at the next start) and comes back if
// the swap fails.
func replaceExecutable(goos, exe, staged string) error {
	if goos != "windows" {
		return os.Rename(staged, exe)
	}
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.Rename(staged, exe); err != nil {
		_ = os.Rename(old, exe)
		return err
	}
	return nil
}

// startSelf launches a fresh copy of exe with this run's arguments.
func startSelf(exe string) error { return exec.Command(exe, os.Args[1:]...).Start() }

// restartHeadless replaces this process with the installed binary, keeping its
// PID so systemd and terminals see the same process. Windows has no exec, so it
// starts a new copy and exits.
func restartHeadless(exe string) error {
	if runtime.GOOS == "windows" {
		if err := startSelf(exe); err != nil {
			return err
		}
		os.Exit(0)
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}

// jobSlot names the live connection, whose one-job-at-a-time slot an update
// takes so no job starts while the binary is swapped and the process restarts.
var jobSlot struct {
	sync.Mutex
	a *agent
}

// claimIdleJobSlot takes the job slot if no job is running. The caller holds it
// until release, or for good once the process restarts.
func claimIdleJobSlot() (release func(), ok bool) {
	jobSlot.Lock()
	a := jobSlot.a
	if a != nil {
		a.mu.Lock()
		if a.busy {
			a.mu.Unlock()
			jobSlot.Unlock()
			return nil, false
		}
		a.busy = true
		a.mu.Unlock()
	}
	return func() {
		if a != nil {
			a.mu.Lock()
			a.busy = false
			a.mu.Unlock()
		}
		jobSlot.Unlock()
	}, true
}
