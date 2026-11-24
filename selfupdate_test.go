package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket/wsjson"
)

// fakeReleases serves GitHub's latest-release answer and one release's files.
func fakeReleases(t *testing.T, tag string, files map[string]string) (*httptest.Server, *[]string) {
	t.Helper()
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		if r.URL.Path == "/api/releases/latest" {
			fmt.Fprintf(w, `{"tag_name":%q}`, tag)
			return
		}
		body, ok := files[strings.TrimPrefix(r.URL.Path, "/download/"+tag+"/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func testUpdater(t *testing.T, srv *httptest.Server) (updater, string) {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "dtx-agent")
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	return updater{api: srv.URL + "/api", downloads: srv.URL + "/download", client: srv.Client(), exe: exe, asset: "dtx-agent-test", current: "0.1.4"}, exe
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func idle() (func(), bool) { return func() {}, true }

func TestNewerVersion(t *testing.T) {
	for _, c := range []struct {
		current, tag string
		want         bool
	}{
		{"0.1.4", "v0.1.5", true},
		{"0.1.4", "v0.2.0", true},
		{"0.1.9", "v0.1.10", true},
		{"0.1.4", "v0.1.4", false},
		{"0.1.5", "v0.1.4", false},
		{"1.0.0", "v0.9.9", false},
		{"0.1.4", "0.1.5", false},          // GitHub tags carry the v
		{"0.1.4", "v0.1.5-rc1", false},     // only plain releases
		{"0.1.4", "v0.1.5/../../x", false}, // the tag lands in a URL
	} {
		if got := newerVersion(c.current, c.tag); got != c.want {
			t.Errorf("newerVersion(%q, %q) = %v, want %v", c.current, c.tag, got, c.want)
		}
	}
}

func TestUpdateReplacesVerifiedBinaryAndRestarts(t *testing.T) {
	srv, _ := fakeReleases(t, "v0.1.5", map[string]string{
		"SHA256SUMS":     sum("new binary") + "  dtx-agent-test\n" + sum("other") + "  llm.txt\n",
		"dtx-agent-test": "new binary",
	})
	u, exe := testUpdater(t, srv)
	restarted := 0
	if err := u.updateOnce(context.Background(), idle, func(got string) error {
		if got != exe {
			t.Errorf("restarted %q, want the installed %q", got, exe)
		}
		restarted++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, exe); got != "new binary" || restarted != 1 {
		t.Fatalf("exe = %q, restarts = %d", got, restarted)
	}
	if info, _ := os.Stat(exe); info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("replaced binary is not executable: %v", info.Mode())
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), "*")); len(left) != 1 {
		t.Fatalf("staging files left behind: %v", left)
	}
}

func TestUpdateRefusesUnverifiedDownloads(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"checksum mismatch": {"SHA256SUMS": sum("new binary") + "  dtx-agent-test\n", "dtx-agent-test": "tampered binary"},
		"no checksum file":  {"dtx-agent-test": "new binary"},
		"asset not listed":  {"SHA256SUMS": sum("new binary") + "  dtx-agent-other\n", "dtx-agent-test": "new binary"},
		"malformed sum":     {"SHA256SUMS": "nothex  dtx-agent-test\n", "dtx-agent-test": "new binary"},
		"no asset":          {"SHA256SUMS": sum("new binary") + "  dtx-agent-test\n"},
	} {
		t.Run(name, func(t *testing.T) {
			srv, _ := fakeReleases(t, "v0.1.5", files)
			u, exe := testUpdater(t, srv)
			err := u.updateOnce(context.Background(), idle, func(string) error { t.Fatal("restarted on an unverified download"); return nil })
			if err == nil {
				t.Fatal("unverified update succeeded")
			}
			if got := readFile(t, exe); got != "old binary" {
				t.Fatalf("exe replaced with %q", got)
			}
			if left, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), "*")); len(left) != 1 {
				t.Fatalf("staging files left behind: %v", left)
			}
		})
	}
}

func TestUpdateSkipsWhenNotNewer(t *testing.T) {
	srv, hits := fakeReleases(t, "v0.1.4", map[string]string{"SHA256SUMS": "", "dtx-agent-test": "new binary"})
	u, exe := testUpdater(t, srv)
	if err := u.updateOnce(context.Background(), idle, func(string) error { t.Fatal("restarted"); return nil }); err != nil {
		t.Fatal(err)
	}
	if readFile(t, exe) != "old binary" || len(*hits) != 1 {
		t.Fatalf("downloaded for the current version: %v", *hits)
	}
}

func TestUpdateWaitsForIdleBeforeReplacing(t *testing.T) {
	srv, _ := fakeReleases(t, "v0.1.5", map[string]string{
		"SHA256SUMS":     sum("new binary") + "  dtx-agent-test\n",
		"dtx-agent-test": "new binary",
	})
	u, exe := testUpdater(t, srv)
	defer func(d time.Duration) { idlePollEvery = d }(idlePollEvery)
	idlePollEvery = time.Millisecond
	busyChecks := 0
	claim := func() (func(), bool) {
		if busyChecks < 3 {
			busyChecks++
			if readFile(t, exe) != "old binary" {
				t.Fatal("replaced mid-job")
			}
			return nil, false
		}
		return func() {}, true
	}
	if err := u.updateOnce(context.Background(), claim, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if busyChecks != 3 || readFile(t, exe) != "new binary" {
		t.Fatalf("busy checks %d, exe %q", busyChecks, readFile(t, exe))
	}

	// A job that never ends: the update gives up with the process, unreplaced.
	u, exe = testUpdater(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := u.updateOnce(ctx, func() (func(), bool) { return nil, false }, func(string) error { t.Fatal("restarted"); return nil })
	if !errors.Is(err, context.DeadlineExceeded) || readFile(t, exe) != "old binary" {
		t.Fatalf("err %v, exe %q", err, readFile(t, exe))
	}
}

func TestFailedRestartReleasesTheJobSlot(t *testing.T) {
	srv, _ := fakeReleases(t, "v0.1.5", map[string]string{
		"SHA256SUMS":     sum("new binary") + "  dtx-agent-test\n",
		"dtx-agent-test": "new binary",
	})
	u, _ := testUpdater(t, srv)
	released := false
	err := u.updateOnce(context.Background(), func() (func(), bool) { return func() { released = true }, true }, func(string) error { return errors.New("exec failed") })
	if err == nil || !released {
		t.Fatalf("err %v, released %v", err, released)
	}
}

func TestClaimIdleJobSlot(t *testing.T) {
	jobSlot.Lock()
	jobSlot.a = nil
	jobSlot.Unlock()
	release, ok := claimIdleJobSlot()
	if !ok {
		t.Fatal("no connection: the slot should be free")
	}
	release()

	a := &agent{jobs: map[string]context.CancelFunc{}}
	jobSlot.Lock()
	jobSlot.a = a
	jobSlot.Unlock()
	defer func() { jobSlot.Lock(); jobSlot.a = nil; jobSlot.Unlock() }()

	a.busy = true
	if _, ok := claimIdleJobSlot(); ok {
		t.Fatal("claimed the slot mid-job")
	}
	a.busy = false
	release, ok = claimIdleJobSlot()
	if !ok || !a.busy {
		t.Fatalf("idle claim ok=%v busy=%v: a job could start during the restart", ok, a.busy)
	}
	release()
	if a.busy {
		t.Fatal("release left the slot taken")
	}
}

func TestReleaseAssetName(t *testing.T) {
	got := releaseAsset("linux", "arm64", false)
	if got != "dtx-agent-linux-arm64-headless" {
		t.Fatal(got)
	}
	if got := releaseAsset("windows", "arm64", true); got != "dtx-agent-windows-arm64.exe" {
		t.Fatal(got)
	}
	if got := releaseAsset("darwin", "arm64", true); got != "dtx-agent-darwin-arm64" {
		t.Fatal(got)
	}
}

func TestReplaceExecutableOnWindowsMovesTheRunningFileAside(t *testing.T) {
	dir := t.TempDir()
	exe, staged := filepath.Join(dir, "dtx-agent.exe"), filepath.Join(dir, "staged")
	os.WriteFile(exe, []byte("old"), 0o755)
	os.WriteFile(exe+".old", []byte("older"), 0o755)
	os.WriteFile(staged, []byte("new"), 0o755)
	if err := replaceExecutable("windows", exe, staged); err != nil {
		t.Fatal(err)
	}
	if readFile(t, exe) != "new" || readFile(t, exe+".old") != "old" {
		t.Fatalf("exe %q, old %q", readFile(t, exe), readFile(t, exe+".old"))
	}
}

// A live connection's running job holds the slot; a claimed slot refuses jobs.
func TestPairedJobHoldsTheUpdateSlot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	model, started, stopped := blockingChatModel(t)
	conn := connectPairedChat(t, ctx, model.URL+"/v1", "fixture-chat:7b", 8192).Conn
	readComputeReply(t, ctx, conn)
	writeChatFixtureJob(t, ctx, conn, "slot-job")
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("local chat request did not start")
	}
	if _, ok := claimIdleJobSlot(); ok {
		t.Fatal("update claimed the slot mid-job")
	}
	if err := wsjson.Write(ctx, conn, map[string]any{"type": "job.cancel", "jobId": "slot-job"}); err != nil {
		t.Fatal(err)
	}
	<-stopped
	readChatResult(t, ctx, conn, "slot-job")

	release, ok := claimIdleJobSlot()
	if !ok {
		t.Fatal("idle connection refused the update")
	}
	writeChatFixtureJob(t, ctx, conn, "during-restart")
	if reply := readChatResult(t, ctx, conn, "during-restart"); reply.OK || reply.Error != "agent busy: one job at a time" {
		t.Fatalf("a job started while the update held the slot: %+v", reply)
	}
	release()
}
