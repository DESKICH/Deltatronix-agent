package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/deltatronix/dtx-agent/internal/packruntime"
)

func approvedPackRunner(t *testing.T) (Config, packRunnerConfig) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DTX_AGENT_CONFIG_DIR", dir)
	cfg := Config{APIURL: "https://example.invalid", AgentID: "paired-fixture", AgentToken: "synthetic"}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binary := []byte("synthetic signed runtime; not executable or production trust")
	descriptor, err := packruntime.Build(bytes.NewReader(binary), runtime.GOOS+"-"+runtime.GOARCH, strings.Repeat("a", 40), "fixture", private)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	approval := packRunnerConfig{cfg.APIURL, cfg.AgentID, []string{"project-a"}, filepath.Join(dir, "worker"), filepath.Join(dir, "descriptor.json"), filepath.Join(dir, "public.pem"), "fixture", descriptor.ArtifactID}
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{approval.Binary: binary, approval.Descriptor: encoded, approval.PublicKey: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writePackApproval(t, approval)
	return cfg, approval
}
func writePackApproval(t *testing.T, approval packRunnerConfig) {
	t.Helper()
	dir, err := agentConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(approval)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "pack-runner.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestPackRegistrationRequiresIndependentApprovalAndVerifiedBytes(t *testing.T) {
	cfg, approval := approvedPackRunner(t)
	registration, err := loadPackRegistration(cfg)
	if err != nil || registration == nil || registration.Runtime.Version != "2.9.8" {
		t.Fatalf("verified registration: %v", err)
	}
	for name, change := range map[string]func(*packRunnerConfig){"pairing": func(c *packRunnerConfig) { c.AgentID = "foreign" }, "api": func(c *packRunnerConfig) { c.APIURL = "https://foreign.invalid" }, "projects": func(c *packRunnerConfig) { c.ProjectIDs = []string{"project-a", "project-a"} }, "pin": func(c *packRunnerConfig) { c.ArtifactID = "unapproved" }, "signer": func(c *packRunnerConfig) { c.KeyID = "unapproved" }, "relative": func(c *packRunnerConfig) { c.Binary = "worker" }} {
		t.Run(name, func(t *testing.T) {
			bad := approval
			change(&bad)
			writePackApproval(t, bad)
			if _, err := loadPackRegistration(cfg); err == nil {
				t.Fatal("unapproved registration accepted")
			}
		})
	}
	writePackApproval(t, approval)
	if err := os.WriteFile(approval.Binary, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPackRegistration(cfg); err == nil {
		t.Fatal("tampered executable accepted")
	}
	dir, _ := agentConfigDir()
	if err := os.Remove(filepath.Join(dir, "pack-runner.json")); err != nil {
		t.Fatal(err)
	}
	if got, err := loadPackRegistration(cfg); err != nil || got != nil {
		t.Fatal("legacy profile must remain disabled")
	}
}
func TestPackRegistrationAcknowledgementIsExactAndRefusalClears(t *testing.T) {
	cfg, _ := approvedPackRunner(t)
	expected, err := loadPackRegistration(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := agent{packRegistration: expected}
	send := func(kind string, r *runnerRegistration) {
		b, _ := json.Marshal(map[string]any{"type": kind, "registration": r})
		if !a.onPackRunnerFrame(b) {
			t.Fatal("unconsumed registry frame")
		}
	}
	wrong := *expected
	wrong.ProjectIDs = []string{"foreign"}
	send("runner.registered", &wrong)
	if a.packRegistered {
		t.Fatal("foreign ACK accepted")
	}
	send("runner.registered", expected)
	if !a.packRegistered {
		t.Fatal("matching ACK refused")
	}
	send("runner.registration-refused", nil)
	if a.packRegistered {
		t.Fatal("refusal retained acknowledgement")
	}
	if a.onPackRunnerFrame([]byte(`{"type":"config"}`)) {
		t.Fatal("legacy frame intercepted")
	}
}
func TestPackRegistrationUsesActualPairedSocketAndReverifiesOnReconnect(t *testing.T) {
	cfg, approval := approvedPackRunner(t)
	var logs bytes.Buffer
	previousLog := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previousLog)
	t.Setenv("PATH", t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	frames := make(chan runnerRegistration, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic" {
			http.Error(w, "unauthorized", 401)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			var frame struct {
				Type         string             `json:"type"`
				Registration runnerRegistration `json:"registration"`
			}
			if err := wsjson.Read(ctx, conn, &frame); err != nil {
				return
			}
			if frame.Type == "runner.register" {
				frames <- frame.Registration
				_ = wsjson.Write(ctx, conn, map[string]any{"type": "runner.registered", "registration": frame.Registration})
				_ = conn.Close(websocket.StatusGoingAway, "fixture reconnect")
				return
			}
		}
	}))
	defer server.Close()
	for i := 0; i < 2; i++ {
		connected, _ := serve(ctx, cfg, "ws"+strings.TrimPrefix(server.URL, "http"))
		if !connected {
			t.Fatal("socket did not connect")
		}
		select {
		case registration := <-frames:
			if registration.ProjectIDs[0] != "project-a" {
				t.Fatal("scope changed")
			}
		case <-ctx.Done():
			t.Fatal("registration missing")
		}
	}
	if strings.Count(logs.String(), "Pack runner project advertisement acknowledged") != 2 {
		t.Fatalf("missing actual socket acknowledgements: %s", logs.String())
	}
	// A new connection cannot reuse the previous connection's successful proof.
	if err := os.WriteFile(approval.Binary, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	thirdCtx, stop := context.WithTimeout(ctx, 200*time.Millisecond)
	defer stop()
	_, _ = serve(thirdCtx, cfg, "ws"+strings.TrimPrefix(server.URL, "http"))
	select {
	case <-frames:
		t.Fatal("reconnect advertised changed bytes")
	default:
	}
}
