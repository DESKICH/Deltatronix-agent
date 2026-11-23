package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket/wsjson"
)

func occupancyWireFixture(t *testing.T) *nativePayload {
	t.Helper()
	p, _ := assemblyWireFixture(t)
	p.ContractVersion = 4
	p.Operation = json.RawMessage(`{"kind":"assembly-occupancy"}`)
	return p
}
func occupancyPayloadWire(t *testing.T, p *nativePayload) map[string]any {
	t.Helper()
	wire := nativePayloadWire(t, p)
	delete(wire, "boardCaptures")
	delete(wire, "fitLimits")
	delete(wire, "proofHash")
	return wire
}
func TestNativeOccupancyAuthorizesExactV4AndKeepsClosureWire(t *testing.T) {
	p := occupancyWireFixture(t)
	if err := validateNativePayload(p); err != nil {
		t.Fatal(err)
	}
	wire := occupancyPayloadWire(t, p)
	data, _ := json.Marshal(wire)
	var parsed nativePayload
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if err := validateNativePayload(&parsed); err != nil {
		t.Fatal(err)
	}
	_, expected := assemblyWireFixture(t)
	expected["contractVersion"] = float64(4)
	expected["operation"] = map[string]any{"kind": "assembly-occupancy"}
	want, _ := canonicalNativeJSON(expected)
	actual, _ := canonicalNativeJSON(nativeChildManifest(p))
	if !bytes.Equal(want, actual) {
		t.Fatalf("v4 changed source/identity wire\nwant %s\ngot %s", want, actual)
	}
	if strings.Contains(string(actual), `"url"`) {
		t.Fatal("transport URLs leaked into child")
	}
}
func TestNativeOccupancyRejectsWrongActionPolicyScopeAndAmbiguousWire(t *testing.T) {
	cases := map[string]func(*nativePayload){
		"v2 action":       func(p *nativePayload) { p.Operation = json.RawMessage(`{"kind":"assembly-verify"}`) },
		"extra action":    func(p *nativePayload) { p.Operation = json.RawMessage(`{"kind":"assembly-occupancy","format":"json"}`) },
		"wrong version":   func(p *nativePayload) { p.ContractVersion = 2 },
		"unknown version": func(p *nativePayload) { p.ContractVersion = 5 },
		"lease expired":   func(p *nativePayload) { p.Lease.ExpiresAt = time.Now().Add(-time.Minute).UnixMilli() },
		"invalid request": func(p *nativePayload) { p.RequestID = "../request" },
		"changed source":  func(p *nativePayload) { p.SourceDocuments[0].Version++ },
		"changed version": func(p *nativePayload) { p.Version++ },
		"changed budget":  func(p *nativePayload) { p.Limits["maxOutputBytes"]++ },
		"wrong runtime":   func(p *nativePayload) { p.Runtime.ArtifactID = "../runtime" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := occupancyWireFixture(t)
			mutate(p)
			if validateNativePayload(p) == nil {
				t.Fatal("invalid assignment accepted")
			}
		})
	}
	for _, field := range []string{"configurationId", "version", "source configuration", "unknown", "source URL", "PCB field"} {
		t.Run(field, func(t *testing.T) {
			wire := occupancyPayloadWire(t, occupancyWireFixture(t))
			switch field {
			case "configurationId":
				delete(wire, field)
			case "version":
				wire[field] = nil
			case "source configuration":
				delete(wire["sourceDocuments"].([]any)[0].(map[string]any), "configurationId")
			case "unknown":
				wire["outputPath"] = "/tmp/caller"
			case "source URL":
				delete(wire["sourceDocuments"].([]any)[0].(map[string]any)["document"].(map[string]any), "url")
			case "PCB field":
				wire["boardCaptures"] = nil
			}
			data, _ := json.Marshal(wire)
			var p nativePayload
			if json.Unmarshal(data, &p) == nil {
				t.Fatal("ambiguous v4 wire accepted")
			}
		})
	}
}
func occupancyOutputFixture(t *testing.T) (*nativePayload, map[string]any, string, []byte) {
	t.Helper()
	p := occupancyWireFixture(t)
	summary := assemblySummaryFixture(t)
	dir := t.TempDir()
	// Synthetic staged bytes exercise forwarding only; Shape owns occupancy semantics.
	data := []byte(`{"fixture":"canonical occupancy bytes"}`)
	file := map[string]any{"format": "json", "hash": hashNative(data), "size": float64(len(data))}
	summary["file"] = file
	details, _ := json.Marshal(map[string]any{"assembly": summary["assembly"], "file": file})
	summary["resultHash"] = hashNative(details)
	summary["resultSize"] = float64(len(details))
	if err := os.WriteFile(filepath.Join(dir, "export.bin"), data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "result.json"), details, 0644); err != nil {
		t.Fatal(err)
	}
	return p, summary, dir, data
}
func occupancyOutputFrames(p *nativePayload, summary map[string]any) []byte {
	var output bytes.Buffer
	for _, frame := range []map[string]any{{"type": "limits", "applied": map[string]any{"memoryBytes": 1 << 30, "swapBytes": 0, "pids": 64, "cpuQuota": 1, "runtime": "deno", "runtimeVersion": "2.9.8"}}, {"type": "phase", "phase": "booting"}, {"type": "phase", "phase": "running"}, {"type": "result", "result": summary}} {
		frame["contractVersion"] = p.ContractVersion
		frame["requestId"] = p.RequestID
		data, _ := json.Marshal(frame)
		output.Write(data)
		output.WriteByte('\n')
	}
	return output.Bytes()
}
func TestNativeOccupancyVerifiesRequiredFileAndPreservesLegacySummary(t *testing.T) {
	p, summary, dir, _ := occupancyOutputFixture(t)
	if _, err := verifyNativeOutput(occupancyOutputFrames(p, summary), p, dir); err != nil {
		t.Fatal(err)
	}
	monitor := &nativeOutputMonitor{contractVersion: 4, requestID: p.RequestID, running: make(chan struct{}, 1)}
	if err := monitor.write(occupancyOutputFrames(p, summary)); err != nil {
		t.Fatal(err)
	}
	legacy, _ := assemblyWireFixture(t)
	if validateNativeAssemblySummary(legacy, summary) == nil {
		t.Fatal("legacy assembly accepted JSON file")
	}
	cases := map[string]func(map[string]any, string){
		"aggregate bytes": func(s map[string]any, dir string) {
			data := make([]byte, 8<<20)
			os.WriteFile(filepath.Join(dir, "export.bin"), data, 0644)
			file := s["file"].(map[string]any)
			file["hash"] = hashNative(data)
			file["size"] = float64(len(data))
		},
		"missing metadata": func(s map[string]any, _ string) { s["file"] = nil },
		"wrong format":     func(s map[string]any, _ string) { s["file"].(map[string]any)["format"] = "step" },
		"extra field":      func(s map[string]any, _ string) { s["file"].(map[string]any)["path"] = "elsewhere" },
		"missing file":     func(_ map[string]any, dir string) { os.Remove(filepath.Join(dir, "export.bin")) },
		"changed bytes": func(_ map[string]any, dir string) {
			os.WriteFile(filepath.Join(dir, "export.bin"), []byte("changed"), 0644)
		},
		"symlink": func(_ map[string]any, dir string) {
			os.Remove(filepath.Join(dir, "export.bin"))
			os.Symlink(filepath.Join(dir, "result.json"), filepath.Join(dir, "export.bin"))
		},
		"fractional size": func(s map[string]any, _ string) { s["file"].(map[string]any)["size"] = 0.5 },
		"empty hash":      func(s map[string]any, _ string) { s["file"].(map[string]any)["hash"] = "" },
		"derived poses":   func(s map[string]any, _ string) { s["poses"] = []any{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, s, dir, _ := occupancyOutputFixture(t)
			mutate(s, dir)
			if _, err := verifyNativeOutput(occupancyOutputFrames(p, s), p, dir); err == nil {
				t.Fatal("invalid output accepted")
			}
		})
	}
}
func TestNativeOccupancyForwardsJSONOnlyThroughLeasedUpload(t *testing.T) {
	for _, mime := range []string{"application/json", "application/step"} {
		t.Run(mime, func(t *testing.T) {
			p, s, dir, data := occupancyOutputFixture(t)
			var puts, completed int
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/upload" {
					puts++
					if r.Header.Get("Authorization") != "" || r.Header.Get("X-Shape-Lease") != "" || r.Header.Get("Content-Type") != "application/json" {
						t.Error("upload transport changed scope")
					}
					actual, _ := io.ReadAll(r.Body)
					if !bytes.Equal(actual, data) {
						t.Error("forwarded bytes changed")
					}
					w.WriteHeader(200)
					return
				}
				if r.Header.Get("Authorization") != "Bearer synthetic-token" || r.Header.Get("X-Shape-Lease") != p.Lease.ID {
					t.Error("staging lost leased owner")
				}
				switch r.URL.Path {
				case "/compute/shape-jobs/job/output-upload":
					var file map[string]any
					json.NewDecoder(r.Body).Decode(&file)
					if file["format"] != "json" || file["hash"] != hashNative(data) {
						t.Error("staging metadata changed")
					}
					json.NewEncoder(w).Encode(map[string]any{"fileId": "owned-file", "uploadUrl": server.URL + "/upload", "contentType": mime})
				case "/compute/shape-jobs/job/output-complete":
					completed++
					json.NewEncoder(w).Encode(map[string]any{"fileId": "owned-file", "status": "READY"})
				default:
					t.Error("unexpected output route")
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			a := &agent{cfg: Config{APIURL: server.URL, AgentToken: "synthetic-token"}}
			receipt, err := a.uploadNativeOutput(context.Background(), "job", p, dir, s["file"].(map[string]any))
			if mime == "application/json" {
				if err != nil || receipt["format"] != "json" || puts != 1 || completed != 1 {
					t.Fatalf("JSON forwarding failed %v %v", receipt, err)
				}
			} else if err == nil || puts != 0 || completed != 0 {
				t.Fatal("wrong MIME reached upload")
			}
		})
	}
}
func TestNativeOccupancyCapabilityRequiresSupportedSandbox(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("synthetic Docker probe uses a POSIX shell fixture")
	}
	for _, ready := range []bool{false, true} {
		t.Run(map[bool]string{false: "unavailable", true: "ready"}[ready], func(t *testing.T) {
			dir := t.TempDir()
			script := "#!/bin/sh\nexit 1\n"
			if ready {
				script = "#!/bin/sh\ncase \"$1\" in\nps) exit 0;;\ninfo) echo 'linux aarch64 2';;\nimage) exit 0;;\n*) exit 1;;\nesac\n"
			}
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"data":[]}`) }))
			defer model.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn := connectPairedChat(t, ctx, model.URL+"/v1", "fixture-chat:7b", 8192).Conn
			var frame struct {
				Capabilities []string `json:"capabilities"`
			}
			if err := wsjson.Read(ctx, conn, &frame); err != nil {
				t.Fatal(err)
			}
			if slices.Contains(frame.Capabilities, "shape.assembly.occupancy.v1") != ready || slices.Contains(frame.Capabilities, "shape.native.v1") != ready || slices.Contains(frame.Capabilities, "shape.assembly.v1") != ready || slices.Contains(frame.Capabilities, "shape.pcb-fit.v1") != ready {
				t.Fatalf("capability without supported sandbox %v", frame.Capabilities)
			}
		})
	}
}
