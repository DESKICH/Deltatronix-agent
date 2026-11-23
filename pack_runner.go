package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/deltatronix/dtx-agent/internal/packruntime"
)

// Operator approval is separate from pairing and signed artifact metadata. Nothing
// received over the socket can install trust, select a release or enable this.
type packRunnerConfig struct {
	APIURL     string   `json:"apiUrl"`
	AgentID    string   `json:"agentId"`
	ProjectIDs []string `json:"projectIds"`
	Binary     string   `json:"binary"`
	Descriptor string   `json:"descriptor"`
	PublicKey  string   `json:"publicKey"`
	KeyID      string   `json:"keyId"`
	ArtifactID string   `json:"artifactId"`
}
type runnerRegistration struct {
	ContractVersion int               `json:"contractVersion"`
	Kind            string            `json:"kind"`
	ProjectIDs      []string          `json:"projectIds"`
	Domains         []string          `json:"domains"`
	EngineVersions  map[string]string `json:"engineVersions"`
	Runtime         runnerRuntime     `json:"runtime"`
}
type runnerRuntime struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
}

func loadPackRegistration(cfg Config) (*runnerRegistration, error) {
	dir, err := agentConfigDir()
	if err != nil {
		return nil, err
	}
	data, err := packruntime.ReadRegularFile(filepath.Join(dir, "pack-runner.json"), 64<<10)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var approved packRunnerConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&approved); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid Pack runner config")
	}
	if approved.APIURL != cfg.APIURL || approved.AgentID != cfg.AgentID || cfg.AgentID == "" || len(approved.ProjectIDs) < 1 || len(approved.ProjectIDs) > 16 {
		return nil, errors.New("Pack runner pairing or project scope unavailable")
	}
	seen := map[string]bool{}
	for _, id := range approved.ProjectIDs {
		if strings.TrimSpace(id) != id || id == "" || len(id) > 128 || strings.ContainsAny(id, "\x00\r\n") || seen[id] {
			return nil, errors.New("invalid Pack runner project scope")
		}
		seen[id] = true
	}
	for _, path := range []string{approved.Binary, approved.Descriptor, approved.PublicKey} {
		if !filepath.IsAbs(path) {
			return nil, errors.New("Pack runner requires absolute local paths")
		}
	}
	descriptor, err := packruntime.ReadRegularFile(approved.Descriptor, packruntime.MaxDescriptorBytes)
	if err != nil {
		return nil, err
	}
	key, err := packruntime.ReadRegularFile(approved.PublicKey, 8192)
	if err != nil {
		return nil, err
	}
	binary, err := packruntime.RegularFile(approved.Binary)
	if err != nil {
		return nil, err
	}
	defer binary.Close()
	verified, err := packruntime.Verify(descriptor, binary, packruntime.Trust{KeyID: approved.KeyID, PublicKeyPEM: string(key), ArtifactID: approved.ArtifactID, Platform: runtime.GOOS + "-" + runtime.GOARCH})
	if err != nil {
		return nil, err
	}
	return &runnerRegistration{1, "companion", approved.ProjectIDs, []string{"pack"}, map[string]string{"@deltatronix/pack-core": verified.PackCoreVersion}, runnerRuntime{"deno", verified.DenoVersion}}, nil
}

func (a *agent) registerPackRunner() {
	registration, err := loadPackRegistration(a.cfg)
	if err != nil {
		log.Printf("Pack runner registration disabled: local approval or runtime verification failed")
		return
	}
	if registration == nil {
		return
	}
	a.mu.Lock()
	a.packRegistration = registration
	a.packRegistered = false
	a.mu.Unlock()
	a.send(map[string]any{"type": "runner.register", "registration": registration})
}
func (a *agent) onPackRunnerFrame(data []byte) bool {
	var frame struct {
		Type         string              `json:"type"`
		Registration *runnerRegistration `json:"registration"`
	}
	if json.Unmarshal(data, &frame) != nil {
		return false
	}
	if frame.Type != "runner.registered" && frame.Type != "runner.registration-refused" {
		return false
	}
	a.mu.Lock()
	a.packRegistered = frame.Type == "runner.registered" && a.packRegistration != nil && reflect.DeepEqual(frame.Registration, a.packRegistration)
	accepted := a.packRegistered
	a.mu.Unlock()
	if accepted {
		log.Printf("Pack runner project advertisement acknowledged (no task claim)")
	} else {
		log.Printf("Pack runner project advertisement unavailable")
	}
	return true
}
