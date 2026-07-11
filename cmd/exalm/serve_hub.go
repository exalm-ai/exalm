package main

// serve_hub.go — the multi-dashboard hub side of `exalm serve`: a discovery
// file (~/.exalm/hub.json) that analyzer `--open` runs use to find and
// authenticate to the running hub, and the closures the web layer needs to
// reconstruct an investigation engine from an ingested session.
//
// Trust model: the hub secret is random per run, stored 0600, sent only in
// the X-Exalm-Ingest header to a loopback address, and removed on shutdown.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/internal/registry"
	"github.com/exalm-ai/exalm/internal/web"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// hubFile is the on-disk discovery record for a running hub.
type hubFile struct {
	Port   int    `json:"port"`
	Secret string `json:"secret"`
	PID    int    `json:"pid"`
}

// hubFilePath returns ~/.exalm/hub.json.
func hubFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".exalm", "hub.json"), nil
}

// newHubSecret returns a fresh random shared secret.
func newHubSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate hub secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// writeHubFile persists the discovery record (0600, atomic) and returns a
// cleanup func that removes it on shutdown.
func writeHubFile(port int, secret string) (func(), error) {
	p, err := hubFilePath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	data, err := json.Marshal(hubFile{Port: port, Secret: secret, PID: os.Getpid()})
	if err != nil {
		return nil, err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return nil, fmt.Errorf("write hub file: %w", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return nil, fmt.Errorf("persist hub file: %w", err)
	}
	return func() { os.Remove(p) }, nil //nolint:errcheck
}

// profileLookup resolves an analyzer name to its investigation profile via
// the plugin registry.
func profileLookup(analyzer string) (investigate.Profile, bool) {
	p, ok := registry.Get(analyzer)
	if !ok {
		return investigate.Profile{}, false
	}
	inv, ok := p.(investigable)
	if !ok {
		return investigate.Profile{}, false
	}
	return inv.InvestigationProfile(), true
}

// applyHubServeOpts turns a ServeOpts into a multi-dashboard hub: session
// registry, ingest secret, and the engine-reconstruction closures. Returns
// the hub-file cleanup func (call on shutdown).
func applyHubServeOpts(opts *web.ServeOpts, llm plugin.LLMClient, red plugin.Redactor) (func(), error) {
	secret, err := newHubSecret()
	if err != nil {
		return nil, err
	}
	port := opts.Port
	if port == 0 {
		port = 7433
	}
	cleanup, err := writeHubFile(port, secret)
	if err != nil {
		return nil, err
	}
	opts.Sessions = web.NewSessionRegistry()
	opts.IngestAuth = secret
	opts.ProfileLookup = profileLookup
	opts.BuildSessionHandlers = func(session *investigate.LogSession, profile investigate.Profile) (web.SessionHandlers, error) {
		engine, err := investigate.NewEngine(profile)
		if err != nil {
			return web.SessionHandlers{}, err
		}
		return buildAnalyzerHandlers(session, engine, llm, red), nil
	}
	return cleanup, nil
}

// tryAttachToHub attempts to hand the analyzer session to a running hub.
// Returns the dashboard URL on success; any failure returns ("", err) and
// the caller falls back to serving locally.
func tryAttachToHub(session *investigate.LogSession) (string, error) {
	p, err := hubFilePath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return "", err // no hub file — no hub
	}
	var hf hubFile
	if err := json.Unmarshal(data, &hf); err != nil {
		return "", fmt.Errorf("parse hub file: %w", err)
	}
	client := &http.Client{Timeout: 2 * time.Second}

	// Probe: only trust the file if a live Exalm hub answers.
	healthURL := fmt.Sprintf("http://localhost:%d/healthz", hf.Port)
	resp, err := client.Get(healthURL)
	if err != nil {
		return "", fmt.Errorf("hub not reachable: %w", err)
	}
	var health struct {
		Hub bool `json:"hub"`
	}
	err = json.NewDecoder(resp.Body).Decode(&health)
	resp.Body.Close() //nolint:errcheck
	if err != nil || !health.Hub {
		return "", fmt.Errorf("listener on port %d is not an exalm hub", hf.Port)
	}

	snap, err := session.Snapshot()
	if err != nil {
		return "", fmt.Errorf("snapshot session: %w", err)
	}
	body, err := json.Marshal(snap)
	if err != nil {
		return "", fmt.Errorf("encode snapshot: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://localhost:%d/api/ingest/session", hf.Port), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(web.IngestHeader, hf.Secret)
	req.Header.Set("X-Exalm-Request", "true") // CSRF middleware contract
	resp, err = client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ingest request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hub rejected the session (HTTP %d)", resp.StatusCode)
	}
	var out struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.URL, nil
}
