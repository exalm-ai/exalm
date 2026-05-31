// Package webhook implements an HTTP handler that receives Terraform Cloud
// run-notification webhooks and persists them to an append-only JSONL store.
//
// On each accepted "run:completed" or "run:errored" notification the handler:
//  1. Appends a TerraformEvent to the tf-events JSONL store.
//  2. Appends a dora.DeploymentEvent so Terraform applies count toward DORA
//     Deployment Frequency automatically.
//
// HMAC-SHA512 signature verification (optional) is performed when an hmacSecret
// is provided. The secret is compared using crypto/hmac.Equal to prevent
// timing-oracle attacks.
package webhook

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/exalm-ai/exalm/plugins/dora"
)

const maxBodyBytes = 1 << 20 // 1 MB

// TerraformEvent is the normalised record written to the tf-events JSONL store
// for every actionable Terraform Cloud run notification.
type TerraformEvent struct {
	RunID            string    `json:"run_id"`
	RunURL           string    `json:"run_url"`
	WorkspaceName    string    `json:"workspace_name"`
	OrganizationName string    `json:"organization_name"`
	Status           string    `json:"status"` // "applied", "errored", "discarded"
	AppliedAt        time.Time `json:"applied_at"`
	AppliedBy        string    `json:"applied_by,omitempty"`
	Message          string    `json:"message,omitempty"`
}

// Handler is an http.Handler that accepts Terraform Cloud webhook POSTs.
type Handler struct {
	storePath  string
	hmacSecret []byte
	// onEvent is an optional callback invoked after successful event extraction.
	// Nil in production; set in tests to intercept events without filesystem I/O.
	onEvent func(TerraformEvent)
}

// NewHandler returns a Handler that writes events to storePath.
// Pass an empty hmacSecret to skip signature verification.
func NewHandler(storePath, hmacSecret string) *Handler {
	return &Handler{
		storePath:  storePath,
		hmacSecret: []byte(hmacSecret),
	}
}

// StorePath returns the path to the JSONL events file.
func (h *Handler) StorePath() string { return h.storePath }

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusInternalServerError)
		return
	}
	if int64(len(body)) > maxBodyBytes { //nolint:gosec // G115: len() is always non-negative
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	if len(h.hmacSecret) > 0 {
		sig := r.Header.Get("X-TFE-Notification-Signature")
		if !h.verifyHMAC(body, sig) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
	}

	var raw tfPayload
	if err := json.Unmarshal(body, &raw); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	ev, ok := extractEvent(raw)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
		return
	}

	if err := h.appendEvent(ev); err != nil {
		http.Error(w, fmt.Sprintf("store write: %v", err), http.StatusInternalServerError)
		return
	}

	if err := appendDORA(ev); err != nil {
		// Non-fatal: DORA store failure should not reject the webhook delivery.
		_ = err
	}

	if h.onEvent != nil {
		h.onEvent(ev)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

// verifyHMAC returns true if the hex-encoded HMAC-SHA512 of body matches sig.
func (h *Handler) verifyHMAC(body []byte, sig string) bool {
	mac := hmac.New(sha512.New, h.hmacSecret)
	mac.Write(body)
	expected := mac.Sum(nil)

	got, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	return hmac.Equal(expected, got)
}

// appendEvent persists ev to the JSONL store file, creating the file and its
// parent directory if they don't exist.
func (h *Handler) appendEvent(ev TerraformEvent) error {
	if err := os.MkdirAll(filepath.Dir(h.storePath), 0o700); err != nil {
		return fmt.Errorf("create store dir: %w", err)
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	f, err := os.OpenFile(h.storePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: storePath is an internal data file from config
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer f.Close() //nolint:errcheck
	if _, err := fmt.Fprintf(f, "%s\n", data); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	return nil
}

// appendDORA writes a dora.DeploymentEvent so Terraform applies automatically
// contribute to DORA Deployment Frequency metrics.
func appendDORA(ev TerraformEvent) error {
	dep := dora.DeploymentEvent{
		Service:    ev.WorkspaceName,
		Version:    ev.RunID,
		DeployedAt: ev.AppliedAt,
		DeployedBy: ev.AppliedBy,
		Success:    ev.Status == "applied",
	}
	if dep.DeployedAt.IsZero() {
		dep.DeployedAt = time.Now().UTC()
	}
	return dora.AppendDeploymentPublic(dep)
}

// LoadEvents reads all TerraformEvents from the JSONL file at storePath.
// Returns an empty slice (no error) if the file does not yet exist.
func LoadEvents(storePath string) ([]TerraformEvent, error) {
	f, err := os.Open(storePath) //nolint:gosec // G304: storePath is an internal data file, not user-controlled
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open tf-events: %w", err)
	}
	defer f.Close() //nolint:errcheck

	var events []TerraformEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, maxBodyBytes), maxBodyBytes) // match write-side 1 MB limit
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var ev TerraformEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			// Skip malformed lines rather than aborting.
			continue
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read tf-events: %w", err)
	}
	return events, nil
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// extractEvent finds the first actionable notification in a raw payload and
// returns the normalised TerraformEvent. Returns (zero, false) for ping/unknown
// payloads with no matching notification.
func extractEvent(p tfPayload) (TerraformEvent, bool) {
	for _, n := range p.Notifications {
		if n.Trigger != "run:completed" && n.Trigger != "run:errored" {
			continue
		}
		appliedAt := n.RunUpdatedAt
		if appliedAt.IsZero() {
			appliedAt = time.Now().UTC()
		}
		ev := TerraformEvent{
			RunID:            p.RunID,
			RunURL:           p.RunURL,
			WorkspaceName:    p.WorkspaceName,
			OrganizationName: p.OrganizationName,
			Status:           n.RunStatus,
			AppliedAt:        appliedAt,
			AppliedBy:        n.RunUpdatedBy,
			Message:          n.Message,
		}
		return ev, true
	}
	return TerraformEvent{}, false
}

// tfPayload is the raw Terraform Cloud webhook JSON envelope. Only the fields
// the handler uses are mapped; unknown fields are ignored.
type tfPayload struct {
	PayloadVersion   int              `json:"payload_version"`
	RunID            string           `json:"run_id"`
	RunURL           string           `json:"run_url"`
	RunMessage       string           `json:"run_message"`
	RunCreatedAt     time.Time        `json:"run_created_at"`
	RunCreatedBy     string           `json:"run_created_by"`
	WorkspaceID      string           `json:"workspace_id"`
	WorkspaceName    string           `json:"workspace_name"`
	OrganizationName string           `json:"organization_name"`
	Notifications    []tfNotification `json:"notifications"`
}

// tfNotification is one entry in the "notifications" array of a Terraform Cloud
// webhook payload.
type tfNotification struct {
	Message      string    `json:"message"`
	Trigger      string    `json:"trigger"`
	RunStatus    string    `json:"run_status"`
	RunUpdatedAt time.Time `json:"run_updated_at"`
	RunUpdatedBy string    `json:"run_updated_by"`
}
