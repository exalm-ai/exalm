package webhook_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/webhook"
	"github.com/exalm-ai/exalm/plugins/dora"
)

// buildPayload returns a minimal Terraform Cloud webhook JSON body.
func buildPayload(trigger, status string) []byte {
	type notif struct {
		Message      string `json:"message"`
		Trigger      string `json:"trigger"`
		RunStatus    string `json:"run_status"`
		RunUpdatedAt string `json:"run_updated_at"`
		RunUpdatedBy string `json:"run_updated_by"`
	}
	type payload struct {
		PayloadVersion   int     `json:"payload_version"`
		RunID            string  `json:"run_id"`
		RunURL           string  `json:"run_url"`
		WorkspaceName    string  `json:"workspace_name"`
		OrganizationName string  `json:"organization_name"`
		Notifications    []notif `json:"notifications"`
	}
	p := payload{
		PayloadVersion:   1,
		RunID:            "run-abc123",
		RunURL:           "https://app.terraform.io/app/myorg/workspaces/prod/runs/run-abc123",
		WorkspaceName:    "production",
		OrganizationName: "my-org",
		Notifications:    []notif{},
	}
	if trigger != "" {
		p.Notifications = append(p.Notifications, notif{
			Message:      "Run event",
			Trigger:      trigger,
			RunStatus:    status,
			RunUpdatedAt: time.Now().UTC().Format(time.RFC3339),
			RunUpdatedBy: "ci-bot",
		})
	}
	b, _ := json.Marshal(p)
	return b
}

func hmacSig(secret, body []byte) string {
	mac := hmac.New(sha512.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// TestServeHTTP_Ping — POST with no notifications → 200 ignored.
func TestServeHTTP_Ping(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	h := webhook.NewHandler(dir+"/tf-events.jsonl", "")

	body := buildPayload("", "")
	req := httptest.NewRequest(http.MethodPost, "/webhook/terraform", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "ignored") {
		t.Fatalf("want 'ignored' in body, got: %s", rr.Body.String())
	}

	events, err := webhook.LoadEvents(h.StorePath())
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("want 0 events for ping, got %d", len(events))
	}
}

// TestServeHTTP_Applied — POST with run:completed + applied → 200 accepted, event written.
func TestServeHTTP_Applied(t *testing.T) {
	// Not parallel: mutates the package-level dora.DeploymentDir global.
	dir := t.TempDir()
	dora.DeploymentDir = dir
	t.Cleanup(func() { dora.DeploymentDir = "" })

	storePath := dir + "/tf-events.jsonl"
	h := webhook.NewHandler(storePath, "")

	body := buildPayload("run:completed", "applied")
	req := httptest.NewRequest(http.MethodPost, "/webhook/terraform", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "accepted") {
		t.Fatalf("want 'accepted' in body, got: %s", rr.Body.String())
	}

	events, err := webhook.LoadEvents(storePath)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.RunID != "run-abc123" {
		t.Errorf("want RunID run-abc123, got %s", ev.RunID)
	}
	if ev.Status != "applied" {
		t.Errorf("want Status applied, got %s", ev.Status)
	}
	if ev.WorkspaceName != "production" {
		t.Errorf("want WorkspaceName production, got %s", ev.WorkspaceName)
	}
}

// TestServeHTTP_Errored — POST with run:errored → event has Success: false in DORA store.
func TestServeHTTP_Errored(t *testing.T) {
	// Not parallel: mutates the package-level dora.DeploymentDir global.
	dir := t.TempDir()
	dora.DeploymentDir = dir
	t.Cleanup(func() { dora.DeploymentDir = "" })

	storePath := dir + "/tf-events.jsonl"
	h := webhook.NewHandler(storePath, "")

	body := buildPayload("run:errored", "errored")
	req := httptest.NewRequest(http.MethodPost, "/webhook/terraform", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	events, err := webhook.LoadEvents(storePath)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Status != "errored" {
		t.Errorf("want Status errored, got %s", events[0].Status)
	}
}

// TestServeHTTP_BadMethod — GET → 405.
func TestServeHTTP_BadMethod(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	h := webhook.NewHandler(dir+"/tf-events.jsonl", "")

	req := httptest.NewRequest(http.MethodGet, "/webhook/terraform", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rr.Code)
	}
}

// TestServeHTTP_HMACValid — correct HMAC → 200.
func TestServeHTTP_HMACValid(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dora.DeploymentDir = dir
	t.Cleanup(func() { dora.DeploymentDir = "" })

	secret := "supersecret"
	h := webhook.NewHandler(dir+"/tf-events.jsonl", secret)

	body := buildPayload("run:completed", "applied")
	sig := hmacSig([]byte(secret), body)

	req := httptest.NewRequest(http.MethodPost, "/webhook/terraform", bytes.NewReader(body))
	req.Header.Set("X-TFE-Notification-Signature", sig)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestServeHTTP_HMACInvalid — wrong HMAC → 401.
func TestServeHTTP_HMACInvalid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	h := webhook.NewHandler(dir+"/tf-events.jsonl", "supersecret")

	body := buildPayload("run:completed", "applied")
	req := httptest.NewRequest(http.MethodPost, "/webhook/terraform", bytes.NewReader(body))
	req.Header.Set("X-TFE-Notification-Signature", "deadbeef")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

// TestServeHTTP_BodyTooLarge — body > 1MB → 413.
func TestServeHTTP_BodyTooLarge(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	h := webhook.NewHandler(dir+"/tf-events.jsonl", "")

	// Build a body that exceeds 1 MB.
	large := bytes.Repeat([]byte("x"), (1<<20)+1)
	req := httptest.NewRequest(http.MethodPost, "/webhook/terraform", bytes.NewReader(large))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", rr.Code)
	}
}

// TestLoadEvents_RoundTrip — write then read back.
func TestLoadEvents_RoundTrip(t *testing.T) {
	// Not parallel: mutates the package-level dora.DeploymentDir global.
	dir := t.TempDir()
	dora.DeploymentDir = dir
	t.Cleanup(func() { dora.DeploymentDir = "" })

	storePath := dir + "/tf-events.jsonl"
	h := webhook.NewHandler(storePath, "")

	// Write two events.
	for _, status := range []string{"applied", "errored"} {
		trigger := "run:completed"
		if status == "errored" {
			trigger = "run:errored"
		}
		body := buildPayload(trigger, status)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200 for %s, got %d", status, rr.Code)
		}
	}

	events, err := webhook.LoadEvents(storePath)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events, got %d", len(events))
	}
	if events[0].Status != "applied" {
		t.Errorf("first event status: want applied, got %s", events[0].Status)
	}
	if events[1].Status != "errored" {
		t.Errorf("second event status: want errored, got %s", events[1].Status)
	}
}
