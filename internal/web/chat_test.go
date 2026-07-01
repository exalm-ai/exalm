package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func chatTestServer() *liveServer {
	srv := newTestServer(plugin.Report{Title: "t"})
	srv.chatSem = make(chan struct{}, maxConcurrentChats)
	return srv
}

func sampleConv(id string) *plugin.Conversation {
	return &plugin.Conversation{
		ID: id, Focus: "prod/payment-api",
		Messages: []plugin.ConversationMessage{
			{Role: "user", Content: "Why is payment-api crashing?"},
			{Role: "assistant", Content: "It was OOM-killed.", Confidence: "high"},
		},
	}
}

func TestHandleChat_Unwired503(t *testing.T) {
	srv := chatTestServer() // converseFn nil
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"message":"hi"}`))
	srv.handleChat(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when chat is unwired, got %d", rr.Code)
	}
}

func TestHandleChat_RequiresMessage(t *testing.T) {
	srv := chatTestServer()
	srv.converseFn = func(_ context.Context, req ConverseRequest) (*plugin.Conversation, error) {
		return sampleConv("c1"), nil
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"message":""}`))
	srv.handleChat(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for an empty message, got %d", rr.Code)
	}
}

func TestHandleChat_HappyPath(t *testing.T) {
	srv := chatTestServer()
	var gotReq ConverseRequest
	srv.converseFn = func(_ context.Context, req ConverseRequest) (*plugin.Conversation, error) {
		gotReq = req
		return sampleConv("c1"), nil
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"message":"Why is payment-api crashing?","namespace":"prod"}`))
	srv.handleChat(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	if gotReq.Message != "Why is payment-api crashing?" || gotReq.Namespace != "prod" {
		t.Errorf("converseFn did not receive the decoded request: %+v", gotReq)
	}
	if !strings.Contains(rr.Body.String(), "OOM-killed") {
		t.Errorf("expected the conversation reply in the response, got: %s", rr.Body.String())
	}
}

func TestHandleChat_MethodNotAllowed(t *testing.T) {
	srv := chatTestServer()
	srv.converseFn = func(_ context.Context, _ ConverseRequest) (*plugin.Conversation, error) { return sampleConv("c1"), nil }
	rr := httptest.NewRecorder()
	srv.handleChat(rr, httptest.NewRequest(http.MethodGet, "/api/chat", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", rr.Code)
	}
}

func TestHandleChat_ConcurrencyGate(t *testing.T) {
	srv := chatTestServer()
	srv.converseFn = func(_ context.Context, _ ConverseRequest) (*plugin.Conversation, error) { return sampleConv("c1"), nil }
	// Fill the semaphore to simulate maxConcurrentChats in-flight requests.
	for i := 0; i < maxConcurrentChats; i++ {
		srv.chatSem <- struct{}{}
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"message":"hi"}`))
	srv.handleChat(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 once the concurrency gate is full, got %d", rr.Code)
	}
}

func TestHandleGetConversation_Unwired503(t *testing.T) {
	srv := chatTestServer() // getConvoFn nil
	rr := httptest.NewRecorder()
	srv.handleGetConversation(rr, httptest.NewRequest(http.MethodGet, "/api/chat/c1", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when GetConversation is unwired, got %d", rr.Code)
	}
}

func TestHandleGetConversation_Found(t *testing.T) {
	srv := chatTestServer()
	srv.getConvoFn = func(_ context.Context, id string) (*plugin.Conversation, error) {
		if id != "c1" {
			t.Fatalf("expected id c1, got %q", id)
		}
		return sampleConv(id), nil
	}
	rr := httptest.NewRecorder()
	srv.handleGetConversation(rr, httptest.NewRequest(http.MethodGet, "/api/chat/c1", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "payment-api") {
		t.Errorf("expected the conversation body, got: %s", rr.Body.String())
	}
}

func TestHandleGetConversation_NotFound(t *testing.T) {
	srv := chatTestServer()
	srv.getConvoFn = func(_ context.Context, id string) (*plugin.Conversation, error) {
		return nil, errors.New("conversation not found")
	}
	rr := httptest.NewRecorder()
	srv.handleGetConversation(rr, httptest.NewRequest(http.MethodGet, "/api/chat/does-not-exist", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}
