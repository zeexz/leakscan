package report

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"leakscan/internal/detector"
)

func TestSendWebhook_Success(t *testing.T) {
	receivedAuth := ""
	var receivedPayload WebhookPayload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sampleFindings := []detector.Finding{
		{
			Type:     "AWS Access Key ID",
			Location: "keys.env:1",
			Severity: "critical",
			Redacted: "AKIA************ABCD",
		},
	}

	err := SendWebhook(context.Background(), server.URL, sampleFindings, "secret-token-123")
	if err != nil {
		t.Fatalf("SendWebhook failed: %v", err)
	}

	if receivedAuth != "Bearer secret-token-123" {
		t.Errorf("expected Bearer secret-token-123, got %q", receivedAuth)
	}

	if receivedPayload.TotalFindings != 1 {
		t.Errorf("expected 1 total finding, got %d", receivedPayload.TotalFindings)
	}
}

func TestUploadReport_Success(t *testing.T) {
	receivedAuth := ""
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	testData := []byte(`{"sarifVersion": "2.1.0"}`)
	err := UploadReport(context.Background(), server.URL, "application/sarif+json", testData, "token-xyz")
	if err != nil {
		t.Fatalf("UploadReport failed: %v", err)
	}

	if receivedAuth != "Bearer token-xyz" {
		t.Errorf("expected Bearer token-xyz, got %q", receivedAuth)
	}

	if string(receivedBody) != string(testData) {
		t.Errorf("received body mismatch: %s", string(receivedBody))
	}
}

func TestSendWebhook_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	sampleFindings := []detector.Finding{
		{
			Type:     "AWS Access Key ID",
			Severity: "critical",
		},
	}

	err := SendWebhook(context.Background(), server.URL, sampleFindings, "")
	if err == nil {
		t.Fatalf("expected error from 500 server, got nil")
	}
}
