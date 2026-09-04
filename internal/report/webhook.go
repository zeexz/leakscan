package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"leakscan/internal/detector"
)

// WebhookPayload represents the structured notification sent to webhooks (Slack, Teams, Discord, or generic endpoints).
type WebhookPayload struct {
	Text          string             `json:"text"` // Markdown text supported by Slack/Discord/Teams incoming webhooks
	Scanner       string             `json:"scanner"`
	Timestamp     string             `json:"timestamp"`
	TotalFindings int                `json:"total_findings"`
	Findings      []detector.Finding `json:"findings"`
}

// SendWebhook dispatches an alert payload to the specified webhook URL.
func SendWebhook(ctx context.Context, webhookURL string, findings []detector.Finding, authToken string) error {
	if webhookURL == "" || len(findings) == 0 {
		return nil
	}

	critCount := 0
	highCount := 0
	medCount := 0
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			critCount++
		case "high":
			highCount++
		case "medium":
			medCount++
		}
	}

	summaryText := fmt.Sprintf("🚨 *Leakscan Alert*: Detected %d leaked secret(s) [Critical: %d, High: %d, Medium: %d]",
		len(findings), critCount, highCount, medCount)

	payload := WebhookPayload{
		Text:          summaryText,
		Scanner:       "leakscan",
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		TotalFindings: len(findings),
		Findings:      findings,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "leakscan-cli")

	if authToken == "" {
		authToken = os.Getenv("LEAKSCAN_AUTH_TOKEN")
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook endpoint responded with HTTP %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// UploadReport uploads serialized scan reports (e.g. SARIF or JSON) to a central security server.
func UploadReport(ctx context.Context, uploadURL string, contentType string, data []byte, authToken string) error {
	if uploadURL == "" {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create upload request: %w", err)
	}

	if contentType == "" {
		contentType = "application/json"
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "leakscan-cli")

	if authToken == "" {
		authToken = os.Getenv("LEAKSCAN_AUTH_TOKEN")
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload report: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload endpoint responded with HTTP %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
