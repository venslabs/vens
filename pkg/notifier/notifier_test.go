// Copyright 2025 venslabs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const testVEX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "vulnerabilities": [
    {
      "bom-ref": "urn:cdx:abc/1#pkg-a",
      "id": "CVE-2024-1234",
      "ratings": [
        {"method": "OWASP", "score": 63.0, "severity": "critical", "vector": "OWASP/1.0/8:7/8:9"}
      ],
      "affects": [{"ref": "urn:cdx:abc/1#pkg-a"}]
    },
    {
      "bom-ref": "urn:cdx:abc/1#pkg-b",
      "id": "CVE-2024-5678",
      "ratings": [
        {"method": "CVSSv3", "score": 9.8, "severity": "critical"},
        {"method": "OWASP", "score": 12.0, "severity": "low"}
      ]
    },
    {
      "bom-ref": "urn:cdx:abc/1#pkg-c",
      "id": "CVE-2024-9999",
      "ratings": [
        {"method": "OWASP", "score": 40.0, "severity": "high"}
      ]
    }
  ]
}`

func TestParseVEX(t *testing.T) {
	r, err := ParseVEX([]byte(testVEX))
	require.NoError(t, err)
	require.Equal(t, 3, r.Total)
	require.Equal(t, 1, r.BySeverity["critical"])
	require.Equal(t, 1, r.BySeverity["high"])
	require.Equal(t, 1, r.BySeverity["low"])

	// Sorted by severity band first, then score.
	require.Equal(t, "CVE-2024-1234", r.Findings[0].VulnID)
	require.Equal(t, 63.0, r.Findings[0].Score)
	require.Equal(t, []string{"urn:cdx:abc/1#pkg-a"}, r.Findings[0].Affects)
	require.Equal(t, "CVE-2024-9999", r.Findings[1].VulnID)
	// The CVSSv3 rating is ignored in favour of the OWASP one.
	require.Equal(t, "CVE-2024-5678", r.Findings[2].VulnID)
	require.Equal(t, 12.0, r.Findings[2].Score)
	require.Equal(t, "low", r.Findings[2].Severity)
}

func TestParseVEXInvalid(t *testing.T) {
	_, err := ParseVEX([]byte("not json"))
	require.Error(t, err)
}

func TestParseVEXEmpty(t *testing.T) {
	r, err := ParseVEX([]byte(`{"bomFormat": "CycloneDX"}`))
	require.NoError(t, err)
	require.Equal(t, 0, r.Total)
}

func TestSlackFormatMessage(t *testing.T) {
	r, err := ParseVEX([]byte(testVEX))
	require.NoError(t, err)

	n, err := New("slack", SlackOpts{WebhookURL: "https://hooks.slack.com/test"})
	require.NoError(t, err)
	msg := n.FormatMessage(r)

	require.Contains(t, msg, "*vens scan:* 3 vulnerabilities scored")
	require.Contains(t, msg, "critical: 1")
	require.Contains(t, msg, "high: 1")
	require.Contains(t, msg, "low: 1")
	require.Contains(t, msg, "`CVE-2024-1234` — 63.0 (critical)")
	require.Contains(t, msg, "`CVE-2024-9999` — 40.0 (high)")
}

func TestSlackSend(t *testing.T) {
	var gotContentType, gotText string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotContentType = req.Header.Get("Content-Type")
		body, _ := io.ReadAll(req.Body)
		var payload map[string]string
		require.NoError(t, json.Unmarshal(body, &payload))
		gotText = payload["text"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r, err := ParseVEX([]byte(testVEX))
	require.NoError(t, err)

	n, err := New("slack", SlackOpts{WebhookURL: srv.URL})
	require.NoError(t, err)
	require.NoError(t, n.Send(context.Background(), r))

	require.Equal(t, "application/json", gotContentType)
	require.Contains(t, gotText, "CVE-2024-1234")
}

func TestSlackSendFailsOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	r, err := ParseVEX([]byte(testVEX))
	require.NoError(t, err)

	n, err := New("slack", SlackOpts{WebhookURL: srv.URL})
	require.NoError(t, err)
	err = n.Send(context.Background(), r)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "404"))
}

func TestNewUnknownTarget(t *testing.T) {
	_, err := New("jira", SlackOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), `unknown notify target "jira"`)
}

func TestSlackSendNeedsWebhook(t *testing.T) {
	// Building a notifier without a webhook is fine — formatting (dry-run)
	// needs none. Only Send requires one.
	n, err := New("slack", SlackOpts{})
	require.NoError(t, err)

	r, err := ParseVEX([]byte(testVEX))
	require.NoError(t, err)

	err = n.Send(context.Background(), r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "webhook")
}
