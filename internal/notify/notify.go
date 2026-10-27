/*
Copyright 2026 Greybeard Holdings LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package notify posts queue/alert events to an optional webhook.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Payload is the JSON body.
type Payload struct {
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Reason    string    `json:"reason"`
	Message   string    `json:"message"`
	Enforced  string    `json:"enforcedDigest,omitempty"`
	Pending   string    `json:"pendingDigest,omitempty"`
	Time      time.Time `json:"time"`
}

// Webhook posts payloads. A zero URL is a no-op.
type Webhook struct {
	HTTP *http.Client
}

// Send posts p to url; errors are returned for logging only and never block reconciliation.
func (w *Webhook) Send(ctx context.Context, url string, p Payload) error {
	if url == "" {
		return nil
	}
	c := w.HTTP
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	b, _ := json.Marshal(p)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook HTTP %d", resp.StatusCode)
	}
	return nil
}
