package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Dual-time verify over HTTP: the same event time investigated with
// different knowledge cutoffs yields different verdicts, and the export
// carries per-path material basis with acquisition times.
func TestDualTimeVerifyAndExport(t *testing.T) {
	_, h := newHarness(t)

	event := time.Now().UTC().Format(time.RFC3339)
	code, before := do(t, h, "POST", "/api/verify",
		`{"leafId":"leaf-laterev","purpose":"serverAuth","eventTime":"`+event+`"}`)
	if code != http.StatusOK || before["valid"] != true {
		t.Fatalf("late notice unknown yet, expected valid: %d %v", code, before["reason"])
	}
	if before["eventTime"] == nil || before["knowledgeCutoff"] == nil {
		t.Fatal("evidence must record both the event time and the knowledge cutoff")
	}

	later := time.Now().Add(3 * time.Hour).UTC().Format(time.RFC3339)
	code, after := do(t, h, "POST", "/api/verify",
		`{"leafId":"leaf-laterev","purpose":"serverAuth","eventTime":"`+event+`","knowledgeCutoff":"`+later+`"}`)
	if code != http.StatusOK || after["valid"] != false {
		t.Fatalf("later knowledge must disqualify the same event: %d %v", code, after)
	}
	if after["eventTime"] != before["eventTime"] {
		t.Fatal("both versions must share the event time")
	}

	id := int(after["evidenceId"].(float64))
	req := httptest.NewRequest("GET", "/api/history/"+itoa(id)+"/export", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d", rec.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["disclaimer"] == nil || doc["knowledgeCutoff"] == nil {
		t.Fatal("export must state the knowledge cutoff and the time-basis disclaimer")
	}
	chains := doc["chains"].([]any)
	if len(chains) == 0 {
		t.Fatal("export must list candidate paths")
	}
	basis := chains[0].(map[string]any)["basis"].([]any)
	if len(basis) == 0 {
		t.Fatal("each exported path must carry its material basis")
	}
	first := basis[0].(map[string]any)
	if first["acquiredAt"] == nil || first["kind"] == nil {
		t.Fatal("basis items must carry acquisition time and kind")
	}
	// The revocation basis item must cite the late notice's times.
	foundRev := false
	for _, c := range chains {
		for _, b := range c.(map[string]any)["basis"].([]any) {
			item := b.(map[string]any)
			if item["kind"] == "revocation" {
				foundRev = true
				if item["effective"] == nil {
					t.Fatal("revocation basis must carry the effective revocation time")
				}
			}
		}
	}
	if !foundRev {
		t.Fatal("export must cite the revocation material actually used")
	}

	// Knowledge endpoint lists late/corrected material side by side.
	code, k := do(t, h, "GET", "/api/knowledge", "")
	if code != http.StatusOK {
		t.Fatalf("knowledge: %d", code)
	}
	revs := k["revocationEvents"].([]any)
	if len(revs) < 2 {
		t.Fatal("expected multiple revocation material items")
	}
	var late map[string]any
	for _, rv := range revs {
		m := rv.(map[string]any)
		if m["certId"] == "leaf-laterev" {
			late = m
		}
	}
	if late == nil || !strings.Contains(late["note"].(string), "late") {
		t.Fatal("late revocation notice must be listed with its note")
	}
}

func itoa(n int) string {
	return strings.TrimSpace(jsonNumber(n))
}

func jsonNumber(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
