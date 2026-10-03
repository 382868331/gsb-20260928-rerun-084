package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"certlab/internal/pki"
)

func newHarness(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	lab := pki.NewLab()
	if err := pki.LoadSamples(lab); err != nil {
		t.Fatal(err)
	}
	s := &Server{lab: lab, hmux: http.NewServeMux()}
	s.routes()
	return s, s.hmux
}

func do(t *testing.T, h http.Handler, method, path, body string) (int, map[string]any) {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	if rec.Body.Len() > 0 && strings.Contains(rec.Header().Get("Content-Type"), "json") {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec.Code, out
}

func doVerify(t *testing.T, h http.Handler, leaf string) map[string]any {
	t.Helper()
	code, body := do(t, h, "POST", "/api/verify", `{"leafId":"`+leaf+`","purpose":"serverAuth"}`)
	if code != http.StatusOK {
		t.Fatalf("verify %s: %d %v", leaf, code, body)
	}
	return body
}

func TestSampleScenariosOverHTTP(t *testing.T) {
	_, h := newHarness(t)

	code, state := do(t, h, "GET", "/api/state", "")
	if code != http.StatusOK || len(state["certs"].([]any)) == 0 {
		t.Fatalf("state: %d %v", code, state)
	}

	ok := doVerify(t, h, "leaf-ok")
	if ok["valid"] != true {
		t.Fatalf("leaf-ok should validate: %v", ok["reason"])
	}
	if len(ok["chains"].([]any)) < 2 {
		t.Fatal("expected multiple trust paths")
	}

	expired := doVerify(t, h, "leaf-expired")
	if expired["valid"] != false || !strings.Contains(expired["reason"].(string), "expired") {
		t.Fatalf("expired path must fail, got %v", expired["reason"])
	}
	nocrl := doVerify(t, h, "leaf-nocrl")
	if nocrl["valid"] != false || !strings.Contains(nocrl["reason"].(string), "revocation data missing") {
		t.Fatalf("missing CRL path must fail, got %v", nocrl["reason"])
	}
	if revoked := doVerify(t, h, "leaf-revoked"); revoked["valid"] != false {
		t.Fatalf("revoked leaf must fail, got %v", revoked)
	}

	if code, _ := do(t, h, "POST", "/api/certs/rootA/trust", `{"trusted":false}`); code != http.StatusOK {
		t.Fatalf("distrust failed: %d", code)
	}
	after := doVerify(t, h, "leaf-ok")
	if after["valid"] != true {
		t.Fatalf("after cut-over leaf must validate via rootB: %v", after["reason"])
	}
	if selected := after["selectedPath"].([]any); selected[0] != "rootB" {
		t.Fatalf("expected rootB path, got %v", selected)
	}
}

func TestHistoryAndCRLAndIndex(t *testing.T) {
	_, h := newHarness(t)
	doVerify(t, h, "leaf-ok")
	doVerify(t, h, "leaf-expired")

	req := httptest.NewRequest("GET", "/api/history", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var hist []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &hist); err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 {
		t.Fatalf("expected 2 evidence records, got %d", len(hist))
	}
	if hist[0]["valid"] != false || hist[1]["valid"] != true {
		t.Fatal("history must be newest-first and immutable")
	}

	req = httptest.NewRequest("GET", "/api/crl/intermediateX", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
		t.Fatalf("expected DER CRL, got %d", rec.Code)
	}
	req = httptest.NewRequest("GET", "/api/crl/silent-im", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("silent CA must not serve a CRL")
	}

	req = httptest.NewRequest("GET", "/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "证书生命周期") {
		t.Fatalf("index page not served: %d", rec.Code)
	}
}

func TestIssueAndRotateOverHTTP(t *testing.T) {
	_, h := newHarness(t)
	code, _ := do(t, h, "POST", "/api/leaves/rotate",
		`{"newId":"leaf-newgen","leafId":"leaf-ok","newIssuerId":"intermediateX","days":30}`)
	if code != http.StatusCreated {
		t.Fatalf("rotate: %d", code)
	}
	if res := doVerify(t, h, "leaf-newgen"); res["valid"] != true {
		t.Fatalf("rotated leaf must validate: %v", res["reason"])
	}
}

// The dual-lookback API accepts separate event time and knowledge cutoff,
// and corrected revocations only affect investigations whose cutoff
// includes the correction.
func TestDualLookbackOverHTTP(t *testing.T) {
	_, h := newHarness(t)

	// Baseline investigation of a past event with current knowledge.
	code, base := do(t, h, "POST", "/api/verify",
		`{"leafId":"leaf-ok","purpose":"serverAuth"}`)
	if code != http.StatusOK || base["valid"] != true {
		t.Fatalf("baseline: %d %v", code, base["reason"])
	}
	if base["eventTime"] == nil || base["knowledgeCutoff"] == nil {
		t.Fatal("evidence must record event time and knowledge cutoff")
	}
	chains := base["chains"].([]any)
	ev := chains[0].(map[string]any)["evidence"].([]any)
	if len(ev) == 0 {
		t.Fatal("each path must list the materials its verdict used")
	}

	// Let the lab clock separate sample loading from the revocation so a
	// knowledge cutoff can sit between them.
	time.Sleep(1500 * time.Millisecond)
	beforeRevoke := time.Now().UTC()
	event := beforeRevoke.Format(time.RFC3339)
	cutoff := beforeRevoke.Format(time.RFC3339)

	// Revoke the leaf now, then correct the revocation date backwards.
	if code, _ := do(t, h, "POST", "/api/certs/leaf-ok/revoke", `{}`); code != http.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	past := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	code, _ = do(t, h, "POST", "/api/certs/leaf-ok/correctrevoke",
		`{"revokedAt":"`+past+`"}`)
	if code != http.StatusOK {
		t.Fatalf("correctrevoke: %d", code)
	}

	// Same event moment, knowledge cutoff just before the revocation: the
	// new revocation material must not leak into the old investigation.
	code, old := do(t, h, "POST", "/api/verify", `{"leafId":"leaf-ok","purpose":"serverAuth",`+
		`"eventTime":"`+event+`","knowledgeCutoff":"`+cutoff+`"}`)
	if code != http.StatusOK {
		t.Fatalf("old-knowledge verify: %d", code)
	}
	if old["valid"] != true {
		t.Fatalf("old knowledge must not see the revocation: %v %v", old["valid"], old["reason"])
	}

	// Same event moment, current knowledge: backdated revocation fails it.
	code, cur := do(t, h, "POST", "/api/verify", `{"leafId":"leaf-ok","purpose":"serverAuth",`+
		`"eventTime":"`+event+`"}`)
	if code != http.StatusOK {
		t.Fatalf("current-knowledge verify: %d", code)
	}
	if cur["valid"] != false || cur["status"] != "disqualified" {
		t.Fatalf("backdated revocation must disqualify the event: %v %v", cur["valid"], cur["reason"])
	}

	// History keeps every version, newest first, all immutable.
	req := httptest.NewRequest("GET", "/api/history", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var hist []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &hist); err != nil {
		t.Fatal(err)
	}
	if len(hist) != 3 {
		t.Fatalf("expected 3 evidence versions, got %d", len(hist))
	}
	if hist[2]["valid"] != true {
		t.Fatal("oldest evidence must still show its original conclusion")
	}
}
