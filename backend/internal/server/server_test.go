package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
