package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"certlab/internal/pki"
)

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	lab := pki.NewLab()
	if err := pki.SeedScenarios(lab); err != nil {
		t.Fatal(err)
	}
	ev, err := pki.NewEvidenceStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(lab, ev, nil).Routes()
}

func call(t *testing.T, h http.Handler, method, path string, body any) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	if rw.Code >= 400 {
		t.Fatalf("%s %s -> %d: %s", method, path, rw.Code, rw.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rw.Body.Bytes(), &out)
	return out
}

func TestAPIEndToEnd(t *testing.T) {
	h := newTestHandler(t)

	// cross-signed leaf: valid, two chains reported.
	res := call(t, h, "POST", "/api/verify", map[string]string{"leafId": "leaf-cross", "purpose": "serverAuth", "note": "基线"})
	result := res["result"].(map[string]any)
	if result["valid"] != true {
		t.Fatalf("cross leaf should verify: %v", result["reason"])
	}
	if len(result["chains"].([]any)) != 2 {
		t.Fatalf("want 2 chains, got %v", result["chains"])
	}

	// expired intermediate -> fail
	res = call(t, h, "POST", "/api/verify", map[string]string{"leafId": "leaf-expired", "purpose": "serverAuth"})
	if res["result"].(map[string]any)["valid"] != false {
		t.Fatal("expired chain must fail")
	}

	// missing CRL -> fail
	res = call(t, h, "POST", "/api/verify", map[string]string{"leafId": "leaf-nocrl", "purpose": "serverAuth"})
	if res["result"].(map[string]any)["valid"] != false {
		t.Fatal("missing CRL chain must fail")
	}

	// purpose mismatch: clientAuth on a serverAuth-only leaf -> fail
	res = call(t, h, "POST", "/api/verify", map[string]string{"leafId": "leaf-cross", "purpose": "clientAuth"})
	if res["result"].(map[string]any)["valid"] != false {
		t.Fatal("wrong purpose must fail")
	}

	// rotation
	rot := call(t, h, "POST", "/api/leaves/rotate", map[string]string{"oldId": "leaf-cross", "newId": "leaf-cross-v2"})
	if rot["new"] == nil {
		t.Fatal("rotation failed")
	}
	res = call(t, h, "POST", "/api/verify", map[string]string{"leafId": "leaf-cross-v2", "purpose": "serverAuth"})
	if res["result"].(map[string]any)["valid"] != true {
		t.Fatal("rotated leaf must verify")
	}

	// distrust old root, revoke intermediate: re-verify appends new evidence.
	call(t, h, "POST", "/api/trust", map[string]any{"rootId": "root-old", "trust": false})
	call(t, h, "POST", "/api/trust", map[string]any{"rootId": "root-new", "trust": false})
	res = call(t, h, "POST", "/api/verify", map[string]string{"leafId": "leaf-cross-v2", "purpose": "serverAuth", "note": "双根取消信任后复检"})
	if res["result"].(map[string]any)["valid"] != false {
		t.Fatal("no trusted anchor must fail")
	}

	// evidence history: baseline + expired + nocrl + purpose + rotated + recheck = 6
	ev := call(t, h, "GET", "/api/evidence", nil)
	recs := ev["evidence"].([]any)
	if len(recs) != 6 {
		t.Fatalf("want 6 immutable evidence records, got %d", len(recs))
	}
	first := recs[0].(map[string]any)
	if first["note"] != "基线" {
		t.Fatalf("old evidence must be preserved, got %v", first["note"])
	}

	// CRL endpoint for a normal CA works; blocked CA errors.
	req := httptest.NewRequest("GET", "/api/crl/int-mig", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("CRL expected 200, got %d", rw.Code)
	}
	req = httptest.NewRequest("GET", "/api/crl/int-nocrl", nil)
	rw = httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	if rw.Code != 400 {
		t.Fatalf("blocked CRL expected 400, got %d", rw.Code)
	}
}
