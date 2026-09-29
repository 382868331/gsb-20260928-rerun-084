package lab

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestServer(t *testing.T) (*API, http.Handler) {
	t.Helper()
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	a := NewAPI(s)
	return a, a.Handler()
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code >= 400 {
		t.Fatalf("%s %s -> %d %s", method, path, rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

func TestHTTPEndToEnd(t *testing.T) {
	_, h := newTestServer(t)
	st := doJSON(t, h, "GET", "/api/state", nil)
	certs := st["certs"].(map[string]any)
	var oldRoot, newRoot, serverLeaf string
	for _, v := range certs {
		cm := v.(map[string]any)
		switch cm["subject"] {
		case "Lab Root Old":
			if cm["issuerId"] == nil {
				oldRoot = cm["id"].(string)
			}
		case "Lab Root New":
			if cm["issuerId"] == nil {
				newRoot = cm["id"].(string)
			}
		case "api.lab.test":
			serverLeaf = cm["id"].(string)
		}
		// Key location must never leave the backend.
		if _, leak := cm["KeyFile"]; leak {
			t.Fatalf("KeyFile leaked in JSON")
		}
		if _, leak := cm["keyFile"]; leak {
			t.Fatalf("keyFile leaked in JSON")
		}
	}
	if oldRoot == "" || newRoot == "" || serverLeaf == "" {
		t.Fatal("missing bootstrap certs")
	}

	ok := doJSON(t, h, "POST", "/api/verify", map[string]any{
		"leafCertId": serverLeaf, "purpose": "serverAuth", "trustRoots": []string{oldRoot, newRoot},
	})
	if ok["valid"] != true {
		t.Fatalf("verify should pass under both roots: %v", ok)
	}

	// Purpose mismatch fails.
	mismatch := doJSON(t, h, "POST", "/api/verify", map[string]any{
		"leafCertId": serverLeaf, "purpose": "clientAuth", "trustRoots": []string{oldRoot},
	})
	if mismatch["valid"] != false {
		t.Fatal("purpose mismatch must fail")
	}

	// No trust anchor fails.
	noTrust := doJSON(t, h, "POST", "/api/verify", map[string]any{
		"leafCertId": serverLeaf, "purpose": "serverAuth", "trustRoots": []string{},
	})
	if noTrust["valid"] != false {
		t.Fatal("missing trust anchor must fail")
	}

	// Revocation immediately invalidates, even though an earlier verdict passed.
	doJSON(t, h, "POST", "/api/revoke", map[string]any{"certId": serverLeaf, "reason": "hold"})
	after := doJSON(t, h, "POST", "/api/verify", map[string]any{
		"leafCertId": serverLeaf, "purpose": "serverAuth", "trustRoots": []string{oldRoot, newRoot},
	})
	if after["valid"] != false {
		t.Fatal("revoked cert must not validate")
	}
}

func TestHTTPIssueRotation(t *testing.T) {
	_, h := newTestServer(t)
	st := doJSON(t, h, "GET", "/api/state", nil)
	var interEntity string
	for _, v := range st["entities"].(map[string]any) {
		em := v.(map[string]any)
		if em["name"] == "Lab Intermediate Alpha" {
			interEntity = em["id"].(string)
		}
	}

	// Issue a brand new leaf.
	created := doJSON(t, h, "POST", "/api/issue", map[string]any{
		"name": "svc-rotated.lab.test", "kind": "leaf", "issuerId": interEntity,
		"ekus": []string{"serverAuth"}, "ttlDays": 30,
	})
	c1 := created["cert"].(map[string]any)
	if c1["version"].(float64) != 1 {
		t.Fatalf("first version = %v", c1["version"])
	}

	// Issuing again to the same subject rotates to version 2.
	rot := doJSON(t, h, "POST", "/api/issue", map[string]any{
		"name": "svc-rotated.lab.test", "kind": "leaf", "issuerId": interEntity,
		"ekus": []string{"serverAuth", "clientAuth"}, "ttlDays": 10,
	})
	c2 := rot["cert"].(map[string]any)
	if c2["version"].(float64) != 2 {
		t.Fatalf("rotated version = %v, want 2", c2["version"])
	}
	if c1["id"] == c2["id"] {
		t.Fatal("rotation must mint a new certificate id")
	}

	// Bad request: leaf without issuer.
	req := httptest.NewRequest("POST", "/api/issue", bytes.NewReader([]byte(`{"name":"x","kind":"leaf"}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}
