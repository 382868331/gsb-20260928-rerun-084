package pki

import (
	"strings"
	"testing"
)

func freshSampleLab(t *testing.T) *Lab {
	t.Helper()
	l := NewLab()
	if err := LoadSamples(l); err != nil {
		t.Fatalf("LoadSamples: %v", err)
	}
	return l
}

// The cross-signed leaf validates, and verification must report which path
// was actually selected.
func TestCrossSignedLeafSelectsATrustedPath(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-ok", EKUServer)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("expected valid cross-signed chain, got: %s", res.Reason)
	}
	if len(res.Chains) < 2 {
		t.Fatalf("expected old+new candidate paths, got %d", len(res.Chains))
	}
	valid := 0
	for _, ch := range res.Chains {
		if ch.Valid {
			valid++
		}
	}
	if valid != 2 {
		t.Fatalf("expected both cross paths valid, got %d/%d", valid, len(res.Chains))
	}
	if len(res.SelectedPath) == 0 {
		t.Fatal("selected path not reported")
	}
	root := res.SelectedPath[0]
	if root != "rootA" && root != "rootB" {
		t.Fatalf("selected path must end at a trusted root, got %v", res.SelectedPath)
	}
}

// Rotation issues a new generation; both generations verify independently.
func TestRotationKeepsOldEvidence(t *testing.T) {
	l := freshSampleLab(t)
	if _, err := l.Verify("leaf-ok", EKUServer); err != nil {
		t.Fatal(err)
	}
	old, ok := l.Get("leaf-rotated")
	if !ok {
		t.Fatal("rotated leaf missing")
	}
	if old.Cert.SerialNumber == nil {
		t.Fatal("rotated leaf has no serial")
	}
	if orig, _ := l.Get("leaf-ok"); orig.Cert.SerialNumber.Cmp(old.Cert.SerialNumber) == 0 {
		t.Fatal("rotation must produce a new certificate/serial")
	}
	if _, err := l.Verify("leaf-rotated", EKUServer); err != nil {
		t.Fatal(err)
	}
}

// An expired intermediate must fail even though the leaf signature itself is
// correct and the root is trusted.
func TestExpiredIntermediateFails(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-expired", EKUServer)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("expired-intermediate path must not validate")
	}
	if !strings.Contains(strings.ToLower(res.Reason), "expired") {
		t.Fatalf("expected expiry reason, got %q", res.Reason)
	}
	for _, ch := range res.Chains {
		last := ch.Path[len(ch.Path)-1]
		_ = last
		if ch.Valid {
			t.Fatal("no path through an expired intermediate may be valid")
		}
	}
}

// Missing revocation data must fail despite correct signatures/periods.
func TestMissingCRLFails(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-nocrl", EKUServer)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("path with missing revocation data must not be reported as valid")
	}
	if !res.Unknown {
		t.Fatal("missing CRL must be reported as unknown rather than deterministic revocation failure")
	}
	if !strings.Contains(strings.ToLower(res.Reason), "cannot be determined") {
		t.Fatalf("expected undetermined revocation reason, got %q", res.Reason)
	}
}

func TestRestoringRevocationDataDoesNotRewriteEvidence(t *testing.T) {
	l := freshSampleLab(t)
	before, err := l.Verify("leaf-nocrl", EKUServer)
	if err != nil {
		t.Fatal(err)
	}
	if before.Valid || !before.Unknown {
		t.Fatalf("initial result should be undetermined, valid=%v unknown=%v", before.Valid, before.Unknown)
	}
	if err := l.SetCRLPublished("silent-im", true); err != nil {
		t.Fatal(err)
	}
	after, err := l.Verify("leaf-nocrl", EKUServer)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Valid {
		t.Fatalf("after CRL publication is restored, path should validate: %s", after.Reason)
	}
	hist := l.History()
	older := hist[1]
	if older.Valid || !older.Unknown {
		t.Fatalf("old evidence was rewritten: valid=%v unknown=%v", older.Valid, older.Unknown)
	}
	if older.Chains[0].Path[1].CRLPublished {
		t.Fatal("old path snapshot must retain missing-CRL state")
	}
}

// Revoked leaf is rejected from a freshly generated CRL.
func TestRevokedLeafFails(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-revoked", EKUServer)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("revoked leaf must not validate")
	}
	if !strings.Contains(strings.ToLower(res.Reason), "revok") {
		t.Fatalf("expected revocation reason, got %q", res.Reason)
	}
}

// Purpose mismatch must fail.
func TestPurposeMismatchFails(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-expired", EKUClient)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("clientAuth use of a serverAuth-only leaf must fail")
	}
}

// Trust-rule change re-verification appends new evidence without overwriting
// the old result, and rules version changes with the trust edit.
func TestTrustChangeKeepsEvidenceHistory(t *testing.T) {
	l := freshSampleLab(t)
	before, err := l.Verify("leaf-ok", EKUServer)
	if err != nil {
		t.Fatal(err)
	}
	if !before.Valid {
		t.Fatalf("precondition: expected valid, %s", before.Reason)
	}
	v0 := l.RulesVersion()
	if err := l.SetTrust("rootA", false); err != nil {
		t.Fatal(err)
	}
	if err := l.SetTrust("rootB", false); err != nil {
		t.Fatal(err)
	}
	if l.RulesVersion() == v0 {
		t.Fatal("trust edit must bump rules version")
	}
	after, err := l.Verify("leaf-ok", EKUServer)
	if err != nil {
		t.Fatal(err)
	}
	if after.Valid {
		t.Fatal("no trusted anchor: verification must fail")
	}
	hist := l.History()
	if len(hist) != 2 {
		t.Fatalf("expected 2 immutable evidence records, got %d", len(hist))
	}
	// Newest first; the old record must still show valid=true.
	if !hist[1].Valid || hist[0].Valid {
		t.Fatal("new verification must not overwrite the old evidence")
	}
	if hist[0].EvidenceID == hist[1].EvidenceID {
		t.Fatal("evidence ids must be unique")
	}
}

// Cut-over: distrust old root; the cross-signed leaf still validates via B.
func TestRootCutoverUsesNewPath(t *testing.T) {
	l := freshSampleLab(t)
	if err := l.SetTrust("rootA", false); err != nil {
		t.Fatal(err)
	}
	res, err := l.Verify("leaf-ok", EKUServer)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("leaf must validate via new root after cut-over: %s", res.Reason)
	}
	if got := res.SelectedPath[0]; got != "rootB" {
		t.Fatalf("expected path via rootB, got %v", res.SelectedPath)
	}
}
