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
	res, err := l.Verify("leaf-ok", EKUServer, nil)
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
	if _, err := l.Verify("leaf-ok", EKUServer, nil); err != nil {
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
	if _, err := l.Verify("leaf-rotated", EKUServer, nil); err != nil {
		t.Fatal(err)
	}
}

// An expired intermediate must fail even though the leaf signature itself is
// correct and the root is trusted.
func TestExpiredIntermediateFails(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-expired", EKUServer, nil)
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
	res, err := l.Verify("leaf-nocrl", EKUServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("path with missing revocation data must not validate")
	}
	if !strings.Contains(strings.ToLower(res.Reason), "revocation data missing") {
		t.Fatalf("expected missing revocation data reason, got %q", res.Reason)
	}
}

// Revoked leaf is rejected from a freshly generated CRL.
func TestRevokedLeafFails(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-revoked", EKUServer, nil)
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
	res, err := l.Verify("leaf-expired", EKUClient, nil)
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
	before, err := l.Verify("leaf-ok", EKUServer, nil)
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
	after, err := l.Verify("leaf-ok", EKUServer, nil)
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
	res, err := l.Verify("leaf-ok", EKUServer, nil)
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

// Missing revocation data alone does not disqualify: the result stays
// undetermined and the chain is marked as lacking evidence.
func TestMissingCRLIsUndeterminedNotDisqualified(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-nocrl", EKUServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid || res.Status != StatusUndetermined {
		t.Fatalf("expected undetermined result, got valid=%v status=%q", res.Valid, res.Status)
	}
	for _, ch := range res.Chains {
		if ch.Status != StatusUndetermined {
			t.Fatalf("expected undetermined chain, got %q (%s)", ch.Status, ch.Reason)
		}
	}
}

// A policy requiring complete CRLs turns undetermined paths into
// disqualified ones, and the policy is recorded in the evidence.
func TestRequireCRLPolicyDisqualifies(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-nocrl", EKUServer, &Policy{RequireCRL: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid || res.Status != StatusDisqualified {
		t.Fatalf("expected disqualified result, got valid=%v status=%q", res.Valid, res.Status)
	}
	if res.Policy == nil || !res.Policy.RequireCRL {
		t.Fatal("evidence must record the policy it was produced under")
	}
}

// Preferred roots steer which valid path is adopted; both candidates stay
// visible in the evidence.
func TestPreferredRootsSteerSelection(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-ok", EKUServer, &Policy{PreferredRoots: []string{"rootB"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("expected valid, got %s", res.Reason)
	}
	if got := res.SelectedPath[0]; got != "rootB" {
		t.Fatalf("preferred rootB must be adopted, got %v", res.SelectedPath)
	}
	if len(res.Chains) < 2 {
		t.Fatal("excluded candidate paths must remain visible")
	}
}

// Allowed roots scope the experiment: paths ending elsewhere are excluded
// with an explicit reason while in-scope paths still validate.
func TestAllowedRootsScopeSelection(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-ok", EKUServer, &Policy{AllowedRoots: []string{"rootB"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid || res.SelectedPath[0] != "rootB" {
		t.Fatalf("expected valid via rootB, got valid=%v path=%v", res.Valid, res.SelectedPath)
	}
	excluded := 0
	for _, ch := range res.Chains {
		if ch.Status == StatusDisqualified && strings.Contains(ch.Reason, "allowed roots") {
			excluded++
		}
	}
	if excluded == 0 {
		t.Fatal("out-of-scope root path must be reported as excluded")
	}
}

// The cross-signing loop terminates and leaf-loop still reaches a root.
func TestCrossSignLoopEnumerates(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-loop", EKUServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("loop scenario must validate, got %s", res.Reason)
	}
	roots := map[string]bool{}
	for _, ch := range res.Chains {
		roots[ch.Path[0].ID] = true
	}
	if !roots["rootE"] || !roots["rootF"] {
		t.Fatalf("expected candidates reaching both loop roots, got %v", roots)
	}
}

// Late revocation material keeps the result undetermined; once the delay
// is cleared the same leaf validates, and both evidences are preserved.
func TestLateCRLUndeterminedThenValid(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-late", EKUServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid || res.Status != StatusUndetermined {
		t.Fatalf("expected undetermined for late CRL, got valid=%v status=%q", res.Valid, res.Status)
	}
	if !strings.Contains(res.Reason, "late CRL") {
		t.Fatalf("expected late-CRL reason, got %q", res.Reason)
	}
	if err := l.SetCRLDelay("tardy-im", 0); err != nil {
		t.Fatal(err)
	}
	res2, err := l.Verify("leaf-late", EKUServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Valid {
		t.Fatalf("expected valid once CRL effective, got %s", res2.Reason)
	}
	hist := l.History()
	if len(hist) != 2 || hist[1].Status != StatusUndetermined {
		t.Fatal("original undetermined evidence must be preserved")
	}
}
