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

func verify(t *testing.T, l *Lab, leaf string, purpose EKU) *VerifyResult {
	t.Helper()
	res, err := l.Verify(leaf, purpose, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// The cross-signed leaf validates, and verification must report which path
// was actually selected.
func TestCrossSignedLeafSelectsATrustedPath(t *testing.T) {
	l := freshSampleLab(t)
	res := verify(t, l, "leaf-ok", EKUServer)
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
	if res.Conclusion != "valid" {
		t.Fatalf("expected conclusion valid, got %q", res.Conclusion)
	}
	// Exactly one path is adopted; the other stays visible as a candidate.
	var selected, candidate int
	for _, ch := range res.Chains {
		switch ch.Decision {
		case DecisionSelected:
			selected++
		case DecisionCandidate:
			candidate++
		}
	}
	if selected != 1 || candidate != 1 {
		t.Fatalf("expected 1 selected + 1 candidate path, got %d/%d", selected, candidate)
	}
}

// Rotation issues a new generation; both generations verify independently.
func TestRotationKeepsOldEvidence(t *testing.T) {
	l := freshSampleLab(t)
	verify(t, l, "leaf-ok", EKUServer)
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
	verify(t, l, "leaf-rotated", EKUServer)
}

// An expired intermediate must fail even though the leaf signature itself is
// correct and the root is trusted.
func TestExpiredIntermediateFails(t *testing.T) {
	l := freshSampleLab(t)
	res := verify(t, l, "leaf-expired", EKUServer)
	if res.Valid {
		t.Fatal("expired-intermediate path must not validate")
	}
	if res.Conclusion != "invalid" {
		t.Fatalf("expired path is definitively ineligible, got %q", res.Conclusion)
	}
	if !strings.Contains(strings.ToLower(res.Reason), "expired") {
		t.Fatalf("expected expiry reason, got %q", res.Reason)
	}
	for _, ch := range res.Chains {
		if ch.Valid {
			t.Fatal("no path through an expired intermediate may be valid")
		}
		if ch.Decision != DecisionInvalid {
			t.Fatalf("expired path must be marked invalid, got %q", ch.Decision)
		}
	}
}

// Missing revocation data makes the path undecidable, not definitively
// invalid: the conclusion is "unknown" and the evidence keeps the reason.
func TestMissingCRLIsUnknown(t *testing.T) {
	l := freshSampleLab(t)
	res := verify(t, l, "leaf-nocrl", EKUServer)
	if res.Valid {
		t.Fatal("path with missing revocation data must not validate")
	}
	if res.Conclusion != "unknown" {
		t.Fatalf("expected unknown conclusion, got %q", res.Conclusion)
	}
	if !strings.Contains(strings.ToLower(res.Reason), "revocation data missing") {
		t.Fatalf("expected missing revocation data reason, got %q", res.Reason)
	}
	for _, ch := range res.Chains {
		if ch.Decision != DecisionUnknown || ch.Status != ChainUnknown {
			t.Fatalf("expected unknown chain, got %q/%q", ch.Decision, ch.Status)
		}
	}
}

// A policy may require complete revocation data; then a path that would be
// "unknown" becomes definitively ineligible for this experiment.
func TestRequireCRLPolicyTurnsUnknownIntoInvalid(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-nocrl", EKUServer, &Policy{RequireCRL: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Conclusion != "invalid" {
		t.Fatalf("expected invalid under RequireCRL, got %q", res.Conclusion)
	}
	if res.Policy == nil || !res.Policy.RequireCRL {
		t.Fatal("evidence must keep the policy snapshot")
	}
}

// Revoked leaf is rejected from a freshly generated CRL.
func TestRevokedLeafFails(t *testing.T) {
	l := freshSampleLab(t)
	res := verify(t, l, "leaf-revoked", EKUServer)
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
	res := verify(t, l, "leaf-expired", EKUClient)
	if res.Valid {
		t.Fatal("clientAuth use of a serverAuth-only leaf must fail")
	}
}

// Trust-rule change re-verification appends new evidence without overwriting
// the old result, and rules version changes with the trust edit.
func TestTrustChangeKeepsEvidenceHistory(t *testing.T) {
	l := freshSampleLab(t)
	before := verify(t, l, "leaf-ok", EKUServer)
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
	after := verify(t, l, "leaf-ok", EKUServer)
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
	res := verify(t, l, "leaf-ok", EKUServer)
	if !res.Valid {
		t.Fatalf("leaf must validate via new root after cut-over: %s", res.Reason)
	}
	if got := res.SelectedPath[0]; got != "rootB" {
		t.Fatalf("expected path via rootB, got %v", res.SelectedPath)
	}
}

// Root priority decides which of several eligible paths is adopted, and the
// evidence keeps the policy snapshot plus the selection rationale.
func TestRootPriorityChangesSelection(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-ok", EKUServer, &Policy{RootPriority: []string{"rootB", "rootA"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid || res.SelectedPath[0] != "rootB" {
		t.Fatalf("priority rootB must be adopted, got %v", res.SelectedPath)
	}
	if res.SelectionReason == "" {
		t.Fatal("selection rationale must be recorded")
	}
	if res.Policy == nil || len(res.Policy.RootPriority) != 2 {
		t.Fatal("policy snapshot missing from evidence")
	}
	// The non-adopted valid path stays visible as a candidate.
	var sawCandidate bool
	for _, ch := range res.Chains {
		if ch.Decision == DecisionCandidate && ch.Path[0].ID == "rootA" {
			sawCandidate = true
		}
	}
	if !sawCandidate {
		t.Fatal("rootA path must remain visible as a non-adopted candidate")
	}

	// Flipping the preference flips the adopted path; the conclusion stays.
	res2, err := l.Verify("leaf-ok", EKUServer, &Policy{RootPriority: []string{"rootA", "rootB"}})
	if err != nil {
		t.Fatal(err)
	}
	if res2.SelectedPath[0] != "rootA" || !res2.Valid {
		t.Fatalf("flipped priority must adopt rootA, got %v", res2.SelectedPath)
	}
	hist := l.History()
	if len(hist) != 2 || hist[1].SelectedPath[0] != "rootB" {
		t.Fatal("earlier evidence must keep its original selection")
	}
}

// AllowedRoots scopes the experiment: paths outside the scope are excluded
// by policy (distinct from definitively ineligible).
func TestAllowedRootsExcludesOutOfScopePaths(t *testing.T) {
	l := freshSampleLab(t)
	res, err := l.Verify("leaf-ok", EKUServer, &Policy{AllowedRoots: []string{"rootB"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid || res.SelectedPath[0] != "rootB" {
		t.Fatalf("only rootB in scope, got %v", res.SelectedPath)
	}
	var excluded int
	for _, ch := range res.Chains {
		if ch.Decision == DecisionExcluded {
			excluded++
			if ch.Path[0].ID != "rootA" {
				t.Fatalf("wrong path excluded: %v", ch.Path[0].ID)
			}
		}
	}
	if excluded != 1 {
		t.Fatalf("expected 1 policy-excluded path, got %d", excluded)
	}
}

// An incomplete path never blocks the independent judgment of a complete
// one: leaf-loop has one valid path (via rootE) and one undecidable path
// (via imF, whose revocation data has not arrived).
func TestIncompletePathDoesNotBlockCompletePath(t *testing.T) {
	l := freshSampleLab(t)
	res := verify(t, l, "leaf-loop", EKUServer)
	if !res.Valid || res.Conclusion != "valid" {
		t.Fatalf("complete path must be judged independently: %s", res.Reason)
	}
	if res.SelectedPath[0] != "rootE" {
		t.Fatalf("expected adoption of the complete rootE path, got %v", res.SelectedPath)
	}
	var unknown int
	for _, ch := range res.Chains {
		if ch.Decision == DecisionUnknown {
			unknown++
		}
	}
	if unknown == 0 {
		t.Fatal("the imF path must be reported as undecidable")
	}
}

// The cross-signing loop must terminate enumeration instead of hanging, and
// the long looping branch (through both cross certificates) must stay
// visible among the candidates instead of being hidden.
func TestCrossSigningLoopTerminates(t *testing.T) {
	l := freshSampleLab(t)
	res := verify(t, l, "leaf-loop", EKUServer)
	if len(res.Chains) != 3 {
		t.Fatalf("expected 3 candidate paths (short, cross, loop), got %d", len(res.Chains))
	}
	var loopPath bool
	for _, ch := range res.Chains {
		if len(ch.Path) == 5 {
			loopPath = true
			if ch.Decision == DecisionSelected {
				t.Fatal("the long loop path must not be preferred over the short path")
			}
		}
	}
	if !loopPath {
		t.Fatal("expected the looping branch to appear as a candidate path")
	}
}

// Root withdrawal plus late-arriving revocation data: after rootE is
// withdrawn, the only remaining complete path depends on imF, whose CRL has
// not arrived, so the conclusion stays unknown; once the late CRL material
// is published, a fresh verification becomes valid while old evidence is
// untouched.
func TestRootWithdrawalAndLateCRL(t *testing.T) {
	l := freshSampleLab(t)
	before := verify(t, l, "leaf-loop", EKUServer)
	if !before.Valid {
		t.Fatalf("precondition: %s", before.Reason)
	}
	if err := l.SetTrust("rootE", false); err != nil {
		t.Fatal(err)
	}
	pending := verify(t, l, "leaf-loop", EKUServer)
	if pending.Valid || pending.Conclusion != "unknown" {
		t.Fatalf("expected unknown while revocation data is late, got %q", pending.Conclusion)
	}
	// Late revocation material arrives.
	if err := l.SetCRLPublished("imF", true); err != nil {
		t.Fatal(err)
	}
	after := verify(t, l, "leaf-loop", EKUServer)
	if !after.Valid || after.SelectedPath[0] != "rootF" {
		t.Fatalf("expected valid via rootF after late CRL, got %v (%s)", after.SelectedPath, after.Reason)
	}
	hist := l.History()
	if len(hist) != 3 {
		t.Fatalf("expected 3 evidence records, got %d", len(hist))
	}
	// Newest first; the unknown verdict from before the CRL arrived and the
	// original valid verdict must both be preserved unchanged.
	if hist[1].Conclusion != "unknown" || !hist[2].Valid {
		t.Fatal("historical evidence must not be rewritten")
	}
	if hist[1].RulesVersion == hist[0].RulesVersion {
		t.Fatal("CRL publication change must bump the rules version")
	}
}

// When every path lacks evidence, the undecidable part is preserved rather
// than collapsed into a hard failure.
func TestAllPathsUnknownStaysUnknown(t *testing.T) {
	l := freshSampleLab(t)
	if err := l.SetCRLPublished("imE", false); err != nil {
		t.Fatal(err)
	}
	res := verify(t, l, "leaf-loop", EKUServer)
	if res.Valid || res.Conclusion != "unknown" {
		t.Fatalf("expected unknown, got %q", res.Conclusion)
	}
	if res.Reason == "" {
		t.Fatal("the undecidable reasons must be preserved")
	}
}
