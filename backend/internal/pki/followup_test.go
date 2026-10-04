package pki

import (
	"strings"
	"testing"
	"time"
)

// The reported bug: a root trusted when the event happened, distrusted
// later, must not make a later review of that event fail. Trust changes
// take effect at their effective time; the knowledge cutoff only limits
// what is known, not when it applies.
func TestTrustEffectiveTimeNotLearnedTime(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)

	event := t0.Add(time.Hour)
	// Distrust learned and effective 30s after the event.
	*cur = event.Add(30 * time.Second)
	if err := l.SetTrust("r1", false); err != nil {
		t.Fatal(err)
	}
	// Review the event with a knowledge cutoff that includes the distrust
	// and is close enough that the CRL still covers the event.
	res, err := l.VerifyAt("leaf1", EKUServer, nil, event, event.Add(31*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("root trusted at the event time must anchor the event, got %v %q", res.Status, res.Reason)
	}
	// The trust material shows separate effective and learned times.
	var trustRef *MaterialRef
	for i, m := range res.Chains[0].Evidence {
		if m.Type == "trust" {
			trustRef = &res.Chains[0].Evidence[i]
		}
	}
	if trustRef == nil || trustRef.EffectiveAt == nil || trustRef.LearnedAt == nil {
		t.Fatal("trust material must carry effective and learned times")
	}
	if !trustRef.EffectiveAt.Before(event) {
		t.Fatalf("adopted trust decision must be the one effective before the event, got %s", trustRef.EffectiveAt)
	}
}

// A trust change learned now but effective in the future only applies to
// events at or after its effective time.
func TestFutureEffectiveTrustChange(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)

	effective := t0.Add(2 * time.Hour)
	if err := l.ScheduleTrust("r1", false, effective); err != nil {
		t.Fatal(err)
	}

	// The current trust set is unchanged until the effective time.
	if roots := l.TrustedRoots(); len(roots) != 1 || roots[0] != "r1" {
		t.Fatalf("future change must not alter current trust, got %v", roots)
	}
	*cur = effective.Add(time.Minute)
	if roots := l.TrustedRoots(); len(roots) != 0 {
		t.Fatalf("after the effective time the root must be gone, got %v", roots)
	}

	// Event before the effective time, knowledge after the announcement:
	// still trusted.
	before, err := l.VerifyAt("leaf1", EKUServer, nil, t0.Add(time.Hour), t0.Add(61*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if before.Cause == CauseTrust || strings.Contains(before.Reason, "trusted anchor") {
		t.Fatalf("event before the effective time must not see the change, got %q", before.Reason)
	}

	// Event after the effective time: the announced distrust applies.
	after, err := l.VerifyAt("leaf1", EKUServer, nil, effective.Add(30*time.Minute), effective.Add(31*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if after.Valid || after.Cause != CauseTrust {
		t.Fatalf("event after the effective time must fail on trust, got %v %q cause=%q",
			after.Valid, after.Reason, after.Cause)
	}
}

// Late-arriving revocation material: learned now, effective earlier.
func TestLateArrivingRevocationMaterial(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)

	event := t0.Add(time.Hour)
	*cur = t0.Add(3 * time.Hour)
	if err := l.RevokeAt("leaf1", t0.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}

	// Knowledge cutoff before the material arrived: not revoked.
	old, err := l.VerifyAt("leaf1", EKUServer, nil, event, t0.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if old.Cause == CauseRevocation {
		t.Fatalf("cutoff before learning must not see the revocation: %q", old.Reason)
	}

	// Current knowledge: the backdated revocation covers the event.
	now, err := l.VerifyAt("leaf1", EKUServer, nil, event, t0.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if now.Valid || now.Cause != CauseRevocation {
		t.Fatalf("late material with earlier effect must disqualify, got %v %q", now.Valid, now.Reason)
	}
}

// Retracted revocation material: the retraction only affects
// investigations whose cutoff includes it; older reports keep their
// revoked conclusion.
func TestRetractedRevocationMaterial(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)

	*cur = t0.Add(time.Hour)
	if err := l.Revoke("leaf1"); err != nil {
		t.Fatal(err)
	}
	*cur = t0.Add(2 * time.Hour)
	if err := l.RetractRevocation("leaf1", "issued in error"); err != nil {
		t.Fatal(err)
	}

	event := t0.Add(90 * time.Minute)
	before, err := l.VerifyAt("leaf1", EKUServer, nil, event, t0.Add(90*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if before.Valid || before.Cause != CauseRevocation {
		t.Fatalf("cutoff before the retraction must still see the revocation, got %v %q", before.Valid, before.Reason)
	}
	after, err := l.VerifyAt("leaf1", EKUServer, nil, event, t0.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if after.Cause == CauseRevocation {
		t.Fatalf("cutoff including the retraction must clear the revocation, got %q", after.Reason)
	}
	hist := l.History()
	if len(hist) != 2 || hist[1].Valid {
		t.Fatal("the retraction must not rewrite the older report")
	}
}

// Contradictory claims from the same source are reported with the
// adoption basis instead of silently overwriting.
func TestConflictingClaimsExplained(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)

	*cur = t0.Add(time.Hour)
	if err := l.Revoke("leaf1"); err != nil {
		t.Fatal(err)
	}
	*cur = t0.Add(2 * time.Hour)
	if err := l.CorrectRevocation("leaf1", t0.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	res, err := l.VerifyAt("leaf1", EKUServer, nil, t0.Add(2*time.Hour), t0.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ch := range res.Chains {
		for _, m := range ch.Evidence {
			if m.Type == "revocation" && strings.Contains(m.Detail, "相互矛盾") && strings.Contains(m.Detail, "采用") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("conflicting revocation claims must be explained with the adoption basis")
	}
}

// Contradictory trust decisions for the same root are reported with the
// adoption basis instead of silently overwriting.
func TestConflictingTrustExplained(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, _ := clockLab(t, t0)
	buildChain(t, l)
	if err := l.ScheduleTrust("r1", false, t0.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	res2, err := l.VerifyAt("leaf1", EKUServer, nil, t0.Add(2*time.Hour), t0.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	foundTrust := false
	for _, ch := range res2.Chains {
		for _, m := range ch.Evidence {
			if m.Type == "trust" && strings.Contains(m.Detail, "相互矛盾") {
				foundTrust = true
			}
		}
	}
	if !foundTrust {
		t.Fatal("conflicting trust decisions must be explained with the adoption basis")
	}
}

// A saved lab reopens with the same reports and material versions.
func TestPersistRoundTrip(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	if err := LoadSamples(l); err != nil {
		t.Fatal(err)
	}
	*cur = t0.Add(time.Hour)
	if _, err := l.VerifyAt("leaf-ok", EKUServer, nil, t0, t0); err != nil {
		t.Fatal(err)
	}
	if err := l.RevokeAt("leaf-ok", t0.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := l.ScheduleTrust("rootA", false, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.VerifyAt("leaf-ok", EKUServer, nil, t0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	path := t.TempDir() + "/state.json"
	if err := l.Save(path); err != nil {
		t.Fatal(err)
	}
	back, err := LoadLab(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.RulesVersion() != l.RulesVersion() {
		t.Fatalf("rules version not preserved: %d != %d", back.RulesVersion(), l.RulesVersion())
	}
	if len(back.History()) != len(l.History()) {
		t.Fatalf("history not preserved: %d != %d", len(back.History()), len(l.History()))
	}
	if len(back.TrustLog()) != len(l.TrustLog()) {
		t.Fatal("trust log not preserved")
	}
	// Frozen reports are identical right after reopening.
	oldReport := l.History()[1]
	restored := back.History()[1]
	if oldReport.EvidenceID != restored.EvidenceID || oldReport.Valid != restored.Valid ||
		!oldReport.KnowledgeCutoff.Equal(restored.KnowledgeCutoff) {
		t.Fatal("reopened reports must match the saved versions")
	}
	// The restored lab still verifies with its real keys and CRLs.
	back.SetClock(func() time.Time { return t0.Add(time.Hour) })
	res, err := back.VerifyAt("leaf-rotated", EKUServer, nil, t0.Add(time.Hour), t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("restored lab must verify leaf-rotated: %s", res.Reason)
	}
}
