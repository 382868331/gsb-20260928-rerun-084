package pki

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// clockLab returns a lab whose clock is steered by the returned setter.
func clockLab(t *testing.T, start time.Time) (*Lab, *time.Time) {
	t.Helper()
	l := NewLab()
	cur := new(time.Time)
	*cur = start
	l.SetClock(func() time.Time { return *cur })
	return l, cur
}

func buildChain(t *testing.T, l *Lab) {
	t.Helper()
	if _, err := l.AddRoot("r1", "Root One", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := l.AddIntermediate("im1", "Intermediate One", "r1", "", 5); err != nil {
		t.Fatal(err)
	}
	if _, err := l.AddLeaf("leaf1", "lookback.lab.example", "im1",
		[]EKU{EKUServer}, []string{"lookback.lab.example"}, 90); err != nil {
		t.Fatal(err)
	}
}

// A revocation learned late but effective earlier must fail the event-time
// check only in investigations whose knowledge cutoff includes it. The
// earlier investigation stays reproducible with its then-current knowledge.
func TestLateLearnedRevocationDualLookback(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)

	event := t0.Add(2 * time.Hour)
	learned := event.Add(-10 * time.Minute)
	*cur = learned
	if err := l.Revoke("leaf1"); err != nil {
		t.Fatal(err)
	}

	// Version 1: cutoff before the revocation was learned -> not revoked.
	old, err := l.VerifyAt("leaf1", EKUServer, nil, event, learned.Add(-20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !old.Valid {
		t.Fatalf("cutoff before learning must not see the revocation: %s", old.Reason)
	}

	// Version 2: same event time, cutoff after learning -> revoked.
	*cur = learned.Add(time.Hour)
	now2, err := l.VerifyAt("leaf1", EKUServer, nil, event, learned.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if now2.Valid || now2.Status != StatusDisqualified {
		t.Fatalf("expected disqualified once revocation is known, got %v %q", now2.Valid, now2.Status)
	}
	if !strings.Contains(now2.Reason, "revoked with effect") {
		t.Fatalf("expected effective-time revocation reason, got %q", now2.Reason)
	}

	// The saved old version still reproduces the then-current conclusion.
	hist := l.History()
	if len(hist) != 2 || !hist[1].Valid || hist[0].Valid {
		t.Fatal("new knowledge must not overwrite the saved investigation")
	}
}

// Correcting a revocation date appends a new claim; investigations before
// and after the correction reach different conclusions for the same event.
func TestCorrectedRevocationDate(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)

	t5 := t0.Add(5 * time.Hour)
	*cur = t5
	if err := l.Revoke("leaf1"); err != nil {
		t.Fatal(err)
	}
	t6 := t0.Add(6 * time.Hour)
	*cur = t6
	// Correction: the certificate was actually revoked one hour after t0.
	if err := l.CorrectRevocation("leaf1", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Event 30s before the originally claimed revocation time.
	event := t5.Add(-30 * time.Second)

	// Cutoff between original claim and correction: effective time is t5,
	// after the event, so the certificate counts as not revoked then.
	before, err := l.VerifyAt("leaf1", EKUServer, nil, event, t5.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !before.Valid {
		t.Fatalf("original claim does not cover the event: %s", before.Reason)
	}

	// Cutoff after the correction: effective time moved before the event.
	after, err := l.VerifyAt("leaf1", EKUServer, nil, event, t6.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if after.Valid || after.Status != StatusDisqualified {
		t.Fatalf("corrected revocation must disqualify the event, got %v %q", after.Valid, after.Status)
	}

	// Both revocation claims remain visible on the certificate.
	c, _ := l.Get("leaf1")
	if len(c.Revocations) != 2 {
		t.Fatalf("expected 2 revocation records, got %d", len(c.Revocations))
	}
}

// Trust decisions carry separate effective and learned times: a distrust
// that became effective after the event must not poison a later review of
// that event, even when the knowledge cutoff includes the distrust. Only
// an event after the distrust took effect is disqualified.
func TestTrustEvaluatedAtEventTime(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)

	event := t0.Add(time.Hour)
	// The distrust is learned (and effective) 30s after the event.
	distrustAt := event.Add(30 * time.Second)
	*cur = distrustAt
	if err := l.SetTrust("r1", false); err != nil {
		t.Fatal(err)
	}

	// Cutoff before the distrust was learned: trusted.
	whileTrusted, err := l.VerifyAt("leaf1", EKUServer, nil, event, event.Add(15*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !whileTrusted.Valid {
		t.Fatalf("cutoff before distrust must still validate: %s", whileTrusted.Reason)
	}

	// Cutoff after the distrust was learned, but the event predates its
	// effective time: the later knowledge must not change the verdict.
	review, err := l.VerifyAt("leaf1", EKUServer, nil, event, distrustAt.Add(15*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !review.Valid {
		t.Fatalf("distrust effective after the event must not disqualify it, got %v %q",
			review.Valid, review.Reason)
	}

	// An event after the distrust took effect is disqualified, with a
	// distinct trust reason (not missing evidence).
	laterEvent := distrustAt.Add(30 * time.Second)
	afterDistrust, err := l.VerifyAt("leaf1", EKUServer, nil, laterEvent, distrustAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if afterDistrust.Valid || afterDistrust.Status != StatusDisqualified {
		t.Fatalf("expected disqualified after distrust, got %v %q", afterDistrust.Valid, afterDistrust.Status)
	}
	if !strings.Contains(afterDistrust.Reason, "not a trusted anchor at the event time") {
		t.Fatalf("expected event-time trust reason, got %q", afterDistrust.Reason)
	}
}

// A trust decision learned early but only effective in the future does not
// apply to events before its effective time, even when the knowledge
// cutoff already includes the decision.
func TestFutureEffectiveTrustLearnedEarly(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)

	// Learn now that the root will be distrusted in two hours.
	effective := t0.Add(2 * time.Hour)
	if err := l.SetTrustAt("r1", false, effective); err != nil {
		t.Fatal(err)
	}
	cutoff := t0.Add(30 * time.Minute)

	// Event before the scheduled distrust: still trusted.
	before, err := l.VerifyAt("leaf1", EKUServer, nil, t0.Add(time.Hour), cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if !before.Valid {
		t.Fatalf("future-effective distrust must not apply yet: %s", before.Reason)
	}

	// Event after the scheduled distrust: disqualified, same cutoff.
	*cur = t0.Add(3 * time.Hour)
	after, err := l.VerifyAt("leaf1", EKUServer, nil, effective.Add(30*time.Minute), t0.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if after.Valid || after.Status != StatusDisqualified {
		t.Fatalf("expected disqualified once the distrust is effective, got %v %q", after.Valid, after.Status)
	}
}

// Late-arriving revocation material: the lab learns today that the
// certificate was revoked with effect before the event. Investigations
// with an earlier cutoff stay reproducible; new ones see the backdate.
func TestLateArrivingRevocationMaterial(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)

	event := t0.Add(time.Hour)
	// The revocation material arrives an hour after the event but is
	// effective 30 minutes before it.
	*cur = event.Add(time.Hour)
	if err := l.RevokeAt("leaf1", event.Add(-30*time.Minute)); err != nil {
		t.Fatal(err)
	}

	old, err := l.VerifyAt("leaf1", EKUServer, nil, event, event.Add(15*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !old.Valid {
		t.Fatalf("cutoff before the material arrived must not see it: %s", old.Reason)
	}

	review, err := l.VerifyAt("leaf1", EKUServer, nil, event, event.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if review.Valid || review.Status != StatusDisqualified {
		t.Fatalf("backdated revocation must disqualify the event, got %v %q", review.Valid, review.Status)
	}
	if !strings.Contains(review.Reason, "revoked with effect") {
		t.Fatalf("expected effective-time reason, got %q", review.Reason)
	}
}

// A retraction withdraws a revocation claim for new investigations while
// older investigations keep concluding "revoked" from their cutoff.
func TestRetractedRevocationMaterial(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)

	event := t0.Add(time.Hour)
	*cur = event.Add(-time.Minute)
	if err := l.Revoke("leaf1"); err != nil {
		t.Fatal(err)
	}
	retractedAt := event.Add(30 * time.Second)
	*cur = retractedAt
	if err := l.RetractRevocation("leaf1", "claim withdrawn by CA"); err != nil {
		t.Fatal(err)
	}

	// Cutoff between revocation and retraction: revoked.
	rev, err := l.VerifyAt("leaf1", EKUServer, nil, event, event.Add(15*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if rev.Valid || rev.Status != StatusDisqualified {
		t.Fatalf("cutoff before retraction must still see the revocation, got %v %q", rev.Valid, rev.Status)
	}

	// Cutoff after the retraction: not revoked.
	after, err := l.VerifyAt("leaf1", EKUServer, nil, event, retractedAt.Add(15*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !after.Valid {
		t.Fatalf("retracted revocation must clear the event: %s", after.Reason)
	}
	found := false
	for _, ch := range after.Chains {
		for _, m := range ch.Evidence {
			if m.Type == "revocation" && strings.Contains(m.Detail, "撤回") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("report must cite the retraction it relied on")
	}
}

// Conflicting same-source revocation claims must be surfaced with the
// adoption basis instead of silently overwriting.
func TestConflictingRevocationClaimsExplained(t *testing.T) {
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

	res, err := l.VerifyAt("leaf1", EKUServer, nil, t0.Add(3*time.Hour), t0.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var detail string
	for _, ch := range res.Chains {
		for _, m := range ch.Evidence {
			if m.Type == "revocation" {
				detail = m.Detail
			}
		}
	}
	if !strings.Contains(detail, "同源撤销记录") {
		t.Fatalf("expected conflict explanation in revocation evidence, got %q", detail)
	}
}

// A saved lab reloads with the same materials, trust log and immutable
// evidence: reopening never changes a saved report's conclusion.
func TestPersistenceRoundTrip(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)
	*cur = t0.Add(time.Hour)
	if err := l.SetTrustAt("r1", false, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := l.RevokeAt("leaf1", t0.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.VerifyAt("leaf1", EKUServer, nil, t0.Add(time.Hour), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "lab.json")
	if err := l.SetStore(path); err != nil {
		t.Fatal(err)
	}

	reopened, err := LoadLab(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened == nil {
		t.Fatal("expected a restored lab")
	}
	reopened.SetClock(func() time.Time { return t0.Add(time.Hour) })
	if got := len(reopened.History()); got != 1 {
		t.Fatalf("saved evidence must survive reopening, got %d", got)
	}
	if got := len(reopened.TrustLog()); got != 2 {
		t.Fatalf("trust log must survive reopening, got %d", got)
	}
	// The same investigation on the reopened lab reaches the same
	// conclusion (revoked with effect before the event).
	res, err := reopened.VerifyAt("leaf1", EKUServer, nil, t0.Add(time.Hour), t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid || res.Status != StatusDisqualified {
		t.Fatalf("reopened lab must reproduce the saved basis, got %v %q", res.Valid, res.Status)
	}
	// And the future-effective distrust is still scheduled, not yet active.
	if roots := reopened.TrustedRoots(); len(roots) != 1 || roots[0] != "r1" {
		t.Fatalf("future-effective distrust must not be active yet, got %v", roots)
	}
}

// Validity periods are evaluated at the event time: just inside the leaf
// validity passes, just past NotAfter fails with an event-time reason.
func TestExpiryBoundaryAtEventTime(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)
	*cur = t0.Add(time.Hour)

	leaf, _ := l.Get("leaf1")
	inside := leaf.Cert.NotAfter.Add(-time.Second)
	res, err := l.VerifyAt("leaf1", EKUServer, nil, inside, inside.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("event just before expiry must validate: %s", res.Reason)
	}

	outside := leaf.Cert.NotAfter.Add(time.Second)
	res2, err := l.VerifyAt("leaf1", EKUServer, nil, outside, outside.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if res2.Valid || !strings.Contains(res2.Reason, "expired at the event time") {
		t.Fatalf("event past expiry must fail with event-time reason, got %v %q", res2.Valid, res2.Reason)
	}
}

// When no revocation material covers the event period the path stays
// undetermined instead of being forced into pass or fail.
func TestMissingCoverageStaysUndetermined(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)
	*cur = t0.Add(3 * time.Hour)

	// Event 30 minutes after issuance; the CRL known at the cutoff is
	// dated near the cutoff and does not reach back to the event.
	event := t0.Add(30 * time.Minute)
	res, err := l.VerifyAt("leaf1", EKUServer, nil, event, t0.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid || res.Status != StatusUndetermined {
		t.Fatalf("expected undetermined for uncovered event period, got %v %q", res.Valid, res.Status)
	}
	if !strings.Contains(res.Reason, "does not cover the event time") {
		t.Fatalf("expected coverage reason, got %q", res.Reason)
	}
}

// Every candidate path carries the time basis of the materials its verdict
// actually used, so an export never describes evidence learned later as
// verified at the time.
func TestPerPathMaterialTimeBasis(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)
	*cur = t0.Add(time.Hour)

	res, err := l.VerifyAt("leaf1", EKUServer, nil, *cur, *cur)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("precondition: %s", res.Reason)
	}
	if len(res.Chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(res.Chains))
	}
	types := map[string]int{}
	for _, m := range res.Chains[0].Evidence {
		types[m.Type]++
		if m.LearnedAt == nil {
			t.Fatalf("material %s/%s lacks learned time", m.Type, m.ID)
		}
		if m.LearnedAt.After(res.KnowledgeCutoff) {
			t.Fatalf("material %s/%s learned after the cutoff", m.Type, m.ID)
		}
	}
	for _, want := range []string{"certificate", "crl", "trust"} {
		if types[want] == 0 {
			t.Fatalf("expected %s materials in evidence, got %v", want, types)
		}
	}
}
