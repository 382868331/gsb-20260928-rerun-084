package pki

import (
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

// Trust decisions are evaluated as known at the cutoff: a path valid while
// the root was trusted becomes disqualified once the distrust is learned,
// with a distinct reason from missing evidence.
func TestTrustEvaluatedAtKnowledgeCutoff(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)

	event := t0.Add(time.Hour)
	t4 := t0.Add(2 * time.Hour)
	*cur = t4
	if err := l.SetTrust("r1", false); err != nil {
		t.Fatal(err)
	}

	whileTrusted, err := l.VerifyAt("leaf1", EKUServer, nil, event, event.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !whileTrusted.Valid {
		t.Fatalf("cutoff before distrust must still validate: %s", whileTrusted.Reason)
	}

	afterDistrust, err := l.VerifyAt("leaf1", EKUServer, nil, event, t4.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if afterDistrust.Valid || afterDistrust.Status != StatusDisqualified {
		t.Fatalf("expected disqualified after distrust, got %v %q", afterDistrust.Valid, afterDistrust.Status)
	}
	if !strings.Contains(afterDistrust.Reason, "not a trusted anchor as of the knowledge cutoff") {
		t.Fatalf("expected cutoff trust reason, got %q", afterDistrust.Reason)
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
