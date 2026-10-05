package pki

import (
	"strings"
	"testing"
	"time"
)

// crlRef returns the CRL material the chain's verdict relied on.
func crlRef(t *testing.T, res *VerifyResult, caID string) MaterialRef {
	t.Helper()
	for _, ch := range res.Chains {
		for _, m := range ch.Evidence {
			if m.Type == "crl" && m.ID == caID {
				return m
			}
		}
	}
	t.Fatalf("no CRL material for %q in report", caID)
	return MaterialRef{}
}

// The same event reviewed at an early and a much later knowledge cutoff
// must cite the same revocation material with identical effective and
// learned times: moving the query cutoff never rewrites material times.
func TestCRLMaterialTimesStableAcrossCutoffs(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)

	event := t0.Add(30 * time.Minute)
	*cur = event.Add(time.Minute)
	early, err := l.VerifyAt("leaf1", EKUServer, nil, event, event.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !early.Valid {
		t.Fatalf("early cutoff must validate: %s", early.Reason)
	}

	// Much later: the lab clock moved on, the same event is reviewed with
	// a late knowledge cutoff.
	*cur = t0.Add(73 * time.Hour)
	late, err := l.VerifyAt("leaf1", EKUServer, nil, event, t0.Add(72*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !late.Valid {
		t.Fatalf("late cutoff must still validate via the CRL that covered the event: %s", late.Reason)
	}

	for _, caID := range []string{"im1", "r1"} {
		a, b := crlRef(t, early, caID), crlRef(t, late, caID)
		if !a.EffectiveAt.Equal(*b.EffectiveAt) || !a.LearnedAt.Equal(*b.LearnedAt) {
			t.Fatalf("cutoff moved CRL material times for %s: %s/%s -> %s/%s",
				caID, a.EffectiveAt, a.LearnedAt, b.EffectiveAt, b.LearnedAt)
		}
		if a.Detail != b.Detail {
			t.Fatalf("coverage interval rewritten for %s: %q -> %q", caID, a.Detail, b.Detail)
		}
	}
}

// Late-arriving revocation material and a later correction: the same
// event reviewed at three cutoffs yields valid (nothing known), valid
// (late material effective after the event) and revoked (correction
// effective before the event); every report keeps its own material basis.
func TestLateRevocationAndCorrectionAcrossCutoffs(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)

	event := t0.Add(30 * time.Minute)

	// Late-arriving revocation: learned at t1, effective after the event.
	t1 := t0.Add(2 * time.Hour)
	*cur = t1
	if err := l.RevokeAt("leaf1", t0.Add(45*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Correction learned at t2: the revocation actually took effect
	// before the event.
	t2 := t0.Add(3 * time.Hour)
	*cur = t2
	if err := l.CorrectRevocation("leaf1", t0.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	*cur = t0.Add(4 * time.Hour)

	// Cutoff A: before any revocation material existed.
	a, err := l.VerifyAt("leaf1", EKUServer, nil, event, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !a.Valid {
		t.Fatalf("cutoff before any revocation material must validate: %s", a.Reason)
	}

	// Cutoff B: the late material is known, but its effective time is
	// after the event, so the event is still valid.
	b, err := l.VerifyAt("leaf1", EKUServer, nil, event, t1.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !b.Valid {
		t.Fatalf("late material effective after the event must not condemn it: %s", b.Reason)
	}

	// Cutoff C: the correction moved the effective time before the event.
	c, err := l.VerifyAt("leaf1", EKUServer, nil, event, t2.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if c.Valid || c.Cause != CauseRevocation {
		t.Fatalf("corrected material must disqualify the event, got %v %q cause=%q", c.Valid, c.Reason, c.Cause)
	}

	// Report B cites the late material with its real effective/learned
	// times; report C cites the correction. Neither rewrites the other.
	var revB, revC *MaterialRef
	for i, m := range b.Chains[0].Evidence {
		if m.Type == "revocation" {
			revB = &b.Chains[0].Evidence[i]
		}
	}
	for i, m := range c.Chains[0].Evidence {
		if m.Type == "revocation" {
			revC = &c.Chains[0].Evidence[i]
		}
	}
	if revB == nil || !revB.EffectiveAt.Equal(t0.Add(45*time.Minute)) || !revB.LearnedAt.Equal(t1) {
		t.Fatalf("report B must cite the late material with its real times: %+v", revB)
	}
	if revC == nil || !revC.EffectiveAt.Equal(t0.Add(15*time.Minute)) || !revC.LearnedAt.Equal(t2) {
		t.Fatalf("report C must cite the correction with its real times: %+v", revC)
	}

	// All three reports are preserved with their own conclusions.
	hist := l.History()
	if len(hist) != 3 || !hist[2].Valid || !hist[1].Valid || hist[0].Valid {
		t.Fatalf("each report must keep its original conclusion, got %v %v %v",
			hist[2].Status, hist[1].Status, hist[0].Status)
	}
}

// The three knowledge states are told apart: material that already
// covered the event, material only learned after the cutoff, and truly
// missing revocation data.
func TestCoveredLateLearnedAndMissingDistinguished(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)
	*cur = t0.Add(6 * time.Hour)

	event := t0.Add(30 * time.Minute)

	// Simulate revocation material that only reached the lab at t0+5h:
	// every issuance of im1 is learned then (its intervals stay frozen).
	ca, _ := l.Get("im1")
	for i := range ca.CRLIssues {
		ca.CRLIssues[i].LearnedAt = t0.Add(5 * time.Hour)
	}
	ca.CRLKnownAt = t0.Add(5 * time.Hour)
	*cur = t0.Add(7 * time.Hour)

	// Cutoff before the material arrived: undetermined, "only obtained
	// later" — distinct from truly missing data.
	late, err := l.VerifyAt("leaf1", EKUServer, nil, event, t0.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if late.Status != StatusUndetermined || late.Cause != CauseEvidence {
		t.Fatalf("late-learned material must stay undetermined, got %v cause=%q", late.Status, late.Cause)
	}
	if !strings.Contains(late.Reason, "after the knowledge cutoff") {
		t.Fatalf("expected a late-learned reason, got %q", late.Reason)
	}

	// Cutoff after the material arrived: the frozen interval covers the
	// event, so the same event now validates.
	covered, err := l.VerifyAt("leaf1", EKUServer, nil, event, t0.Add(6*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !covered.Valid {
		t.Fatalf("material learned by the cutoff and covering the event must validate: %s", covered.Reason)
	}
	ref := crlRef(t, covered, "im1")
	if !ref.LearnedAt.Equal(t0.Add(5 * time.Hour)) {
		t.Fatalf("learned time must be the material's own, got %s", ref.LearnedAt)
	}

	// Truly missing: the CA publishes nothing at all.
	if _, err := l.AddRoot("r2", "Root Two", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := l.AddIntermediate("im2", "Intermediate Two", "r2", "", 5); err != nil {
		t.Fatal(err)
	}
	if err := l.SetCRLPublished("im2", false); err != nil {
		t.Fatal(err)
	}
	if _, err := l.AddLeaf("leaf2", "missing.lab.example", "im2",
		[]EKU{EKUServer}, []string{"missing.lab.example"}, 90); err != nil {
		t.Fatal(err)
	}
	missing, err := l.VerifyAt("leaf2", EKUServer, nil, t0.Add(7*time.Hour), t0.Add(7*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if missing.Status != StatusUndetermined || !strings.Contains(missing.Reason, "revocation data missing") {
		t.Fatalf("truly missing data must be reported as such, got %v %q", missing.Status, missing.Reason)
	}
}

// A saved and reopened lab still explains every original report's basis:
// the frozen reports are identical and re-running the same investigation
// reproduces the same conclusion from the restored issuance log.
func TestReportBasisSurvivesReopen(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, cur := clockLab(t, t0)
	buildChain(t, l)

	event := t0.Add(30 * time.Minute)
	t1 := t0.Add(2 * time.Hour)
	*cur = t1
	if err := l.RevokeAt("leaf1", t0.Add(45*time.Minute)); err != nil {
		t.Fatal(err)
	}
	t2 := t0.Add(3 * time.Hour)
	*cur = t2
	if err := l.CorrectRevocation("leaf1", t0.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	*cur = t0.Add(4 * time.Hour)

	early, err := l.VerifyAt("leaf1", EKUServer, nil, event, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	late, err := l.VerifyAt("leaf1", EKUServer, nil, event, t2.Add(30*time.Minute))
	if err != nil {
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
	back.SetClock(func() time.Time { return t0.Add(4 * time.Hour) })

	// The frozen reports survive the reopen byte-for-byte in conclusion
	// and material basis.
	restored := back.History()
	if len(restored) != 2 {
		t.Fatalf("expected 2 restored reports, got %d", len(restored))
	}
	if !restored[1].Valid || restored[0].Valid {
		t.Fatal("restored reports must keep their original conclusions")
	}
	a0, a1 := crlRef(t, early, "im1"), crlRef(t, restored[1], "im1")
	if !a0.EffectiveAt.Equal(*a1.EffectiveAt) || !a0.LearnedAt.Equal(*a1.LearnedAt) || a0.Detail != a1.Detail {
		t.Fatal("restored early report lost its CRL material basis")
	}
	// The late report was decided by the corrected revocation material;
	// its basis must survive the reopen as well.
	revOf := func(res *VerifyResult) MaterialRef {
		t.Helper()
		for _, ch := range res.Chains {
			for _, m := range ch.Evidence {
				if m.Type == "revocation" && m.ID == "leaf1" {
					return m
				}
			}
		}
		t.Fatal("no revocation material for leaf1 in report")
		return MaterialRef{}
	}
	b0, b1 := revOf(late), revOf(restored[0])
	if !b0.EffectiveAt.Equal(*b1.EffectiveAt) || !b0.LearnedAt.Equal(*b1.LearnedAt) || b0.Detail != b1.Detail {
		t.Fatal("restored late report lost its revocation material basis")
	}

	// Re-running the same historical investigation on the reopened lab
	// reproduces both conclusions from the restored issuance log.
	reEarly, err := back.VerifyAt("leaf1", EKUServer, nil, event, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !reEarly.Valid {
		t.Fatalf("reopened lab must reproduce the early conclusion: %s", reEarly.Reason)
	}
	reLate, err := back.VerifyAt("leaf1", EKUServer, nil, event, t2.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if reLate.Valid || reLate.Cause != CauseRevocation {
		t.Fatalf("reopened lab must reproduce the corrected conclusion, got %v %q", reLate.Valid, reLate.Reason)
	}
}
