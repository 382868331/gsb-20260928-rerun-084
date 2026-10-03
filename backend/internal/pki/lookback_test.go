package pki

import (
	"strings"
	"testing"
	"time"
)

// A revocation notice that arrives late but predates the event must not
// change an investigation run with an earlier knowledge cutoff; the same
// event time re-investigated with a later cutoff is disqualified, and the
// old evidence is preserved unchanged.
func TestLateRevocationNoticeDualCutoff(t *testing.T) {
	l := freshSampleLab(t)
	event := l.Now()

	before, err := l.VerifyAt("leaf-laterev", EKUServer, nil, &event, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !before.Valid {
		t.Fatalf("with today's knowledge the late notice is unknown, expected valid: %s", before.Reason)
	}

	later := l.Now().Add(3 * time.Hour) // after the notice arrives
	after, err := l.VerifyAt("leaf-laterev", EKUServer, nil, &event, &later)
	if err != nil {
		t.Fatal(err)
	}
	if after.Valid || after.Status != StatusDisqualified {
		t.Fatalf("later knowledge must disqualify the same event, got valid=%v status=%q", after.Valid, after.Status)
	}
	if !strings.Contains(after.Reason, "revoked") {
		t.Fatalf("expected revocation reason, got %q", after.Reason)
	}
	if after.EventTime != before.EventTime {
		t.Fatal("both versions must investigate the same event time")
	}
	hist := l.History()
	if len(hist) != 2 || !hist[1].Valid || hist[0].Valid {
		t.Fatal("the old investigation must remain reproducible with its then-current knowledge")
	}
}

// A root that stops being trusted validates events before the cut and
// rejects events after it, with the anchor as the stated reason.
func TestRootTrustCutoffAroundEvent(t *testing.T) {
	l := freshSampleLab(t)
	now := l.Now()
	before := now.Add(30 * time.Minute)
	after := now.Add(2 * time.Hour)

	res, err := l.VerifyAt("leaf-rootcut", EKUServer, nil, &before, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("event before the trust cut must validate: %s", res.Reason)
	}
	res2, err := l.VerifyAt("leaf-rootcut", EKUServer, nil, &after, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Valid || !strings.Contains(res2.Reason, "not a trusted anchor") {
		t.Fatalf("event after the trust cut must fail on the anchor, got valid=%v reason=%q", res2.Valid, res2.Reason)
	}
}

// Events exactly at the certificate expiry boundary flip the verdict.
func TestExpiryBoundaryEventTime(t *testing.T) {
	l := freshSampleLab(t)
	leaf, _ := l.Get("leaf-ok")
	// Move the lab clock to the expiry boundary so the live CRL coverage
	// window follows the event.
	inside := leaf.Cert.NotAfter.Add(-time.Minute)
	l.SetClock(func() time.Time { return inside })
	res, err := l.Verify("leaf-ok", EKUServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("event just before expiry must validate: %s", res.Reason)
	}
	outside := leaf.Cert.NotAfter.Add(time.Minute)
	l.SetClock(func() time.Time { return outside })
	res2, err := l.Verify("leaf-ok", EKUServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Valid || !strings.Contains(res2.Reason, "expired") {
		t.Fatalf("event after expiry must fail with expiry reason, got valid=%v reason=%q", res2.Valid, res2.Reason)
	}
}

// A corrected revocation date supersedes the original notice once
// acquired; investigations with a cutoff between the two notices keep the
// original date.
func TestCorrectedRevocationDate(t *testing.T) {
	l := NewLab()
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	l.SetClock(func() time.Time { return base })
	if _, err := l.AddRoot("rootT", "Root T", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := l.AddLeaf("leafT", "t.lab.example", "rootT", []EKU{EKUServer}, nil, 90); err != nil {
		t.Fatal(err)
	}
	// Original notice: revoked at base+24h, known immediately.
	if err := l.RevokeTimed("leafT", base.Add(24*time.Hour), base, "original notice"); err != nil {
		t.Fatal(err)
	}
	// Correction arrives at base+1h: revocation actually started at base-48h.
	if err := l.RevokeTimed("leafT", base.Add(-48*time.Hour), base.Add(time.Hour), "corrected date"); err != nil {
		t.Fatal(err)
	}

	event := base // before the original notice's date, after the corrected one
	cutoffEarly := base.Add(30 * time.Minute)
	res, err := l.VerifyAt("leafT", EKUServer, nil, &event, &cutoffEarly)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("with only the original notice the event predates revocation: %s", res.Reason)
	}
	cutoffLate := base.Add(2 * time.Hour)
	res2, err := l.VerifyAt("leafT", EKUServer, nil, &event, &cutoffLate)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Valid || !strings.Contains(res2.Reason, "revoked") {
		t.Fatalf("corrected notice must revoke the earlier event, got valid=%v reason=%q", res2.Valid, res2.Reason)
	}
	// The correction must be visible in the per-path material basis.
	found := false
	for _, ch := range res2.Chains {
		for _, b := range ch.Basis {
			if b.Kind == "revocation" && b.Effective != nil && b.Effective.Equal(base.Add(-48*time.Hour)) {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("export basis must cite the corrected revocation material")
	}
}

// Without revocation material covering the event period the path stays
// undetermined instead of failing.
func TestMissingCoverageKeepsUncertainty(t *testing.T) {
	l := freshSampleLab(t)
	// Move the clock forward so the event sits inside the certificates'
	// validity but outside the live CRL coverage window.
	l.SetClock(func() time.Time { return time.Now().Add(48 * time.Hour) })
	past := l.Now().Add(-24 * time.Hour)
	res, err := l.VerifyAt("leaf-ok", EKUServer, nil, &past, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid || res.Status != StatusUndetermined {
		t.Fatalf("expected undetermined without covering revocation data, got valid=%v status=%q reason=%q", res.Valid, res.Status, res.Reason)
	}
	if !strings.Contains(res.Reason, "covers the event time") {
		t.Fatalf("expected missing-coverage reason, got %q", res.Reason)
	}
}

// Two candidate paths fail for different reasons at the same investigation:
// one lacks evidence known by the cutoff, the other has complete material
// but its root is outside the experiment's allowed set.
func TestDistinctPathReasons(t *testing.T) {
	l := freshSampleLab(t)
	// leaf-loop reaches rootE via imP and rootF via imQ: delay imP's CRL
	// so the rootE path lacks evidence, and exclude rootF by policy so
	// that path fails on the researcher's trust conditions instead.
	if err := l.SetCRLDelay("imP", 30); err != nil {
		t.Fatal(err)
	}
	res, err := l.Verify("leaf-loop", EKUServer, &Policy{AllowedRoots: []string{"rootE"}})
	if err != nil {
		t.Fatal(err)
	}
	var late, okPath *ChainReport
	for i := range res.Chains {
		ch := &res.Chains[i]
		switch ch.Path[0].ID {
		case "rootE":
			late = ch
		case "rootF":
			okPath = ch
		}
	}
	if late == nil || okPath == nil {
		t.Fatal("expected both loop candidate paths")
	}
	if late.Status != StatusUndetermined || !strings.Contains(late.Reason, "late CRL") {
		t.Fatalf("rootE path must be undetermined for late CRL, got %q %q", late.Status, late.Reason)
	}
	if okPath.Status != StatusDisqualified || !strings.Contains(okPath.Reason, "allowed roots") {
		t.Fatalf("rootF path must be disqualified by the allowed-roots policy, got %q %q", okPath.Status, okPath.Reason)
	}
}
