package pki

import "time"

// LoadSamples builds three local scenarios in one lab:
//
//  1. Cross-signing (root migration):
//     rootA -> intermediateX <- cross(by rootB); leaf-ok chains via either
//     trusted root. Rotated leaf-rotated is issued by the same intermediate
//     key after migration.
//  2. Expired intermediate:
//     rootC -> expired-im (negative validity) -> leaf-expired. Even though
//     every signature is correct, no path can validate.
//  3. Missing revocation data:
//     rootD -> silent-im (CRL publication switched off) -> leaf-nocrl.
//     Signatures and validity are fine, but revocation information is
//     unavailable so the path must fail.
//
// rootA, rootB, rootC, rootD are all trusted initially so each scenario can
// be verified independently.
func LoadSamples(l *Lab) error {
	l.Reset()
	if _, err := l.AddRoot("rootA", "Root A (old)", 10); err != nil {
		return err
	}
	if _, err := l.AddRoot("rootB", "Root B (new)", 10); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("intermediateX", "Intermediate X", "rootA", "", 5); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("crossX", "Cross of X under Root B", "rootB", "intermediateX", 5); err != nil {
		return err
	}
	if _, err := l.AddLeaf("leaf-ok", "server.lab.example", "intermediateX",
		[]EKU{EKUServer, EKUClient}, []string{"server.lab.example"}, 90); err != nil {
		return err
	}
	if _, err := l.RotateLeaf("leaf-rotated", "leaf-ok", "intermediateX", 90); err != nil {
		return err
	}

	if _, err := l.AddRoot("rootC", "Root C (expiry demo)", 10); err != nil {
		return err
	}
	// years=-1: certificate that ended one year ago.
	if _, err := l.AddIntermediate("expired-im", "Expired Intermediate", "rootC", "", -1); err != nil {
		return err
	}
	if _, err := l.AddLeaf("leaf-expired", "expired-path.lab.example", "expired-im",
		[]EKU{EKUServer}, []string{"expired-path.lab.example"}, 90); err != nil {
		return err
	}

	if _, err := l.AddRoot("rootD", "Root D (no CRL demo)", 10); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("silent-im", "Silent Intermediate (no CRL)", "rootD", "", 5); err != nil {
		return err
	}
	if err := l.SetCRLPublished("silent-im", false); err != nil {
		return err
	}
	if _, err := l.AddLeaf("leaf-nocrl", "nocrl.lab.example", "silent-im",
		[]EKU{EKUServer}, []string{"nocrl.lab.example"}, 90); err != nil {
		return err
	}

	// A revoked leaf on the healthy cross-signed path for revocation demos.
	if _, err := l.AddLeaf("leaf-revoked", "revoked.lab.example", "intermediateX",
		[]EKU{EKUServer}, []string{"revoked.lab.example"}, 90); err != nil {
		return err
	}
	if err := l.Revoke("leaf-revoked"); err != nil {
		return err
	}

	// 4. Cross-signing loop: imP (rootE) and imQ (rootF) cross-sign each
	// other, so leaf-loop reaches both roots and the enumerator must walk
	// the imP <-> imQ cycle without getting stuck.
	if _, err := l.AddRoot("rootE", "Root E (loop demo)", 10); err != nil {
		return err
	}
	if _, err := l.AddRoot("rootF", "Root F (loop demo)", 10); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("imP", "Intermediate P", "rootE", "", 5); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("imQ", "Intermediate Q", "rootF", "", 5); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("crossQP", "Cross of P under Q", "imQ", "imP", 5); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("crossPQ", "Cross of Q under P", "imP", "imQ", 5); err != nil {
		return err
	}
	if _, err := l.AddLeaf("leaf-loop", "loop.lab.example", "imP",
		[]EKU{EKUServer}, []string{"loop.lab.example"}, 90); err != nil {
		return err
	}

	// 5. Late revocation material: tardy-im publishes a CRL whose
	// ThisUpdate is 30 minutes in the future, so leaf-late cannot be
	// confirmed nor ruled out until the data becomes effective.
	if _, err := l.AddRoot("rootG", "Root G (late CRL demo)", 10); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("tardy-im", "Tardy Intermediate (late CRL)", "rootG", "", 5); err != nil {
		return err
	}
	if err := l.SetCRLDelay("tardy-im", 30); err != nil {
		return err
	}
	if _, err := l.AddLeaf("leaf-late", "late.lab.example", "tardy-im",
		[]EKU{EKUServer}, []string{"late.lab.example"}, 90); err != nil {
		return err
	}

	// 6. Late revocation notice: the notice says leaf-laterev was revoked
	// a day ago, but it only arrives two hours from now. An investigation
	// with today's knowledge cutoff finds nothing; the same event time
	// re-investigated after the notice arrives is disqualified.
	if _, err := l.AddRoot("rootH", "Root H (late revocation notice)", 10); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("drip-im", "Drip Intermediate", "rootH", "", 5); err != nil {
		return err
	}
	if _, err := l.AddLeaf("leaf-laterev", "laterev.lab.example", "drip-im",
		[]EKU{EKUServer}, []string{"laterev.lab.example"}, 90); err != nil {
		return err
	}
	now := l.Now()
	if err := l.RevokeTimed("leaf-laterev", now.Add(-24*time.Hour), now.Add(2*time.Hour),
		"late notice: certificate was already revoked 24h before it arrived"); err != nil {
		return err
	}

	// 7. Corrected revocation date: two notices coexist; the second
	// corrects the revocation moment 48h earlier. Both stay listed side
	// by side; investigations use the newest notice known by the cutoff.
	if _, err := l.AddRoot("rootI", "Root I (corrected revocation)", 10); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("fix-im", "Fix Intermediate", "rootI", "", 5); err != nil {
		return err
	}
	if _, err := l.AddLeaf("leaf-corrected", "corrected.lab.example", "fix-im",
		[]EKU{EKUServer}, []string{"corrected.lab.example"}, 90); err != nil {
		return err
	}
	if err := l.Revoke("leaf-corrected"); err != nil {
		return err
	}
	if err := l.RevokeTimed("leaf-corrected", now.Add(-48*time.Hour), now,
		"correction: revocation date moved 48h earlier"); err != nil {
		return err
	}

	// 8. Scheduled root distrust: rootJ stops being trusted one hour from
	// now (material already obtained). Events before the cut still
	// validate; events after it fail on the anchor requirement.
	if _, err := l.AddRoot("rootJ", "Root J (trust ends soon)", 10); err != nil {
		return err
	}
	if _, err := l.AddLeaf("leaf-rootcut", "rootcut.lab.example", "rootJ",
		[]EKU{EKUServer}, []string{"rootcut.lab.example"}, 90); err != nil {
		return err
	}
	if err := l.SetTrustTimed("rootJ", false, now.Add(time.Hour), now,
		"root stops being trusted in 1h"); err != nil {
		return err
	}
	return nil
}
