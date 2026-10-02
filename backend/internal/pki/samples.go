package pki

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
	if err := loadLoopSamples(l); err != nil {
		return err
	}
	return nil
}

// loadLoopSamples adds the combined scenario: a cross-signing loop between
// two intermediates, plus material for root-withdrawal and late-arriving
// revocation-data experiments.
//
//	rootE -> imE <-cross- imF <- rootF
//	rootF -> imF <-cross- imE <- rootE   (imE and imF cross-sign each other)
//
// leaf-loop is issued by imE, so its candidate paths include:
//   - leaf-loop -> imE -> rootE                       (complete)
//   - leaf-loop -> crossImEunderF -> imF -> rootF     (complete)
//   - leaf-loop -> crossImEunderF -> crossImFunderE -> (loop, dead end)
//
// imF starts with CRL publication switched off to model revocation data
// that has not arrived yet; restoring it demonstrates late-arriving
// revocation material. Withdrawing trust in rootE demonstrates that the
// remaining paths are judged independently.
func loadLoopSamples(l *Lab) error {
	if _, err := l.AddRoot("rootE", "Root E (loop)", 10); err != nil {
		return err
	}
	if _, err := l.AddRoot("rootF", "Root F (loop)", 10); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("imE", "Intermediate E", "rootE", "", 5); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("imF", "Intermediate F", "rootF", "", 5); err != nil {
		return err
	}
	// Cross-signing loop: each intermediate is also issued under the other.
	if _, err := l.AddIntermediate("crossImEunderF", "Cross of E under F", "imF", "imE", 5); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("crossImFunderE", "Cross of F under E", "imE", "imF", 5); err != nil {
		return err
	}
	if _, err := l.AddLeaf("leaf-loop", "loop.lab.example", "imE",
		[]EKU{EKUServer}, []string{"loop.lab.example"}, 90); err != nil {
		return err
	}
	// Revocation data for imF has not arrived yet (late CRL material).
	if err := l.SetCRLPublished("imF", false); err != nil {
		return err
	}
	return nil
}
