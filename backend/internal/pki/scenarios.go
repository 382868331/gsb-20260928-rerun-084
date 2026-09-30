package pki

import "time"

// SeedScenarios builds the three required local samples:
//  1. cross-signing during root migration (two trust paths),
//  2. an expired intermediate (path must fail even though every hop is
//     cryptographically signed),
//  3. an issuer that publishes no revocation data (path must fail).
func SeedScenarios(l *Lab) error {
	now := l.Now()

	// --- Scenario 1: cross signing / root migration ---
	if _, err := l.AddRoot("root-old", "Old Root CA", 10); err != nil {
		return err
	}
	if _, err := l.AddRoot("root-new", "New Root CA", 10); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("int-mig", "Migration Intermediate", "root-old", "",
		now.Add(-time.Hour), now.AddDate(5, 0, 0)); err != nil {
		return err
	}
	// Cross certificate: same intermediate key/identity, signed by the new root.
	if _, err := l.AddIntermediate("int-mig-cross", "Migration Intermediate (cross-signed by New Root)",
		"root-new", "int-mig", now.Add(-time.Hour), now.AddDate(5, 0, 0)); err != nil {
		return err
	}
	if _, err := l.AddLeaf("leaf-cross", "www.cross-example.local", "int-mig",
		[]EKU{EKUServer}, []string{"www.cross-example.local"}, 90); err != nil {
		return err
	}

	// --- Scenario 2: expired intermediate ---
	if _, err := l.AddRoot("root-exp", "Expired-Demo Root CA", 10); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("int-expired", "Expired Intermediate", "root-exp", "",
		now.AddDate(-3, 0, 0), now.AddDate(-1, 0, 0)); err != nil {
		return err
	}
	if _, err := l.AddLeaf("leaf-expired", "www.expired-chain.local", "int-expired",
		[]EKU{EKUServer}, []string{"www.expired-chain.local"}, 90); err != nil {
		return err
	}

	// --- Scenario 3: revocation data missing ---
	if _, err := l.AddRoot("root-nocrl", "No-CRL-Demo Root CA", 10); err != nil {
		return err
	}
	if _, err := l.AddIntermediate("int-nocrl", "Intermediate With No CRL Publication", "root-nocrl", "",
		now.Add(-time.Hour), now.AddDate(5, 0, 0)); err != nil {
		return err
	}
	if _, err := l.AddLeaf("leaf-nocrl", "www.no-crl.local", "int-nocrl",
		[]EKU{EKUServer}, []string{"www.no-crl.local"}, 90); err != nil {
		return err
	}
	if err := l.SetCRLPublished("int-nocrl", false); err != nil {
		return err
	}
	return nil
}
