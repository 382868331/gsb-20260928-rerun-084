package lab

import (
	"testing"
	"time"
)

func bootstrappedStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	return s
}

func findCert(st *State, subject string, version int, cross bool) string {
	for id, c := range st.Certificates {
		if c.Subject == subject && c.Version == version && (c.CrossSignedBy != "") == cross {
			return id
		}
	}
	return ""
}

func rootID(st *State, name string) string {
	return findCert(st, name, 1, false)
}

func TestOldAndNewChainsBothValidateUnderMatchingTrust(t *testing.T) {
	s := bootstrappedStore(t)
	st := s.Snapshot()
	old := rootID(st, "Lab Root Old")
	newR := rootID(st, "Lab Root New")
	leaf := findCert(st, "api.lab.test", 1, false)
	if old == "" || newR == "" || leaf == "" {
		t.Fatal("missing bootstrap certificates")
	}

	oldRes, err := s.Verify(leaf, "serverAuth", []string{old}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !oldRes.Valid {
		t.Fatalf("old chain should validate with old root: %+v", oldRes.Paths)
	}
	if got := oldRes.ChosenPath.Label; got != "old chain" {
		t.Fatalf("label = %q, want old chain", got)
	}

	newRes, err := s.Verify(leaf, "serverAuth", []string{newR}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !newRes.Valid {
		t.Fatalf("new chain should validate via cross-certificate: %+v", newRes.Paths)
	}
	if got := newRes.ChosenPath.Label; got != "new chain" {
		t.Fatalf("label = %q, want new chain", got)
	}

	// Every candidate path is enumerated independently.
	if len(oldRes.Paths) < 2 {
		t.Fatalf("expected old and new candidate paths, got %d", len(oldRes.Paths))
	}
}

func TestTrustAnchorRequired(t *testing.T) {
	s := bootstrappedStore(t)
	st := s.Snapshot()
	leaf := findCert(st, "api.lab.test", 1, false)
	res, err := s.Verify(leaf, "serverAuth", nil, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("chain must not validate without a trust anchor")
	}
}

func TestPurposeMismatch(t *testing.T) {
	s := bootstrappedStore(t)
	st := s.Snapshot()
	old := rootID(st, "Lab Root Old")
	serverLeaf := findCert(st, "api.lab.test", 1, false)
	clientLeaf := findCert(st, "device.lab.test", 1, false)

	r1, _ := s.Verify(serverLeaf, "clientAuth", []string{old}, time.Time{})
	if r1.Valid {
		t.Fatal("server-only leaf must not pass clientAuth purpose")
	}
	r2, _ := s.Verify(clientLeaf, "serverAuth", []string{old}, time.Time{})
	if r2.Valid {
		t.Fatal("client-only leaf must not pass serverAuth purpose")
	}
	r3, _ := s.Verify(serverLeaf, "serverAuth", []string{old}, time.Time{})
	if !r3.Valid {
		t.Fatal("server leaf must pass serverAuth purpose")
	}
}

func TestExpiredIntermediateFailsPath(t *testing.T) {
	s := bootstrappedStore(t)
	st := s.Snapshot()
	old := rootID(st, "Lab Root Old")
	newR := rootID(st, "Lab Root New")
	legacy := findCert(st, "legacy.lab.test", 1, false)

	res, err := s.Verify(legacy, "serverAuth", []string{old, newR}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("legacy chain through expired intermediate v1 must not validate")
	}
	for _, p := range res.Paths {
		for _, n := range p.Nodes {
			if n.Subject == "Lab Intermediate Alpha" && !n.Expired {
				t.Fatalf("expected expired node flag: %+v", n)
			}
		}
	}
}

func TestRevocationIsImmediateAndDurable(t *testing.T) {
	s := bootstrappedStore(t)
	st := s.Snapshot()
	old := rootID(st, "Lab Root Old")
	leaf := findCert(st, "api.lab.test", 1, false)

	res, _ := s.Verify(leaf, "serverAuth", []string{old}, time.Time{})
	if !res.Valid {
		t.Fatal("pre-revocation verification must pass")
	}
	if _, err := s.Revoke(leaf, "key compromise"); err != nil {
		t.Fatal(err)
	}
	// Fresh verification reads live state; no cached verdict survives.
	res2, _ := s.Verify(leaf, "serverAuth", []string{old}, time.Time{})
	if res2.Valid {
		t.Fatal("revoked leaf must not keep validating through cache")
	}

	// Reopen: same experiment, revocation persisted.
	s2, err := NewStore(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	st2 := s2.Snapshot()
	c := st2.Certificates[leaf]
	if c == nil || !c.Revoked || c.RevokeReason != "key compromise" {
		t.Fatal("revocation must survive restart")
	}
	res3, _ := s2.Verify(leaf, "serverAuth", []string{old}, time.Time{})
	if res3.Valid {
		t.Fatal("revoked leaf must still fail after reopen")
	}
}

func TestPersistedExperimentKeepsSerialsAndVersions(t *testing.T) {
	s := bootstrappedStore(t)
	before := s.Snapshot()
	s2, err := NewStore(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	after := s2.Snapshot()
	if len(after.Certificates) != len(before.Certificates) {
		t.Fatal("certificate count changed after reopen")
	}
	for id, c := range before.Certificates {
		a := after.Certificates[id]
		if a == nil || a.Serial != c.Serial || a.Version != c.Version {
			t.Fatalf("cert %s differs after reopen", id)
		}
	}
}

func TestRotationAddsVersionAndOldChainStillDistinct(t *testing.T) {
	s := bootstrappedStore(t)
	st := s.Snapshot()
	newR := rootID(st, "Lab Root New")

	// Rotate the server leaf: a fresh key/version under the new root's chain.
	rotated, err := s.Issue(IssueParams{Name: "api.lab.test", Kind: "leaf", IssuerID: st.Certificates[findCert(st, "Lab Intermediate Alpha", 2, true)].EntityID, EKUs: []string{"serverAuth"}})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Version != 2 {
		t.Fatalf("rotated version = %d, want 2", rotated.Version)
	}
	res, err := s.Verify(rotated.ID, "serverAuth", []string{newR}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("rotated leaf must validate under new root: %+v", res.Paths)
	}
	if res.ChosenPath.Label != "new chain" {
		t.Fatalf("rotated leaf chose %q", res.ChosenPath.Label)
	}
}

func TestKeyFileNeverExposedInSnapshotSerialization(t *testing.T) {
	s := bootstrappedStore(t)
	st := s.Snapshot()
	for id, c := range st.Certificates {
		if c.KeyFile != "" {
			t.Fatalf("snapshot leaked key file for %s: %s", id, c.KeyFile)
		}
	}
}
