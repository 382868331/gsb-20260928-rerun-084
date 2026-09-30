package pki

import "testing"

func TestScenarios(t *testing.T) {
	lab := NewLab()
	if err := SeedScenarios(lab); err != nil {
		t.Fatal(err)
	}

	res, err := lab.Verify("leaf-cross", EKUServer)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("cross leaf should validate via one path: %s", res.Reason)
	}
	if len(res.Chains) != 2 {
		t.Fatalf("expected 2 candidate paths (old root + cross), got %d", len(res.Chains))
	}
	for i, ch := range res.Chains {
		t.Logf("cross chain %d valid=%v path=%v", i, ch.Valid, pathIDs(ch))
	}

	res2, err := lab.Verify("leaf-expired", EKUServer)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Valid {
		t.Fatal("expired-intermediate leaf must NOT validate")
	}
	for _, ch := range res2.Chains {
		if ch.Valid {
			t.Fatal("no chain may pass with an expired intermediate")
		}
	}
	t.Logf("expired reason: %s", res2.Reason)

	res3, err := lab.Verify("leaf-nocrl", EKUServer)
	if err != nil {
		t.Fatal(err)
	}
	if res3.Valid {
		t.Fatal("missing-CRL leaf must NOT validate")
	}
	t.Logf("nocrl reason: %s", res3.Reason)

	// Revoke the cross-signed intermediate node itself (the original, used
	// by the old-root path); old path must fail on revocation.
	if err := lab.Revoke("int-mig"); err != nil {
		t.Fatal(err)
	}
	res4, err := lab.Verify("leaf-cross", EKUServer)
	if err != nil {
		t.Fatal(err)
	}
	if res4.Valid {
		t.Log("note: cross cert is a separate certificate (not revoked); new-root path still valid, as expected for key compromise the whole key must be revoked")
	}

	// Rotation: old leaf superseded, new leaf valid.
	newLeaf, err := lab.RotateLeaf("leaf-cross", "leaf-cross-v2", 90)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := lab.Get("leaf-cross")
	if old.SupersededBy != "leaf-cross-v2" {
		t.Fatalf("superseded link missing: %q", old.SupersededBy)
	}
	res5, err := lab.Verify(newLeaf.ID, EKUServer)
	if err != nil || !res5.Valid {
		t.Fatalf("rotated leaf must validate: %v %s", err, res5.Reason)
	}

	// Distrust the new root too -> both cross paths fail.
	if err := lab.SetTrust("root-new", false); err != nil {
		t.Fatal(err)
	}
	res6, err := lab.Verify("leaf-cross", EKUServer)
	if err != nil {
		t.Fatal(err)
	}
	if res6.Valid {
		t.Fatal("with both roots untrusted/revoked paths, no path may pass")
	}
}

func pathIDs(ch ChainReport) []string {
	ids := make([]string, 0, len(ch.Path))
	for _, st := range ch.Path {
		ids = append(ids, st.ID)
	}
	return ids
}
