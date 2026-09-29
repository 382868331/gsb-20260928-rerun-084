package pki

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// PathStep describes one node of a candidate verification path.
type PathStep struct {
	ID       string    `json:"id"`
	Label    string    `json:"label"`
	Kind     NodeKind  `json:"kind"`
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"notAfter"`
	Expired  bool      `json:"expired"`
	Revoked  bool      `json:"revoked"`
	Trusted  bool      `json:"trusted,omitempty"`
}

// ChainReport is one attempted root-to-leaf path with its evaluation.
type ChainReport struct {
	Path   []PathStep `json:"path"`
	Valid  bool       `json:"valid"`
	Reason string     `json:"reason,omitempty"`
}

// VerifyResult is the live verification answer. Nothing here is cached.
type VerifyResult struct {
	LeafID       string        `json:"leafId"`
	Purpose      string        `json:"purpose"`
	CheckedAt    time.Time     `json:"checkedAt"`
	Valid        bool          `json:"valid"`
	Reason       string        `json:"reason,omitempty"`
	SelectedPath []string      `json:"selectedPath,omitempty"`
	Chains       []ChainReport `json:"chains"`
	TrustedRoots []string      `json:"trustedRoots"`
}

// Verify performs a live verification of leafID for the requested purpose
// (serverAuth/clientAuth). It considers:
//   - purpose (ExtKeyUsage on the leaf),
//   - validity period of every certificate in the chain,
//   - trust anchor (only currently trusted roots),
//   - revocation, re-read from live state and a freshly generated CRL.
//
// Cross-signed intermediates naturally surface as multiple candidate paths
// (old chain and new chain); expired intermediates are still shown so the
// lab can demonstrate why a path failed.
func (l *Lab) Verify(leafID string, purpose EKU) (*VerifyResult, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	now := l.nowFunc()
	leaf, ok := l.certs[leafID]
	if !ok {
		return nil, fmt.Errorf("leaf %q not found", leafID)
	}

	res := &VerifyResult{
		LeafID: leafID, Purpose: string(purpose), CheckedAt: now.UTC(),
	}
	for id := range l.trust {
		if l.trust[id] {
			res.TrustedRoots = append(res.TrustedRoots, id)
		}
	}

	wantEKU, ok := map[EKU]x509.ExtKeyUsage{
		EKUServer: x509.ExtKeyUsageServerAuth,
		EKUClient: x509.ExtKeyUsageClientAuth,
	}[purpose]\n+	if !ok {
		return nil, fmt.Errorf("unknown purpose %q", purpose)
	}

	// Enumerate every cryptographic path from the leaf to a self-signed root.
	var chains [][]*Cert
	l.enumerate(leaf, map[string]bool{}, nil, &chains)

	for _, chain := range chains {
		report := ChainReport{Valid: true}
		// chain order: leaf ... root; present root-first.
		for i := len(chain) - 1; i >= 0; i-- {
			c := chain[i]
			step := PathStep{
				ID: c.ID, Label: c.Label, Kind: c.Kind,
				Subject: c.Cert.Subject.String(), Issuer: c.Cert.Issuer.String(),
				NotAfter: c.Cert.NotAfter, Expired: now.Before(c.Cert.NotBefore) || now.After(c.Cert.NotAfter),
				Revoked: c.Revoked,
			}
			if c.Kind == KindRoot {
				step.Trusted = l.trust[c.ID]
			}
			report.Path = append(report.Path, step)
		}

		reason := l.evaluateChain(chain, wantEKU, now)
		if reason != "" {
			report.Valid = false
			report.Reason = reason
		}
		res.Chains = append(res.Chains, report)
		if report.Valid && !res.Valid {
			res.Valid = true
			res.Reason = ""
			res.SelectedPath = idsOf(chain)
		}
	}

	if !res.Valid {
		res.Reason = summarize(res.Chains)
	}
	return res, nil
}

func idsOf(chain []*Cert) []string {
	// root-first order
	ids := make([]string, 0, len(chain))
	for i := len(chain) - 1; i >= 0; i-- {
		ids = append(ids, chain[i].ID)
	}
	return ids
}

func summarize(reports []ChainReport) string {
	if len(reports) == 0 {
		return "no cryptographic path to any root"
	}
	seen := map[string]bool{}
	var reasons []string
	for _, r := range reports {
		if !r.Valid && !seen[r.Reason] {
			seen[r.Reason] = true
			reasons = append(reasons, r.Reason)
		}
	}
	return strings.Join(reasons, "; ")
}

func (l *Lab) evaluateChain(chain []*Cert, wantEKU x509.ExtKeyUsage, now time.Time) string {
	leaf := chain[0]
	hasPurpose := false
	for _, u := range leaf.Cert.ExtKeyUsage {
		if u == wantEKU {
			hasPurpose = true
		}
	}
	if !hasPurpose {
		return "purpose not permitted by certificate ExtKeyUsage"
	}
	for _, c := range chain {
		if now.Before(c.Cert.NotBefore) {
			return fmt.Sprintf("certificate %q not yet valid", c.Label)
		}
		if now.After(c.Cert.NotAfter) {
		return fmt.Sprintf("certificate %q expired", c.Label)
		}
		if c.Revoked {
			return fmt.Sprintf("certificate %q revoked", c.Label)
		}
		if c != leaf && !c.Cert.IsCA {
			return fmt.Sprintf("certificate %q is not a CA", c.Label)
		}
	}
	root := chain[len(chain)-1]
	if root.Kind != KindRoot || !root.Cert.Subject.Equal(root.Cert.Issuer) {
		return "chain does not end at a self-signed root"
	}
	if !l.trust[root.ID] {
		return fmt.Sprintf("root %q is not a trusted anchor", root.Label)
	}

	// Cryptographic confirmation via the standard library, with a freshly
	// generated CRL consulted for every issuing CA (no cached answers).
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	intermediates := x509.NewCertPool()
	for _, c := range chain[1 : len(chain)-1] {
		intermediates.AddCert(c.Cert)
	}
	if _, err := leaf.Cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{wantEKU},
	}); err != nil {
		return "chain verification failed: " + err.Error()
	}
	for _, c := range chain[1:] {
		der, err := l.buildCRLLocked(c)
		if err != nil {
			return "CRL unavailable for " + c.Label + ": " + err.Error()
		}
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			return "invalid CRL from " + c.Label
		}
		if err := crl.CheckSignatureFrom(c.Cert); err != nil {
			return "CRL signature invalid for " + c.Label
		}
		if now.Before(crl.ThisUpdate) || (crl.HasExpired(now)) {
			return "stale CRL from " + c.Label
		}
		if entry := crl.RevokedCertificateEntries(); len(entry) > 0 {
			return fmt.Sprintf("CRL lists a revoked certificate issued by %q", c.Label)
		}
	}
	return ""
}

func (l *Lab) buildCRLLocked(ca *Cert) ([]byte, error) {
	now := l.nowFunc()
	revoked := []x509.RevocationList{}
	for _, c := range l.certs {
		if c.IssuerID == ca.ID && c.Revoked {
			revoked = append(revoked, x509.RevocationList{
				SerialNumber: c.Cert.SerialNumber, RevokedAt: c.RevokedAt,
			})
		}
	}
	tmpl := &x509.RevocationList{
		Number:     l.seq.Add(1),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
		RevokedCertificates: revoked,
	}
	return x509.CreateRevocationList(nil, tmpl, ca.Cert, ca.Key)
}

// enumerate DFS-walks all parents that cryptographically signed the current
// certificate. A cross certificate shares subject DN and public key with the
// original intermediate, so both appear as candidate parents, producing the
// old-root and new-root paths during migration.
func (l *Lab) enumerate(cur *Cert, visited map[string]bool, acc []*Cert, out *[][]*Cert) {
	acc = append(append([]*Cert{}, acc...), cur)
	visited[cur.ID] = true
	selfSigned := cur.Kind == KindRoot && cur.Cert.Subject.Equal(cur.Cert.Issuer)
	if selfSigned {
		*out = append(*out, acc)
		return
	}
	extended := false
	for _, parent := range l.certs {
		if visited[parent.ID] {
			continue
		}
		if !parent.Cert.IsCA {
			continue
		}
		if err := cur.Cert.CheckSignatureFrom(parent.Cert); err == nil {
			extended = true
			l.enumerate(parent, visited, acc, out)
		}
	}
	if !extended {
		// Dead end: still report the partial path so expired/broken paths are
		// visible in the UI.
		*out = append(*out, acc)
	}
}
