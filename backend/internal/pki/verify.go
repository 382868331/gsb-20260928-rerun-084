package pki

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// PathStep describes one node of a candidate verification path.
type PathStep struct {
	ID           string    `json:"id"`
	Label        string    `json:"label"`
	Kind         NodeKind  `json:"kind"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	Expired      bool      `json:"expired"`
	Revoked      bool      `json:"revoked"`
	CRLPublished bool      `json:"crlPublished"`
	Trusted      bool      `json:"trusted,omitempty"`
}

// ChainReport is one attempted root-to-leaf path with its evaluation.
type ChainReport struct {
	Path   []PathStep `json:"path"`
	Valid  bool       `json:"valid"`
	Reason string     `json:"reason,omitempty"`
}

// VerifyResult is one immutable verification answer.
type VerifyResult struct {
	EvidenceID   int           `json:"evidenceId"`
	RulesVersion int           `json:"rulesVersion"`
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
// (serverAuth/clientAuth), appends an immutable evidence record and returns
// it. It evaluates every candidate trust path for:
//   - cryptographic signatures (stdlib x509 chain building),
//   - purpose (ExtKeyUsage on the leaf),
//   - validity period of every certificate in the path,
//   - trust anchor (only currently trusted roots),
//   - revocation, re-read from live state and a freshly generated CRL.
//
// A single correct signature can never make the result valid: the whole
// chain must satisfy every check. Cross-signed intermediates surface as
// multiple candidate paths (old chain and new chain); expired or broken
// paths are still shown with the reason they failed.
func (l *Lab) Verify(leafID string, purpose EKU) (*VerifyResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.nowFunc()
	leaf, ok := l.certs[leafID]
	if !ok {
		return nil, fmt.Errorf("leaf %q not found", leafID)
	}
	if leaf.Kind != KindLeaf {
		return nil, fmt.Errorf("%q is not a leaf certificate", leafID)
	}

	wantEKU, ok := map[EKU]x509.ExtKeyUsage{
		EKUServer: x509.ExtKeyUsageServerAuth,
		EKUClient: x509.ExtKeyUsageClientAuth,
	}[purpose]
	if !ok {
		return nil, fmt.Errorf("unknown purpose %q", purpose)
	}

	res := &VerifyResult{
		RulesVersion: l.rulesVersion, LeafID: leafID, Purpose: string(purpose),
		CheckedAt: now.UTC(),
	}
	for id := range l.trust {
		if l.trust[id] {
			res.TrustedRoots = append(res.TrustedRoots, id)
		}
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
				NotBefore: c.Cert.NotBefore, NotAfter: c.Cert.NotAfter,
				Expired: now.Before(c.Cert.NotBefore) || now.After(c.Cert.NotAfter),
				Revoked: c.Revoked, CRLPublished: c.CRLPublished,
			}
			if c.Kind == KindRoot {
				step.Trusted = l.trust[c.ID]
			}
			report.Path = append(report.Path, step)
		}

		if reason := l.evaluateChain(chain, wantEKU, now); reason != "" {
			report.Valid = false
			report.Reason = reason
		}
		res.Chains = append(res.Chains, report)
		if report.Valid && !res.Valid {
			res.Valid = true
			res.SelectedPath = idsOf(chain)
		}
	}

	if !res.Valid {
		res.Reason = summarize(res.Chains)
	}
	l.history = append(l.history, res)
	res.EvidenceID = len(l.history)
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

	// Validity period, revocation state and CA basic constraints for every
	// certificate in the path. Checking these first makes the failure reason
	// precise instead of hiding it behind a generic stdlib verify error.
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
	if root.Kind != KindRoot || root.Cert.Subject.String() != root.Cert.Issuer.String() {
		return "chain does not end at a self-signed root"
	}
	if !l.trust[root.ID] {
		return fmt.Sprintf("root %q is not a trusted anchor", root.Label)
	}

	// Cryptographic confirmation of the whole path via the standard library.
	// A correct signature on one certificate does not help if another hop is
	// missing: this verifies the complete leaf->root chain.
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

	// Freshly generated revocation data for every issuing CA. Missing CRL
	// publication, stale CRLs, bad CRL signatures or listed serials all fail
	// the path. Each CA's CRL is consulted under that CA's own logical node,
	// so a cross certificate's missing publication flag cannot mask the
	// original CA's CRL.
	for _, issuerNode := range chain[1:] {
		ca := l.canonicalIssuerLocked(issuerNode)
		if !issuerNode.CRLPublished || !ca.CRLPublished {
			return fmt.Sprintf("revocation data missing for CA %q", issuerNode.Label)
		}
		der, err := l.buildCRLLocked(ca)
		if err != nil {
			return "CRL unavailable for " + issuerNode.Label + ": " + err.Error()
		}
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			return "invalid CRL from " + issuerNode.Label
		}
		if err := crl.CheckSignatureFrom(ca.Cert); err != nil {
			return "CRL signature invalid for " + issuerNode.Label
		}
		if now.Before(crl.ThisUpdate) || now.After(crl.NextUpdate) {
			return "stale CRL from " + issuerNode.Label
		}
		for _, entry := range crl.RevokedCertificateEntries {
			for _, c := range chain {
				if c.Cert.SerialNumber.Cmp(entry.SerialNumber) == 0 {
					return fmt.Sprintf("certificate %q listed on CRL of %q", c.Label, ca.Label)
				}
			}
		}
	}
	return ""
}

// enumerate DFS-walks all parents that cryptographically signed the current
// certificate. A cross certificate shares subject DN and public key with the
// original intermediate, so both appear as candidate parents, producing the
// old-root and new-root paths during migration. Each branch gets its own
// visited set so sibling paths do not mask one another.
func (l *Lab) enumerate(cur *Cert, visited map[string]bool, acc []*Cert, out *[][]*Cert) {
	acc = append(append([]*Cert{}, acc...), cur)
	visited[cur.ID] = true
	selfSigned := cur.Kind == KindRoot && cur.Cert.Subject.String() == cur.Cert.Issuer.String()
	if selfSigned {
		*out = append(*out, acc)
		return
	}
	extended := false
	for _, parent := range l.certs {
		if visited[parent.ID] || !parent.Cert.IsCA {
			continue
		}
		if err := cur.Cert.CheckSignatureFrom(parent.Cert); err == nil {
			next := map[string]bool{}
			for k, v := range visited {
				next[k] = v
			}
			extended = true
			l.enumerate(parent, next, acc, out)
		}
	}
	if !extended {
		// Dead end: still report the partial path so expired/broken paths are
		// visible in the UI.
		*out = append(*out, acc)
	}
}
