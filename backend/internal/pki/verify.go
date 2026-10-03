package pki

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// ChainStatus is the tri-state verdict of one candidate path.
type ChainStatus string

const (
	// StatusValid: every check passed; the path can be adopted.
	StatusValid ChainStatus = "valid"
	// StatusDisqualified: a definitive failure (expiry, revocation, wrong
	// purpose, untrusted or out-of-scope root, broken signature, CRL hit).
	StatusDisqualified ChainStatus = "disqualified"
	// StatusUndetermined: not provably bad, but evidence is missing (no
	// CRL published, or revocation data not yet valid / stale).
	StatusUndetermined ChainStatus = "undetermined"
)

// Policy captures the per-experiment selection preferences and mandatory
// conditions. It is stored inside each evidence record so a later review
// shows exactly which rules basis produced the selection.
type Policy struct {
	// AllowedRoots restricts acceptable trust anchors for this experiment.
	// Empty means every currently trusted root is acceptable.
	AllowedRoots []string `json:"allowedRoots,omitempty"`
	// PreferredRoots orders root IDs by preference; among valid paths the
	// one ending at the earliest listed root is adopted.
	PreferredRoots []string `json:"preferredRoots,omitempty"`
	// RequireCRL makes complete revocation data mandatory: paths with
	// missing or not-yet-valid CRLs become disqualified instead of
	// undetermined.
	RequireCRL bool `json:"requireCrl,omitempty"`
}

func (p *Policy) normalized() *Policy {
	if p == nil {
		return &Policy{}
	}
	out := &Policy{RequireCRL: p.RequireCRL}
	out.AllowedRoots = append(out.AllowedRoots, p.AllowedRoots...)
	out.PreferredRoots = append(out.PreferredRoots, p.PreferredRoots...)
	return out
}

func (p *Policy) rootAllowed(id string) bool {
	if len(p.AllowedRoots) == 0 {
		return true
	}
	for _, r := range p.AllowedRoots {
		if r == id {
			return true
		}
	}
	return false
}

func (p *Policy) rootRank(id string) int {
	for i, r := range p.PreferredRoots {
		if r == id {
			return i
		}
	}
	return len(p.PreferredRoots)
}

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
	Path   []PathStep  `json:"path"`
	Valid  bool        `json:"valid"`
	Status ChainStatus `json:"status"`
	Reason string      `json:"reason,omitempty"`
	// Basis lists every material item this path's verdict actually relied
	// on, each with its effective and acquisition times.
	Basis []MaterialBasis `json:"basis,omitempty"`
}

// MaterialBasis is one piece of material a path verdict rests on: what it
// is, when it takes effect, and when the researcher obtained it. Exports
// use this to show what was known by the knowledge cutoff instead of
// claiming later evidence was already verified at the event time.
type MaterialBasis struct {
	Kind       string     `json:"kind"` // cert / trust / revocation / crl
	ID         string     `json:"id"`
	Detail     string     `json:"detail"`
	Effective  *time.Time `json:"effective,omitempty"`
	AcquiredAt time.Time  `json:"acquiredAt"`
}

// VerifyResult is one immutable verification answer.
type VerifyResult struct {
	EvidenceID   int       `json:"evidenceId"`
	RulesVersion int       `json:"rulesVersion"`
	LeafID       string    `json:"leafId"`
	Purpose      string    `json:"purpose"`
	Policy       *Policy   `json:"policy"`
	CheckedAt    time.Time `json:"checkedAt"`
	// EventTime is the moment under investigation; KnowledgeCutoff is the
	// moment up to which obtained material may be used. The two differ
	// when, e.g., a revocation notice arrived late but shows the
	// certificate was already invalid at the event.
	EventTime       time.Time     `json:"eventTime"`
	KnowledgeCutoff time.Time     `json:"knowledgeCutoff"`
	Valid           bool          `json:"valid"`
	Status          ChainStatus   `json:"status"`
	Reason          string        `json:"reason,omitempty"`
	SelectedPath    []string      `json:"selectedPath,omitempty"`
	Chains          []ChainReport `json:"chains"`
	TrustedRoots    []string      `json:"trustedRoots"`
}

// Verify performs a verification at the current lab clock using all
// material obtained so far. See VerifyAt.
func (l *Lab) Verify(leafID string, purpose EKU, policy *Policy) (*VerifyResult, error) {
	return l.VerifyAt(leafID, purpose, policy, nil, nil)
}

// VerifyAt performs a historical investigation of leafID for the requested
// purpose (serverAuth/clientAuth), appends an immutable evidence record and
// returns it. eventTime is the moment under investigation; knowledgeCutoff
// limits which obtained material may be consulted (nil defaults both to
// the lab clock). It evaluates every candidate trust path for:
//   - cryptographic signatures (stdlib x509 chain building),
//   - purpose (ExtKeyUsage on the leaf),
//   - validity period of every certificate at the event time,
//   - trust anchor as trusted at the event time, per material obtained by
//     the knowledge cutoff,
//   - revocation material obtained by the cutoff and covering the event.
//
// A single correct signature can never make the result valid: the whole
// chain must satisfy every check. Cross-signed intermediates surface as
// multiple candidate paths (old chain and new chain); expired or broken
// paths are still shown with the reason they failed.
func (l *Lab) VerifyAt(leafID string, purpose EKU, policy *Policy, eventTime, knowledgeCutoff *time.Time) (*VerifyResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	pol := policy.normalized()
	now := l.nowFunc()
	event := now.UTC()
	if eventTime != nil {
		event = eventTime.UTC()
	}
	cutoff := now.UTC()
	if knowledgeCutoff != nil {
		cutoff = knowledgeCutoff.UTC()
	}
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
		CheckedAt: now.UTC(), Policy: pol,
		EventTime: event, KnowledgeCutoff: cutoff,
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
		report := ChainReport{Status: StatusValid}
		// chain order: leaf ... root; present root-first.
		for i := len(chain) - 1; i >= 0; i-- {
			c := chain[i]
			step := PathStep{
				ID: c.ID, Label: c.Label, Kind: c.Kind,
				Subject: c.Cert.Subject.String(), Issuer: c.Cert.Issuer.String(),
				NotBefore: c.Cert.NotBefore, NotAfter: c.Cert.NotAfter,
				Expired: event.Before(c.Cert.NotBefore) || event.After(c.Cert.NotAfter),
				Revoked: c.Revoked, CRLPublished: c.CRLPublished,
			}
			if c.Kind == KindRoot {
				step.Trusted = l.trust[c.ID]
			}
			report.Path = append(report.Path, step)
		}

		var basis []MaterialBasis
		status, reason, basis := l.evaluateChain(chain, wantEKU, event, cutoff, pol)
		report.Basis = basis
		if status != StatusValid {
			report.Status = status
			report.Reason = reason
		}
		report.Valid = report.Status == StatusValid
		res.Chains = append(res.Chains, report)
	}

	// Adopt the valid path whose root ranks best under the experiment's
	// preferred-roots list (ties keep enumeration order).
	best := -1
	for i := range res.Chains {
		if res.Chains[i].Status != StatusValid {
			continue
		}
		if best == -1 || pol.rootRank(res.Chains[i].Path[0].ID) < pol.rootRank(res.Chains[best].Path[0].ID) {
			best = i
		}
	}
	if best >= 0 {
		res.Valid = true
		res.Status = StatusValid
		res.SelectedPath = idsOfPath(res.Chains[best].Path)
	} else {
		undetermined := false
		for _, ch := range res.Chains {
			if ch.Status == StatusUndetermined {
				undetermined = true
			}
		}
		if undetermined {
			res.Status = StatusUndetermined
		} else {
			res.Status = StatusDisqualified
		}
		res.Reason = summarize(res.Chains)
	}
	l.history = append(l.history, res)
	res.EvidenceID = len(l.history)
	return res, nil
}

func idsOfPath(path []PathStep) []string {
	ids := make([]string, 0, len(path))
	for _, s := range path {
		ids = append(ids, s.ID)
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
		if r.Status != StatusValid && !seen[r.Reason] {
			seen[r.Reason] = true
			prefix := "disqualified: "
			if r.Status == StatusUndetermined {
				prefix = "undetermined: "
			}
			reasons = append(reasons, prefix+r.Reason)
		}
	}
	return strings.Join(reasons, "; ")
}

// evaluateChain returns the tri-state verdict of one candidate path at
// (event, cutoff) plus the material basis the verdict rests on. Hard
// failures (expiry at the event, revocation known by the cutoff, purpose,
// anchor, signatures, CRL hits) are disqualified; material missing at the
// cutoff only makes the path undetermined unless the experiment policy
// requires complete CRLs.
func (l *Lab) evaluateChain(chain []*Cert, wantEKU x509.ExtKeyUsage, event, cutoff time.Time, pol *Policy) (ChainStatus, string, []MaterialBasis) {
	leaf := chain[0]
	var basis []MaterialBasis
	add := func(b MaterialBasis) { basis = append(basis, b) }

	hasPurpose := false
	for _, u := range leaf.Cert.ExtKeyUsage {
		if u == wantEKU {
			hasPurpose = true
		}
	}
	if !hasPurpose {
		return StatusDisqualified, "purpose not permitted by certificate ExtKeyUsage", basis
	}

	// Material availability, validity period at the event, revocation
	// state known by the cutoff and CA basic constraints for every
	// certificate in the path. Checking these first makes the failure
	// reason precise instead of hiding it behind a generic verify error.
	for _, c := range chain {
		add(MaterialBasis{
			Kind: "cert", ID: c.ID,
			Detail:     fmt.Sprintf("certificate %q validity %s .. %s", c.Label, c.Cert.NotBefore.Format(time.RFC3339), c.Cert.NotAfter.Format(time.RFC3339)),
			AcquiredAt: c.AcquiredAt,
		})
		if c.AcquiredAt.After(cutoff) {
			return withBasis(missingCRLVerdict(pol, fmt.Sprintf("certificate %q material acquired only at %s, after the knowledge cutoff", c.Label, c.AcquiredAt.Format(time.RFC3339))), basis)
		}
		if event.Before(c.Cert.NotBefore) {
			return StatusDisqualified, fmt.Sprintf("certificate %q not yet valid at the event time", c.Label), basis
		}
		if event.After(c.Cert.NotAfter) {
			return StatusDisqualified, fmt.Sprintf("certificate %q expired at the event time", c.Label), basis
		}
		if revoked, revBasis := revocationAt(l.revLog, c.ID, event, cutoff); revoked {
			add(MaterialBasis{
				Kind: "revocation", ID: c.ID,
				Detail:     fmt.Sprintf("revocation notice for %q (effective %s)", c.Label, revBasis.RevokedAt.Format(time.RFC3339)),
				Effective:  &revBasis.RevokedAt,
				AcquiredAt: revBasis.AcquiredAt,
			})
			return StatusDisqualified, fmt.Sprintf("certificate %q revoked at %s (notice acquired %s)", c.Label, revBasis.RevokedAt.Format(time.RFC3339), revBasis.AcquiredAt.Format(time.RFC3339)), basis
		}
		if c != leaf && !c.Cert.IsCA {
			return StatusDisqualified, fmt.Sprintf("certificate %q is not a CA", c.Label), basis
		}
	}

	root := chain[len(chain)-1]
	if root.Kind != KindRoot || root.Cert.Subject.String() != root.Cert.Issuer.String() {
		return StatusDisqualified, "chain does not end at a self-signed root", basis
	}
	trusted, found, trustBasis := trustAt(l.trustLog, root.ID, event, cutoff)
	if !found {
		return withBasis(missingCRLVerdict(pol, fmt.Sprintf("no trust material for root %q covers the event time (acquired by the cutoff)", root.Label)), basis)
	}
	add(MaterialBasis{
		Kind: "trust", ID: root.ID,
		Detail:     fmt.Sprintf("root %q trusted=%v", root.Label, trustBasis.Trusted),
		Effective:  &trustBasis.EffectiveFrom,
		AcquiredAt: trustBasis.AcquiredAt,
	})
	if !trusted {
		return StatusDisqualified, fmt.Sprintf("root %q is not a trusted anchor at the event time", root.Label), basis
	}
	if !pol.rootAllowed(root.ID) {
		return StatusDisqualified, fmt.Sprintf("root %q is outside this experiment's allowed roots", root.Label), basis
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
		CurrentTime:   event,
		KeyUsages:     []x509.ExtKeyUsage{wantEKU},
	}); err != nil {
		return StatusDisqualified, "chain verification failed: " + err.Error(), basis
	}

	// Revocation data for every issuing CA, restricted to material
	// obtained by the knowledge cutoff and covering the event time.
	// Missing, late or non-covering revocation data makes the path
	// undetermined (or disqualified when the policy mandates complete
	// CRLs); a CRL that lists a path certificate with a revocation time
	// at or before the event is a definitive disqualification. Each CA's
	// CRL is consulted under that CA's own logical node, so a cross
	// certificate's missing publication flag cannot mask the original
	// CA's CRL.
	for _, issuerNode := range chain[1:] {
		ca := l.canonicalIssuerLocked(issuerNode)
		if !issuerNode.CRLPublished || !ca.CRLPublished {
			return withBasis(missingCRLVerdict(pol, fmt.Sprintf("revocation data missing for CA %q", issuerNode.Label)), basis)
		}
		der, err := l.buildCRLLocked(ca, cutoff)
		if err != nil {
			return withBasis(missingCRLVerdict(pol, "CRL unavailable for "+issuerNode.Label+": "+err.Error()), basis)
		}
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			return StatusDisqualified, "invalid CRL from " + issuerNode.Label, basis
		}
		if err := crl.CheckSignatureFrom(ca.Cert); err != nil {
			return StatusDisqualified, "CRL signature invalid for " + issuerNode.Label, basis
		}
		add(MaterialBasis{
			Kind: "crl", ID: ca.ID,
			Detail:     fmt.Sprintf("CRL of %q covering %s .. %s", ca.Label, crl.ThisUpdate.Format(time.RFC3339), crl.NextUpdate.Format(time.RFC3339)),
			Effective:  &crl.ThisUpdate,
			AcquiredAt: crl.ThisUpdate,
		})
		if cutoff.Before(crl.ThisUpdate) {
			return withBasis(missingCRLVerdict(pol, fmt.Sprintf("revocation data for CA %q not yet acquired by the knowledge cutoff (late CRL)", issuerNode.Label)), basis)
		}
		if event.Before(crl.ThisUpdate) || event.After(crl.NextUpdate) {
			return withBasis(missingCRLVerdict(pol, fmt.Sprintf("no revocation data from CA %q covers the event time", issuerNode.Label)), basis)
		}
		for _, entry := range crl.RevokedCertificateEntries {
			for _, c := range chain {
				if c.Cert.SerialNumber.Cmp(entry.SerialNumber) == 0 && !entry.RevocationTime.After(event) {
					return StatusDisqualified, fmt.Sprintf("certificate %q listed on CRL of %q", c.Label, ca.Label), basis
				}
			}
		}
	}
	return StatusValid, "", basis
}

// verdict is a status/reason pair so it can be threaded through withBasis.
type verdict struct {
	status ChainStatus
	reason string
}

func missingCRLVerdict(pol *Policy, reason string) verdict {
	if pol.RequireCRL {
		return verdict{StatusDisqualified, reason + " (policy requires complete revocation data)"}
	}
	return verdict{StatusUndetermined, reason}
}

// withBasis attaches the accumulated material basis to a verdict pair.
func withBasis(v verdict, basis []MaterialBasis) (ChainStatus, string, []MaterialBasis) {
	return v.status, v.reason, basis
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
