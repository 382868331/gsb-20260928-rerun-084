package pki

import (
	"crypto/x509"
	"fmt"
	"sort"
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

// ChainStatus is the tri-state outcome of one candidate path:
//   - valid:   every check passed; the path is eligible for selection;
//   - invalid: a definitive failure (expired, revoked, wrong purpose,
//     untrusted anchor, broken signature, ...);
//   - unknown: not provably bad, but evidence is missing (e.g. revocation
//     data unavailable), so the path cannot be confirmed either way.
type ChainStatus string

const (
	ChainValid   ChainStatus = "valid"
	ChainInvalid ChainStatus = "invalid"
	ChainUnknown ChainStatus = "unknown"
)

// Chain decisions recorded in the evidence, so a later review can see why
// each candidate path was adopted or set aside.
const (
	DecisionSelected  = "selected"        // adopted path
	DecisionCandidate = "candidate"       // valid but not chosen by policy
	DecisionExcluded  = "excluded-policy" // set aside by experiment policy
	DecisionInvalid   = "invalid"         // definitively ineligible
	DecisionUnknown   = "unknown"         // evidence missing, undecidable
)

// Policy captures per-experiment path-selection preferences. A snapshot is
// stored inside every evidence record so the original selection rationale
// and its rule basis are never replaced by later experiments.
type Policy struct {
	// AllowedRoots restricts acceptable trust anchors for this experiment.
	// Empty means every currently trusted root is in scope.
	AllowedRoots []string `json:"allowedRoots,omitempty"`
	// RootPriority orders eligible roots by preference (first = most
	// preferred). Roots not listed rank after all listed ones.
	RootPriority []string `json:"rootPriority,omitempty"`
	// RequireCRL makes complete revocation data a hard requirement:
	// paths with missing CRL data become invalid instead of unknown.
	RequireCRL bool `json:"requireCRL,omitempty"`
	// MaxPathLength caps the number of certificates per path (0 = no cap).
	MaxPathLength int `json:"maxPathLength,omitempty"`
}

// ChainReport is one attempted root-to-leaf path with its evaluation.
type ChainReport struct {
	Path     []PathStep  `json:"path"`
	Status   ChainStatus `json:"status"`
	Decision string      `json:"decision"`
	// Valid is kept for backwards compatibility: true only when the path
	// passed every check (Status == valid).
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
}

// VerifyResult is one immutable verification answer.
type VerifyResult struct {
	EvidenceID   int       `json:"evidenceId"`
	RulesVersion int       `json:"rulesVersion"`
	LeafID       string    `json:"leafId"`
	Purpose      string    `json:"purpose"`
	CheckedAt    time.Time `json:"checkedAt"`
	// Conclusion is "valid", "unknown" (every path lacks evidence) or
	// "invalid". Valid mirrors Conclusion == "valid".
	Conclusion      string        `json:"conclusion"`
	Valid           bool          `json:"valid"`
	Reason          string        `json:"reason,omitempty"`
	SelectedPath    []string      `json:"selectedPath,omitempty"`
	SelectionReason string        `json:"selectionReason,omitempty"`
	Policy          *Policy       `json:"policy,omitempty"`
	Chains          []ChainReport `json:"chains"`
	TrustedRoots    []string      `json:"trustedRoots"`
}

// Verify performs a live verification of leafID for the requested purpose
// (serverAuth/clientAuth) under the given experiment policy (nil = default),
// appends an immutable evidence record and returns it. It evaluates every
// candidate trust path for:
//   - cryptographic signatures (stdlib x509 chain building),
//   - purpose (ExtKeyUsage on the leaf),
//   - validity period of every certificate in the path,
//   - trust anchor (only currently trusted roots),
//   - revocation, re-read from live state and a freshly generated CRL.
//
// A single correct signature can never make the result valid: the whole
// chain must satisfy every check. Cross-signed intermediates surface as
// multiple candidate paths (old chain and new chain); expired or broken
// paths are still shown with the reason they failed, and paths whose
// revocation evidence is missing are reported as "unknown" instead of
// being silently treated as failures. One incomplete path never blocks the
// independent judgment of the remaining complete paths.
func (l *Lab) Verify(leafID string, purpose EKU, policy *Policy) (*VerifyResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if policy == nil {
		policy = &Policy{}
	}
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
		Policy:    policy,
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
		report := ChainReport{Status: ChainValid, Valid: true}
		// chain order: leaf ... root; present root-first.
		for i := len(chain) - 1; i >= 0; i-- {
			c := chain[i]
			step := PathStep{
				ID: c.ID, Label: c.Label, Kind: c.Kind,
				Subject: c.Cert.Subject.String(), Issuer: c.Cert.Issuer.String(),
				NotBefore: c.Cert.NotBefore, NotAfter: c.Cert.NotAfter,
				Expired: now.Before(c.Cert.NotBefore) || now.After(c.Cert.NotAfter),
				Revoked: c.Revoked,
				// Leaves never publish revocation data; only CA nodes carry
				// the "revocation data missing" signal.
				CRLPublished: c.Kind == KindLeaf || c.CRLPublished,
			}
			if c.Kind == KindRoot {
				step.Trusted = l.trust[c.ID]
			}
			report.Path = append(report.Path, step)
		}

		hard, unknown := l.evaluateChain(chain, wantEKU, now)
		switch {
		case hard != "":
			report.Status, report.Valid, report.Reason = ChainInvalid, false, hard
		case unknown != "" && policy.RequireCRL:
			report.Status, report.Valid = ChainInvalid, false
			report.Reason = unknown + " (policy requires complete revocation data)"
		case unknown != "":
			report.Status, report.Valid, report.Reason = ChainUnknown, false, unknown
		}
		res.Chains = append(res.Chains, report)
	}

	l.applyPolicy(res, chains, policy)
	l.history = append(l.history, res)
	res.EvidenceID = len(l.history)
	return res, nil
}

// applyPolicy marks every chain with its decision, selects the adopted path
// among the eligible ones and derives the overall conclusion. The full
// rationale is stored on the result so the evidence remains self-contained.
func (l *Lab) applyPolicy(res *VerifyResult, chains [][]*Cert, policy *Policy) {
	allowed := map[string]bool{}
	for _, id := range policy.AllowedRoots {
		allowed[id] = true
	}
	priority := map[string]int{}
	for i, id := range policy.RootPriority {
		priority[id] = i
	}

	type eligible struct {
		idx  int
		root string
	}
	var eligibleIdx []eligible
	counts := map[string]int{}

	for i := range res.Chains {
		report := &res.Chains[i]
		rootID := chains[i][len(chains[i])-1].ID

		// Experiment scope/hard preference exclusions apply to valid and
		// unknown paths alike.
		if len(allowed) > 0 && !allowed[rootID] && report.Status != ChainInvalid {
			report.Status, report.Valid = ChainInvalid, false
			report.Decision = DecisionExcluded
			report.Reason = withReason(report.Reason, "root "+rootID+" is outside the experiment's allowed roots")
			counts[DecisionExcluded]++
			continue
		}
		if policy.MaxPathLength > 0 && len(chains[i]) > policy.MaxPathLength && report.Status != ChainInvalid {
			report.Status, report.Valid = ChainInvalid, false
			report.Decision = DecisionExcluded
			report.Reason = withReason(report.Reason, "path length exceeds the experiment's maximum")
			counts[DecisionExcluded]++
			continue
		}

		switch report.Status {
		case ChainValid:
			report.Decision = DecisionCandidate
			eligibleIdx = append(eligibleIdx, eligible{i, rootID})
			counts[DecisionCandidate]++
		case ChainUnknown:
			report.Decision = DecisionUnknown
			counts[DecisionUnknown]++
		default:
			report.Decision = DecisionInvalid
			counts[DecisionInvalid]++
		}
	}

	// Rank eligible paths: root priority first (unlisted roots last), then
	// shorter paths, then root id for a deterministic tie-break.
	sort.SliceStable(eligibleIdx, func(a, b int) bool {
		ra, rb := eligibleIdx[a], eligibleIdx[b]
		pa, oka := priority[ra.root]
		pb, okb := priority[rb.root]
		if !oka {
			pa = len(priority)
		}
		if !okb {
			pb = len(priority)
		}
		if pa != pb {
			return pa < pb
		}
		if la, lb := len(chains[ra.idx]), len(chains[rb.idx]); la != lb {
			return la < lb
		}
		return ra.root < rb.root
	})

	if len(eligibleIdx) > 0 {
		sel := eligibleIdx[0]
		res.Valid = true
		res.Conclusion = "valid"
		res.SelectedPath = idsOf(chains[sel.idx])
		res.Chains[sel.idx].Decision = DecisionSelected
		counts[DecisionSelected]++
		counts[DecisionCandidate]--
		res.SelectionReason = fmt.Sprintf(
			"%d candidate path(s): %d eligible, %d excluded by policy, %d ineligible, %d undecidable; adopted path via root %s%s",
			len(res.Chains), counts[DecisionSelected]+counts[DecisionCandidate],
			counts[DecisionExcluded], counts[DecisionInvalid], counts[DecisionUnknown],
			sel.root, priorityNote(policy, sel.root))
		return
	}

	if counts[DecisionUnknown] > 0 {
		res.Conclusion = "unknown"
		res.Reason = "no complete path could be confirmed: " + summarize(res.Chains)
	} else {
		res.Conclusion = "invalid"
		res.Reason = summarize(res.Chains)
	}
	res.SelectionReason = fmt.Sprintf(
		"%d candidate path(s): none eligible (%d excluded by policy, %d ineligible, %d undecidable)",
		len(res.Chains), counts[DecisionExcluded], counts[DecisionInvalid], counts[DecisionUnknown])
}

func priorityNote(policy *Policy, root string) string {
	for i, id := range policy.RootPriority {
		if id == root {
			return fmt.Sprintf(" (root priority #%d)", i+1)
		}
	}
	if len(policy.RootPriority) > 0 {
		return " (root not listed in priority; ranked last)"
	}
	return ""
}

func withReason(existing, extra string) string {
	if existing == "" {
		return extra
	}
	return existing + "; " + extra
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

// evaluateChain splits findings into a definitive failure reason (hard) and
// an undecidable reason (unknown). A hard failure always wins; unknown is
// only returned when nothing definitive disqualifies the path.
func (l *Lab) evaluateChain(chain []*Cert, wantEKU x509.ExtKeyUsage, now time.Time) (hard, unknown string) {
	leaf := chain[0]

	hasPurpose := false
	for _, u := range leaf.Cert.ExtKeyUsage {
		if u == wantEKU {
			hasPurpose = true
		}
	}
	if !hasPurpose {
		return "purpose not permitted by certificate ExtKeyUsage", ""
	}

	// Validity period, revocation state and CA basic constraints for every
	// certificate in the path. Checking these first makes the failure reason
	// precise instead of hiding it behind a generic stdlib verify error.
	for _, c := range chain {
		if now.Before(c.Cert.NotBefore) {
			return fmt.Sprintf("certificate %q not yet valid", c.Label), ""
		}
		if now.After(c.Cert.NotAfter) {
			return fmt.Sprintf("certificate %q expired", c.Label), ""
		}
		if c.Revoked {
			return fmt.Sprintf("certificate %q revoked", c.Label), ""
		}
		if c != leaf && !c.Cert.IsCA {
			return fmt.Sprintf("certificate %q is not a CA", c.Label), ""
		}
	}

	root := chain[len(chain)-1]
	if root.Kind != KindRoot || root.Cert.Subject.String() != root.Cert.Issuer.String() {
		return "chain does not end at a self-signed root", ""
	}
	if !l.trust[root.ID] {
		return fmt.Sprintf("root %q is not a trusted anchor", root.Label), ""
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
		return "chain verification failed: " + err.Error(), ""
	}

	// Freshly generated revocation data for every issuing CA. A listed
	// serial is a definitive failure; missing, stale or otherwise unusable
	// revocation data makes the path undecidable (unknown) rather than
	// silently invalid. Each CA's CRL is consulted under that CA's own
	// logical node, so a cross certificate's missing publication flag
	// cannot mask the original CA's CRL.
	var unknowns []string
	for _, issuerNode := range chain[1:] {
		ca := l.canonicalIssuerLocked(issuerNode)
		if !issuerNode.CRLPublished || !ca.CRLPublished {
			unknowns = append(unknowns, fmt.Sprintf("revocation data missing for CA %q", issuerNode.Label))
			continue
		}
		der, err := l.buildCRLLocked(ca)
		if err != nil {
			unknowns = append(unknowns, "CRL unavailable for "+issuerNode.Label+": "+err.Error())
			continue
		}
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			unknowns = append(unknowns, "invalid CRL from "+issuerNode.Label)
			continue
		}
		if err := crl.CheckSignatureFrom(ca.Cert); err != nil {
			unknowns = append(unknowns, "CRL signature invalid for "+issuerNode.Label)
			continue
		}
		if now.Before(crl.ThisUpdate) || now.After(crl.NextUpdate) {
			unknowns = append(unknowns, "stale CRL from "+issuerNode.Label)
			continue
		}
		for _, entry := range crl.RevokedCertificateEntries {
			for _, c := range chain {
				if c.Cert.SerialNumber.Cmp(entry.SerialNumber) == 0 {
					return fmt.Sprintf("certificate %q listed on CRL of %q", c.Label, ca.Label), ""
				}
			}
		}
	}
	return "", strings.Join(unknowns, "; ")
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
