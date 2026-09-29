package lab

import (
	"crypto/x509"
	"fmt"
	"time"
)

// PathNode is one certificate in a candidate validation path.
type PathNode struct {
	CertID    string `json:"certId"`
	EntityID  string `json:"entityId"`
	Subject   string `json:"subject"`
	Version   int    `json:"version"`
	IsRoot    bool   `json:"isRoot"`
	Cross     bool   `json:"cross"`
	Revoked   bool   `json:"revoked"`
	Expired   bool   `json:"expired"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

// PathResult describes one candidate chain from leaf to a root.
type PathResult struct {
	Nodes        []PathNode `json:"nodes"`
	RootCertID   string     `json:"rootCertId"`
	RootEntityID string     `json:"rootEntityId"`
	Trusted      bool       `json:"trusted"` // root is a configured trust anchor
	Valid        bool       `json:"valid"`   // full cryptographic + policy verdict
	Reasons      []string   `json:"reasons"`
	Label        string     `json:"label"` // e.g. "old chain" / "new chain"
}

// VerifyResult aggregates all candidate paths for a leaf.
type VerifyResult struct {
	LeafCertID string       `json:"leafCertId"`
	Purpose    string       `json:"purpose"`
	At         time.Time    `json:"at"`
	Valid      bool         `json:"valid"`
	ChosenPath *PathResult  `json:"chosenPath,omitempty"`
	Paths      []PathResult `json:"paths"`
}

type keyGroup struct {
	entityID string
	version  int
}

// groups returns all certificate IDs carrying the same (entity, version) key:
// the original certificate plus every cross-certificate of it.
func (st *State) groups() map[keyGroup][]string {
	m := map[keyGroup][]string{}
	for id, c := range st.Certificates {
		g := keyGroup{c.EntityID, c.Version}
		m[g] = append(m[g], id)
	}
	return m
}

// Verify evaluates the leaf certificate version against a set of trusted root
// certificate IDs. Every candidate chain is examined so a root migration can
// show which path works under the old root and which under the new root.
func (s *Store) Verify(leafCertID, purpose string, trustedRootCertIDs []string, at time.Time) (*VerifyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	leaf, ok := s.st.Certificates[leafCertID]
	if !ok {
		return nil, fmt.Errorf("certificate %s not found", leafCertID)
	}
	if at.IsZero() {
		at = time.Now()
	}

	groups := s.st.groups()
	trusted := map[string]bool{}
	for _, id := range trustedRootCertIDs {
		trusted[id] = true
	}

	// Enumerate every path by expanding cross-cert alternatives at each hop.
	var chains [][]*Certificate
	var walk func(current *Certificate, acc []*Certificate, seen map[string]bool)
	walk = func(current *Certificate, acc []*Certificate, seen map[string]bool) {
		if seen[current.ID] {
			return
		}
		seen[current.ID] = true
		acc = append(acc, current)
		if current.IssuerID == "" {
			chains = append(chains, append([]*Certificate{}, acc...))
			return
		}
		issuer, ok := s.st.Certificates[current.IssuerID]
		if !ok {
			return // dangling issuer; path cannot complete
		}
		for _, altID := range groups[keyGroup{issuer.EntityID, issuer.Version}] {
			walk(s.st.Certificates[altID], acc, seen)
		}
	}
	walk(leaf, nil, map[string]bool{})

	res := &VerifyResult{LeafCertID: leafCertID, Purpose: purpose, At: at}
	rootLabels := map[string]string{}
	for i, ch := range chains {
		pr := s.evaluatePath(ch, purpose, trusted, at)
		root := ch[len(ch)-1]
		if rootLabels[root.EntityID] == "" {
			rootLabels[root.EntityID] = chainLabel(root.EntityID, rootLabels)
		}
		pr.Label = rootLabels[root.EntityID]
		_ = i
		if pr.Valid && res.ChosenPath == nil {
			cur := pr
			res.ChosenPath = &cur
		}
		res.Paths = append(res.Paths, pr)
	}
	res.Valid = res.ChosenPath != nil
	return res, nil
}

func chainLabel(rootEntityID string, existing map[string]string) string {
	n := len(existing)
	if n == 0 {
		return "old chain"
	}
	if n == 1 {
		return "new chain"
	}
	return fmt.Sprintf("chain %d", n+1)
}

func (s *Store) evaluatePath(chain []*Certificate, purpose string, trusted map[string]bool, at time.Time) PathResult {
	pr := PathResult{}
	root := chain[len(chain)-1]
	pr.RootCertID = root.ID
	pr.RootEntityID = root.EntityID
	pr.Trusted = trusted[root.ID]
	reasons := []string{}

	x509s := make([]*x509.Certificate, len(chain))
	for i, c := range chain {
		node := PathNode{
			CertID: c.ID, EntityID: c.EntityID, Subject: c.Subject,
			Version: c.Version, IsRoot: c.IssuerID == "", Cross: c.CrossSignedBy != "",
			Revoked: c.Revoked, NotBefore: c.NotBefore.Format(time.RFC3339),
			NotAfter: c.NotAfter.Format(time.RFC3339),
		}
		if at.Before(c.NotBefore) {
			node.Expired = true // not yet valid
			reasons = append(reasons, fmt.Sprintf("%s not yet valid", c.Subject))
		}
		if at.After(c.NotAfter) {
			node.Expired = true
			reasons = append(reasons, fmt.Sprintf("%s expired", c.Subject))
		}
		if c.Revoked {
			reasons = append(reasons, fmt.Sprintf("%s revoked", c.Subject))
		}
		pr.Nodes = append(pr.Nodes, node)
		xc, err := parsePEMCert(c.PEM)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("%s unparseable", c.Subject))
			continue
		}
		x509s[i] = xc
	}

	if !pr.Trusted {
		reasons = append(reasons, "root is not a configured trust anchor")
	}

	// Cryptographic + purpose validation with exactly this chain, anchored at
	// exactly this root, so each old/new path gets an independent verdict.
	if pr.Trusted && len(x509s) == len(chain) {
		roots := x509.NewCertPool()
		roots.AddCert(x509s[len(x509s)-1])
		intermediates := x509.NewCertPool()
		for _, xc := range x509s[1 : len(x509s)-1] {
			intermediates.AddCert(xc)
		}
		usage := x509.ExtKeyUsageServerAuth
		switch purpose {
		case "clientAuth":
			usage = x509.ExtKeyUsageClientAuth
		case "any":
			usage = x509.ExtKeyUsageAny
		}
		_, err := x509s[0].Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: intermediates, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{usage},
		})
		if err != nil {
			reasons = append(reasons, humanVerifyError(err))
		}
	}

	pr.Reasons = reasons
	pr.Valid = pr.Trusted && len(reasons) == 0 && len(x509s) == len(chain)
	return pr
}

func humanVerifyError(err error) string {
	switch e := err.(type) {
	case x509.CertificateInvalidError:
		switch e.Reason {
		case x509.Expired:
			return "certificate outside validity period"
		case x509.CANotAuthorizedForThisName:
			return "name constraint violation"
		}
		return "invalid certificate: " + err.Error()
	case x509.UnknownAuthorityError:
		return "signature or authority mismatch"
	}
	return err.Error()
}
