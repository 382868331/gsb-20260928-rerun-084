package pki

import (
	"crypto/x509"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Lab holds the whole fictional PKI experiment in memory. All verification
// reads state live: results are never cached, so a revocation takes effect on
// the very next verification.
type Lab struct {
	mu      sync.RWMutex
	seq     atomic.Uint64
	certs   map[string]*Cert
	trust   map[string]bool // logical root IDs currently trusted
	nowFunc func() time.Time
}

func NewLab() *Lab {
	return &Lab{
		certs:   map[string]*Cert{},
		trust:   map[string]bool{},
		nowFunc: time.Now,
	}
}

func (l *Lab) Now() time.Time { return l.nowFunc() }

// SetClock overrides the lab clock (tests/demos of expiry).
func (l *Lab) SetClock(f func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nowFunc = f
}

func (l *Lab) Get(id string) (*Cert, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	c, ok := l.certs[id]
	return c, ok
}

func (l *Lab) List() []*Cert {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]*Cert, 0, len(l.certs))
	for _, c := range l.certs {
		out = append(out, c)
	}
	return out
}

func (l *Lab) put(c *Cert) { l.certs[c.ID] = c }

// AddRoot creates and trusts a new root.
func (l *Lab) AddRoot(id, cn string, years int) (*Cert, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.nowFunc()
	c, err := CreateRoot(id, cn, now.Add(-time.Minute), now.AddDate(years, 0, 0), &l.seq)
	if err != nil {
		return nil, err
	}
	l.put(c)
	l.trust[id] = true
	return c, nil
}

// AddIntermediate issues an intermediate under issuerID. When crossSubjectID
// is set, a cross certificate for that existing intermediate is created
// instead of a fresh key (used during root migration).
func (l *Lab) AddIntermediate(id, cn, issuerID, crossSubjectID string, notBefore, notAfter time.Time) (*Cert, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	issuer, ok := l.certs[issuerID]
	if !ok {
		return nil, fmt.Errorf("issuer %q not found", issuerID)
	}
	opts := IssueOptions{
		ID: id, Label: cn, CN: cn, Intermediate: true,
		NotBefore: notBefore, NotAfter: notAfter,
	}
	var override *Cert
	if crossSubjectID != "" {
		sub, ok := l.certs[crossSubjectID]
		if !ok {
			return nil, fmt.Errorf("cross subject %q not found", crossSubjectID)
		}
		override = sub
		opts.Label = cn
	}
	c, err := Issue(issuer, opts, override, &l.seq)
	if err != nil {
		return nil, err
	}
	l.put(c)
	return c, nil
}

// AddLeaf issues an end-entity certificate for the given purposes.
func (l *Lab) AddLeaf(id, cn, issuerID string, ekus []EKU, dnsNames []string, days int) (*Cert, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	issuer, ok := l.certs[issuerID]
	if !ok {
		return nil, fmt.Errorf("issuer %q not found", issuerID)
	}
	if issuer.Kind == KindLeaf {
		return nil, fmt.Errorf("cannot issue from a leaf certificate")
	}
	now := l.nowFunc()
	c, err := Issue(issuer, IssueOptions{
		ID: id, Label: cn, CN: cn, EKUs: ekus, DNSNames: dnsNames,
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(0, 0, days),
	}, nil, &l.seq)
	if err != nil {
		return nil, err
	}
	l.put(c)
	return c, nil
}

// RotateLeaf re-issues an end-entity certificate under the same issuer with a
// fresh key and validity window. The old certificate is retained as evidence
// and marked as superseded (it is not automatically revoked).
func (l *Lab) RotateLeaf(oldID, newID string, days int) (*Cert, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	old, ok := l.certs[oldID]
	if !ok {
		return nil, fmt.Errorf("cert %q not found", oldID)
	}
	if old.Kind != KindLeaf {
		return nil, fmt.Errorf("cert %q is not a leaf", oldID)
	}
	issuer, ok := l.certs[old.IssuerID]
	if !ok {
		return nil, fmt.Errorf("issuer %q not found", old.IssuerID)
	}
	now := l.nowFunc()
	ekus := make([]EKU, 0, len(old.Cert.ExtKeyUsage))
	for _, u := range old.Cert.ExtKeyUsage {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			ekus = append(ekus, EKUServer)
		case x509.ExtKeyUsageClientAuth:
			ekus = append(ekus, EKUClient)
		}
	}
	c, err := Issue(issuer, IssueOptions{
		ID: newID, Label: old.Label + " (rotated)", CN: old.Cert.Subject.CommonName,
		EKUs: ekus, DNSNames: append([]string{}, old.Cert.DNSNames...),
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(0, 0, days),
	}, nil, &l.seq)
	if err != nil {
		return nil, err
	}
	l.put(c)
	old.SupersededBy = newID
	return c, nil
}

// SetCRLPublished toggles whether a CA publishes revocation data. When
// published is false the lab simulates a CA whose CRL endpoint is missing,
// which must fail chains that require revocation evidence.
func (l *Lab) SetCRLPublished(caID string, published bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.certs[caID]
	if !ok {
		return fmt.Errorf("ca %q not found", caID)
	}
	c.CRLBlocked = !published
	return nil
}

// SetTrust marks a root as trusted (anchor) or distrusted. Old and new roots
// can coexist during migration so both chains validate until cut-over.
func (l *Lab) SetTrust(rootID string, trusted bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.certs[rootID]
	if !ok || c.Kind != KindRoot {
		return fmt.Errorf("root %q not found", rootID)
	}
	l.trust[rootID] = trusted
	return nil
}

func (l *Lab) TrustedRoots() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var ids []string
	for id, ok := range l.trust {
		if ok {
			ids = append(ids, id)
		}
	}
	return ids
}

// Revoke marks a certificate revoked. The next live verification sees it.
func (l *Lab) Revoke(id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.certs[id]
	if !ok {
		return fmt.Errorf("cert %q not found", id)
	}
	if !c.Revoked {
		c.Revoked = true
		c.RevokedAt = l.nowFunc().UTC()
	}
	return nil
}

// CRL renders a fresh X.509 CRL for a CA node containing every currently
// revoked certificate that the CA issued. It is generated on demand, so it
// can never serve stale revocation data.
func (l *Lab) CRL(caID string) ([]byte, error) {
	l.mu.RLock()
	ca, ok := l.certs[caID]
	blocked := false
	if ok {
		blocked = ca.CRLBlocked
	}
	l.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("ca %q not found", caID)
	}
	if blocked {
		return nil, fmt.Errorf("CA %q does not publish revocation data (CRL unavailable)", caID)
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.buildCRLLocked(ca)
}
