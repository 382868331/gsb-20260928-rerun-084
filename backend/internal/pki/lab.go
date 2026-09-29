package pki

import (
	"crypto/rand"
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
func (l *Lab) AddIntermediate(id, cn, issuerID, crossSubjectID string, years int) (*Cert, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	issuer, ok := l.certs[issuerID]
	if !ok {
		return nil, fmt.Errorf("issuer %q not found", issuerID)
	}
	now := l.nowFunc()
	opts := IssueOptions{
		ID: id, Label: cn, CN: cn, Intermediate: true,
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(years, 0, 0),
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
	defer l.mu.RUnlock()
	ca, ok := l.certs[caID]
	if !ok {
		return nil, fmt.Errorf("ca %q not found", caID)
	}
	now := l.nowFunc()
	revoked := []x509.RevocationList{}
	for _, c := range l.certs {
		if c.IssuerID == caID && c.Revoked {
			revoked = append(revoked, x509.RevocationList{
				SerialNumber: c.Cert.SerialNumber,
				RevokedAt:    c.RevokedAt,
			})
		}
	}
	tmpl := &x509.RevocationList{
		Number:     l.seq.Add(1),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
		RevokedCertificates: revoked,
	}
	return x509.CreateRevocationList(rand.Reader, tmpl, ca.Cert, ca.Key)
}
