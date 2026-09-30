package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Lab holds the whole fictional PKI experiment in memory. Verification never
// caches its cryptographic answer, but every verification is appended to an
// immutable evidence history. Trust-rule changes bump the rule version so a
// later re-verification can never silently overwrite older evidence.
type Lab struct {
	mu           sync.RWMutex
	seq          atomic.Uint64
	certs        map[string]*Cert
	trust        map[string]bool // logical root IDs currently trusted
	nowFunc      func() time.Time
	history      []*VerifyResult
	rulesVersion int
}

func NewLab() *Lab {
	return &Lab{
		certs:        map[string]*Cert{},
		trust:        map[string]bool{},
		nowFunc:      time.Now,
		rulesVersion: 1,
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
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (l *Lab) put(c *Cert) { l.certs[c.ID] = c }

// AddRoot creates and trusts a new root. A root publishes CRL data by
// default; use SetCRLPublished to demonstrate missing revocation data.
func (l *Lab) AddRoot(id, cn string, years int) (*Cert, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.nowFunc()
	c, err := CreateRoot(id, cn, now.Add(-time.Minute), now.AddDate(years, 0, 0), &l.seq)
	if err != nil {
		return nil, err
	}
	c.CRLPublished = true
	l.put(c)
	l.trust[id] = true
	l.rulesVersion++
	return c, nil
}

// AddIntermediate issues an intermediate under issuerID. When crossSubjectID
// is set, a cross certificate for that existing intermediate is created
// instead of a fresh key (used during root migration).
//
// years may be negative: the resulting certificate is already expired, which
// the lab uses for the "expired intermediate" sample.
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
		NotBefore: normalizeBounds(now, years, false), NotAfter: normalizeBounds(now, years, true),
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
	c.CRLPublished = true
	l.put(c)
	return c, nil
}

// normalizeBounds keeps NotBefore strictly before NotAfter even for the
// negative-duration (already expired) sample certificates.
func normalizeBounds(now time.Time, years int, after bool) time.Time {
	if years < 0 {
		start := now.AddDate(years*2, 0, 0)
		end := now.AddDate(years, 0, 0)
		if after {
			return end
		}
		return start
	}
	if after {
		return now.AddDate(years, 0, 0)
	}
	return now.Add(-time.Minute)
}

// AddLeaf issues an end-entity certificate for the given purposes.
func (l *Lab) AddLeaf(id, cn, issuerID string, ekus []EKU, dnsNames []string, days int) (*Cert, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.addLeafLocked(id, cn, issuerID, ekus, dnsNames, days)
}

func (l *Lab) addLeafLocked(id, cn, issuerID string, ekus []EKU, dnsNames []string, days int) (*Cert, error) {
	issuer, ok := l.certs[issuerID]
	if !ok {
		return nil, fmt.Errorf("issuer %q not found", issuerID)
	}
	if issuer.Kind == KindLeaf {
		return nil, fmt.Errorf("cannot issue from a leaf certificate")
	}
	issuer = l.canonicalIssuerLocked(issuer)
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

// canonicalIssuerLocked resolves a cross certificate node to the logical CA
// node that owns the signing key (the original intermediate). A leaf issued
// after migration is therefore signed by the same key but can still chain
// through either DN-compatible issuer certificate.
func (l *Lab) canonicalIssuerLocked(c *Cert) *Cert {
	if c.Kind == KindCross && c.ParentID != "" {
		if owner, ok := l.certs[c.ParentID]; ok {
			return owner
		}
	}
	return c
}

// RotateLeaf re-issues an end-entity certificate under newIssuerID with a new
// key, copying CN, DNS names and purposes from the previous generation. The
// old certificate remains in the lab (revoked or not) as historical
// evidence; the returned cert is the new active generation. It does not
// revoke the old leaf automatically, so experiments can compare both.
func (l *Lab) RotateLeaf(newID, leafID, newIssuerID string, days int) (*Cert, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	old, ok := l.certs[leafID]
	if !ok {
		return nil, fmt.Errorf("leaf %q not found", leafID)
	}
	if old.Kind != KindLeaf {
		return nil, fmt.Errorf("%q is not a leaf certificate", leafID)
	}
	var ekus []EKU
	for _, u := range old.Cert.ExtKeyUsage {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			ekus = append(ekus, EKUServer)
		case x509.ExtKeyUsageClientAuth:
			ekus = append(ekus, EKUClient)
		}
	}
	newCN := old.Cert.Subject.CommonName
	return l.addLeafLocked(newID, newCN, newIssuerID, ekus, old.Cert.DNSNames, days)
}

// SetTrust marks a root as trusted (anchor) or distrusted. Old and new roots
// can coexist during migration so both chains validate until cut-over.
// Changing trust is a rules change and bumps the rules version.
func (l *Lab) SetTrust(rootID string, trusted bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.certs[rootID]
	if !ok || c.Kind != KindRoot {
		return fmt.Errorf("root %q not found", rootID)
	}
	if l.trust[rootID] != trusted {
		l.trust[rootID] = trusted
		l.rulesVersion++
	}
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
	sort.Strings(ids)
	return ids
}

func (l *Lab) RulesVersion() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.rulesVersion
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

// SetCRLPublished controls whether a CA publishes revocation data. Turning
// this off models "revocation information unavailable": chains through that
// CA must fail even if every signature is cryptographically correct.
func (l *Lab) SetCRLPublished(caID string, published bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.certs[caID]
	if !ok {
		return fmt.Errorf("cert %q not found", caID)
	}
	if c.Kind == KindLeaf {
		return fmt.Errorf("leaf %q cannot publish a CRL", caID)
	}
	if c.CRLPublished != published {
		c.CRLPublished = published
		l.rulesVersion++
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
	if !ca.CRLPublished {
		return nil, fmt.Errorf("CA %q does not publish revocation data", caID)
	}
	return l.buildCRLLocked(ca)
}

func (l *Lab) buildCRLLocked(ca *Cert) ([]byte, error) {
	now := l.nowFunc()
	entries := []x509.RevocationListEntry{}
	for _, c := range l.certs {
		if c.IssuerID == ca.ID && c.Revoked {
			entries = append(entries, x509.RevocationListEntry{
				SerialNumber:   new(big.Int).Set(c.Cert.SerialNumber),
				RevocationTime: c.RevokedAt,
			})
		}
	}
	tmpl := &x509.RevocationList{
		Number:                    new(big.Int).SetUint64(l.seq.Add(1)),
		ThisUpdate:                now.Add(-time.Minute),
		NextUpdate:                now.Add(time.Hour),
		RevokedCertificateEntries: entries,
	}
	signer, ok := ca.Key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA %q has no local signing key", ca.ID)
	}
	return x509.CreateRevocationList(rand.Reader, tmpl, ca.Cert, signer)
}

// History returns all immutable verification evidence, newest first.
func (l *Lab) History() []*VerifyResult {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]*VerifyResult, len(l.history))
	copy(out, l.history)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Reset removes all lab state (used by the sample loader).
func (l *Lab) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.certs = map[string]*Cert{}
	l.trust = map[string]bool{}
	l.history = nil
	l.seq.Store(0)
	l.rulesVersion = 1
}
