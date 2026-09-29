package lab

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// IssueParams creates a new certificate version for an entity.
type IssueParams struct {
	Name        string
	Kind        string   // root | intermediate | leaf
	IssuerID    string   // entity ID of issuer; empty for a new self-signed root
	EKUs        []string // leaf key usages; ignored for CA
	Description string
	NotBefore   time.Time // zero => now
	TTL         time.Duration
}

// Issue creates a fresh key and certificate, stores the key in the private
// area, and appends a new version to the entity.
func (s *Store) Issue(p IssueParams) (*Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nbf := p.NotBefore
	if nbf.IsZero() {
		nbf = time.Now()
	}
	ttl := p.TTL
	if ttl == 0 {
		ttl = 90 * 24 * time.Hour
	}

	key, err := newKey()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: p.Name},
		NotBefore:    nbf.Add(-time.Minute),
		NotAfter:     nbf.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	var issuerCert *x509.Certificate
	var issuerKey *ecdsa.PrivateKey
	if p.Kind == "root" {
		if p.IssuerID != "" {
			return nil, fmt.Errorf("roots are self-signed")
		}
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		issuerCert = tmpl
		issuerKey = key
	} else {
		if p.IssuerID == "" {
			return nil, fmt.Errorf("%s requires an issuer", p.Kind)
		}
		iss, err := s.st.LatestCert(p.IssuerID)
		if err != nil {
			return nil, err
		}
		if !iss.IsCA {
			return nil, fmt.Errorf("issuer %s is not a CA", iss.Subject)
		}
		issuerCert, err = parsePEMCert(iss.PEM)
		if err != nil {
			return nil, err
		}
		issuerKey, err = readKey(s.Dir, iss.ID)
		if err != nil {
			return nil, err
		}
		if p.Kind == "intermediate" {
			tmpl.IsCA = true
			tmpl.BasicConstraintsValid = true
			tmpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		} else {
			tmpl.ExtKeyUsage = parseEKUs(p.EKUs)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, &key.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	id := certID(cert)
	if _, exists := s.st.Certificates[id]; exists {
		return nil, fmt.Errorf("duplicate certificate id")
	}
	if err := writeKey(s.Dir, id, key); err != nil {
		return nil, err
	}

	eid := entityID(p.Name)
	e, ok := s.st.Entities[eid]
	if !ok {
		e = &Entity{ID: eid, Name: p.Name, Kind: p.Kind, Description: p.Description}
		s.st.Entities[eid] = e
		s.st.Order = append(s.st.Order, eid)
	}
	version := len(e.Versions) + 1
	c := &Certificate{
		ID: id, EntityID: eid, Version: version, Serial: serialString(cert),
		Subject: p.Name, IsCA: tmpl.IsCA, EKUs: mapEKUs(tmpl.ExtKeyUsage),
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		IssuerID: issuerEntityCertID(s.st, p.Kind == "root", p.IssuerID),
		PEM:      encodePEM(der), KeyFile: keyPath(s.Dir, id), CreatedAt: time.Now(),
	}
	if p.Kind == "root" {
		c.IssuerID = "" // self-signed
	}
	s.st.Certificates[id] = c
	e.Versions = append(e.Versions, id)
	if err := s.save(); err != nil {
		return nil, err
	}
	return c, nil
}

func issuerEntityCertID(st *State, selfSigned bool, issuerEntityID string) string {
	if selfSigned || issuerEntityID == "" {
		return ""
	}
	c, err := st.LatestCert(issuerEntityID)
	if err != nil {
		return ""
	}
	return c.ID
}

func parsePEMCert(p string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, fmt.Errorf("bad certificate pem")
	}
	return x509.ParseCertificate(block.Bytes)
}

func encodePEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// CrossSign creates a cross-certificate: the SAME subject key of targetCert is
// signed by another root, so a verifier trusting the other root can build a
// valid path through the target intermediate during a root migration.
func (s *Store) CrossSign(targetCertID, signerRootEntityID string) (*Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	target, ok := s.st.Certificates[targetCertID]
	if !ok {
		return nil, fmt.Errorf("certificate %s not found", targetCertID)
	}
	if !target.IsCA {
		return nil, fmt.Errorf("cross-signing targets an intermediate CA")
	}
	targetX509, err := parsePEMCert(target.PEM)
	if err != nil {
		return nil, err
	}
	signer, err := s.st.LatestCert(signerRootEntityID)
	if err != nil {
		return nil, err
	}
	if !signer.IsCA || signer.IssuerID != "" {
		return nil, fmt.Errorf("cross-signer must be a trusted root")
	}
	signerX509, err := parsePEMCert(signer.PEM)
	if err != nil {
		return nil, err
	}
	signerKey, err := readKey(s.Dir, signer.ID)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               targetX509.Subject,
		NotBefore:             targetX509.NotBefore,
		NotAfter:              targetX509.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerX509, targetX509.PublicKey, signerKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	id := certID(cert)
	c := &Certificate{
		ID: id, EntityID: target.EntityID, Version: target.Version,
		Serial: serialString(cert), Subject: target.Subject, IsCA: true,
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		IssuerID: signer.ID, CrossSignedBy: signer.ID,
		PEM: encodePEM(der), KeyFile: "", CreatedAt: time.Now(),
	}
	s.st.Certificates[id] = c
	s.st.Entities[target.EntityID].Versions = append(s.st.Entities[target.EntityID].Versions, id)
	if err := s.save(); err != nil {
		return nil, err
	}
	return c, nil
}

// Revoke marks a certificate version revoked and persists immediately.
// Verification always reads live state, so a revoked certificate can never
// keep passing via a cached verdict.
func (s *Store) Revoke(certID, reason string) (*Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.st.Certificates[certID]
	if !ok {
		return nil, fmt.Errorf("certificate %s not found", certID)
	}
	if !c.Revoked {
		c.Revoked = true
		c.RevokedAt = time.Now()
		c.RevokeReason = reason
		if err := s.save(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Reset wipes the experiment (state + generated keys). Used by the demo reset.
func (s *Store) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := removeAll(s.Dir); err != nil {
		return err
	}
	s.st = &State{Schema: 1, CreatedAt: time.Now(), Entities: map[string]*Entity{}, Certificates: map[string]*Certificate{}}
	return os.MkdirAll(filepath.Join(s.Dir, "private"), 0o700)
}

func removeAll(dir string) error {
	entries, err := readDirNames(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e)); err != nil {
			return err
		}
	}
	return nil
}

func readDirNames(dir string) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Readdirnames(-1)
}
