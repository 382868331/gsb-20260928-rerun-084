package lab

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

type seedCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func (s *Store) seedRoot(name string, nbf time.Time, ttl time.Duration) (*seedCert, error) {
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	tmpl := caTemplate(name, nbf, ttl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	return &seedCert{c, key}, err
}

func (s *Store) seedChild(name string, isCA bool, parent *seedCert, eku []x509.ExtKeyUsage, nbf time.Time, ttl time.Duration) (*seedCert, error) {
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	tmpl := caTemplate(name, nbf, ttl)
	if !isCA {
		tmpl.IsCA = false
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = eku
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	return &seedCert{c, key}, err
}

// crossSeed re-signs target's public key (same subject key) with signer root.
func crossSeed(target, signer *seedCert) (*x509.Certificate, error) {
	tmpl := caTemplate(target.cert.Subject.CommonName, target.cert.NotBefore, time.Until(target.cert.NotAfter))
	if time.Until(target.cert.NotAfter) <= 0 {
		tmpl.NotAfter = target.cert.NotAfter
	}
	tmpl.NotBefore = target.cert.NotBefore
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer.cert, target.cert.PublicKey, signer.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func caTemplate(name string, nbf time.Time, ttl time.Duration) *x509.Certificate {
	t := &x509.Certificate{
		SerialNumber:          big.NewInt(nbf.UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             nbf.Add(-time.Minute),
		NotAfter:              nbf.Add(ttl),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	return t
}

// register turns a seeded certificate into persisted state, writing its key
// into the private experiment area.
func (s *Store) register(name, kind, desc string, version int, c *x509.Certificate, key *ecdsa.PrivateKey, issuerCertID, crossBy string, eku []x509.ExtKeyUsage) (*Certificate, error) {
	id := certID(c)
	if key != nil {
		if err := writeKey(s.Dir, id, key); err != nil {
			return nil, err
		}
	}
	eid := entityID(name)
	e, ok := s.st.Entities[eid]
	if !ok {
		e = &Entity{ID: eid, Name: name, Kind: kind, Description: desc}
		s.st.Entities[eid] = e
		s.st.Order = append(s.st.Order, eid)
	}
	derPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	cv := &Certificate{
		ID: id, EntityID: eid, Version: version, Serial: serialString(c), Subject: name,
		IsCA: c.IsCA, EKUs: mapEKUs(eku), NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		IssuerID: issuerCertID, CrossSignedBy: crossBy, PEM: string(derPEM), CreatedAt: time.Now(),
	}
	if key != nil {
		cv.KeyFile = keyPath(s.Dir, id)
	}
	s.st.Certificates[id] = cv
	e.Versions = append(e.Versions, id)
	return cv, nil
}

// Bootstrap builds the first-round self-contained test chain:
//   - old root + new root (root migration window)
//   - current intermediate cross-signed by both roots (old chain vs new chain)
//   - an expired intermediate version (shows path failure on validity)
//   - server and client auth leaves with different EKUs (purpose checks)
func (s *Store) Bootstrap() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.st.Certificates) > 0 {
		return nil
	}
	now := time.Now()

	oldRoot, err := s.seedRoot("Lab Root Old", now.Add(-365*24*time.Hour), 10*365*24*time.Hour)
	if err != nil {
		return err
	}
	newRoot, err := s.seedRoot("Lab Root New", now.Add(-30*24*time.Hour), 10*365*24*time.Hour)
	if err != nil {
		return err
	}
	// Expired first-generation intermediate under the old root.
	expInt, err := s.seedChild("Lab Intermediate Alpha", true, oldRoot, nil, now.Add(-200*24*time.Hour), 100*24*time.Hour)
	if err != nil {
		return err
	}
	// Current intermediate key, issued by old root, cross-signed by new root.
	curInt, err := s.seedChild("Lab Intermediate Alpha", true, oldRoot, nil, now.Add(-20*24*time.Hour), 400*24*time.Hour)
	if err != nil {
		return err
	}
	crossInt, err := crossSeed(curInt, newRoot)
	if err != nil {
		return err
	}
	// Server leaf under current intermediate.
	serverLeaf, err := s.seedChild("api.lab.test", false, curInt, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now, 90*24*time.Hour)
	if err != nil {
		return err
	}
	// Client leaf under current intermediate.
	clientLeaf, err := s.seedChild("device.lab.test", false, curInt, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now, 90*24*time.Hour)
	if err != nil {
		return err
	}
	// Legacy leaf whose only path goes through the expired v1 intermediate.
	legacyLeaf, err := s.seedChild("legacy.lab.test", false, expInt, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now.Add(-150*24*time.Hour), 60*24*time.Hour)
	if err != nil {
		return err
	}

	oldRootCV, err := s.register("Lab Root Old", "root", "The legacy trust anchor being retired", 1, oldRoot.cert, oldRoot.key, "", "", nil)
	if err != nil {
		return err
	}
	newRootCV, err := s.register("Lab Root New", "root", "The replacement trust anchor", 1, newRoot.cert, newRoot.key, "", "", nil)
	if err != nil {
		return err
	}
	expCV, err := s.register("Lab Intermediate Alpha", "intermediate", "Issued under old root; v1 has expired", 1, expInt.cert, expInt.key, oldRootCV.ID, "", nil)
	if err != nil {
		return err
	}
	curCV, err := s.register("Lab Intermediate Alpha", "intermediate", "Current key, issued by old root", 2, curInt.cert, curInt.key, oldRootCV.ID, "", nil)
	if err != nil {
		return err
	}
	if _, err := s.register("Lab Intermediate Alpha", "intermediate", "Cross-certificate of v2 under new root", 2, crossInt, nil, newRootCV.ID, newRootCV.ID, nil); err != nil {
		return err
	}
	if _, err := s.register("api.lab.test", "leaf", "Server authentication leaf (current chain)", 1, serverLeaf.cert, serverLeaf.key, curCV.ID, "", serverLeaf.cert.ExtKeyUsage); err != nil {
		return err
	}
	if _, err := s.register("device.lab.test", "leaf", "Client authentication leaf (current chain)", 1, clientLeaf.cert, clientLeaf.key, curCV.ID, "", clientLeaf.cert.ExtKeyUsage); err != nil {
		return err
	}
	if _, err := s.register("legacy.lab.test", "leaf", "Legacy leaf anchored via expired intermediate v1", 1, legacyLeaf.cert, legacyLeaf.key, expCV.ID, "", legacyLeaf.cert.ExtKeyUsage); err != nil {
		return err
	}

	s.st.CreatedAt = now
	return s.save()
}
