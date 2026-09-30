package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync/atomic"
	"time"
)

func generateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func nextSerial(seq *atomic.Uint64) *big.Int {
	return new(big.Int).SetUint64(seq.Add(1))
}

func ekuFromNames(names []EKU) []x509.ExtKeyUsage {
	lookup := map[EKU]x509.ExtKeyUsage{
		EKUServer: x509.ExtKeyUsageServerAuth,
		EKUClient: x509.ExtKeyUsageClientAuth,
	}
	out := make([]x509.ExtKeyUsage, 0, len(names))
	for _, n := range names {
		if u, ok := lookup[n]; ok {
			out = append(out, u)
		}
	}
	return out
}

// CreateRoot builds a self-signed root CA keyed under id.
func CreateRoot(id, cn string, notBefore, notAfter time.Time, seq *atomic.Uint64) (*Cert, error) {
	key, err := generateKey()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(seq),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            3,
		MaxPathLenZero:        false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Cert{
		ID: id, Label: cn, Kind: KindRoot, IssuerID: id,
		Key: key, Cert: parsed, PEM: EncodePEM(der), Expires: notAfter,
		EKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}, nil
}

// IssueOptions parameterizes a new signed certificate.
type IssueOptions struct {
	ID, Label, CN string
	Intermediate  bool
	EKUs          []EKU
	NotBefore     time.Time
	NotAfter      time.Time
	DNSNames      []string
}

// Issue signs a new certificate with the issuer's key. For a cross-signed
// intermediate, issuer is the new CA while subjectKey identifies the
// pre-existing intermediate key/public certificate being signed.
func Issue(issuer *Cert, opts IssueOptions, subjectOverride *Cert, seq *atomic.Uint64) (*Cert, error) {
	key, err := generateKey()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(seq),
		Subject:      pkix.Name{CommonName: opts.CN},
		NotBefore:    opts.NotBefore,
		NotAfter:     opts.NotAfter,
		DNSNames:     opts.DNSNames,
	}
	if opts.Intermediate {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.MaxPathLen = 2
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	} else {
		tmpl.BasicConstraintsValid = true
		tmpl.IsCA = false
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = ekuFromNames(opts.EKUs)
	}

	var publicKey any = &key.PublicKey
	subjectCert := tmpl
	if subjectOverride != nil {
		// Cross-signature: reuse the existing intermediate's public key and
		// subject identity; the new cert chain therefore represents the same
		// private key under a different issuer.
		publicKey = subjectOverride.Cert.PublicKey
		tmpl.Subject = subjectOverride.Cert.Subject
		subjectCert = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, subjectCert, issuer.Cert, publicKey, issuer.Key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	kind := KindLeaf
	if opts.Intermediate {
		kind = KindIntermediate
	}
	ecus := opts.EKUs
	if opts.Intermediate {
		ecus = []EKU{EKU("CA")}
	}
	c := &Cert{
		ID: opts.ID, Label: opts.Label, Kind: kind, IssuerID: issuer.ID,
		Key: key, Cert: parsed, PEM: EncodePEM(der), Expires: opts.NotAfter,
		EKUs: ekuFromNames(ecus),
	}
	if subjectOverride != nil {
		c.Key = nil
		c.Kind = KindCross
		c.ParentID = subjectOverride.ID
	}
	return c, nil
}
