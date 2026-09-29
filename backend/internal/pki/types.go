package pki

import (
	"crypto/x509"
	"encoding/pem"
	"time"
)

// NodeKind marks the role of a stored certificate node.
type NodeKind string

const (
	KindRoot         NodeKind = "root"
	KindIntermediate NodeKind = "intermediate"
	KindCross        NodeKind = "cross"
	KindLeaf         NodeKind = "leaf"
)

// EKU is the lab's simplified certificate purpose.
type EKU string

const (
	EKUServer EKU = "serverAuth"
	EKUClient EKU = "clientAuth"
)

// Cert is a stored certificate together with its local private key.
// Private keys are lab-only material: they never leave the local data dir
// and are never rendered into pages or logs.
type Cert struct {
	ID        string
	Label     string
	Kind      NodeKind
	IssuerID  string // logical node that signed this certificate
	ParentID  string // logical node of the issuing certificate when cross-signed
	EKUs      []x509.ExtKeyUsage
	Key       any    // *rsa.PrivateKey / *ecdsa.PrivateKey; local only
	Cert      *x509.Certificate
	PEM       string // CERTIFICATE PEM
	RevokedAt time.Time
	Revoked   bool
	Expires   time.Time
}

// EncodePEM renders a DER certificate as PEM text.
func EncodePEM(der []byte) string {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

// PublicView is the safe representation sent over HTTP. It never contains
// private key material.
type PublicView struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	Kind      NodeKind   `json:"kind"`
	IssuerID  string     `json:"issuerId"`
	ParentID  string     `json:"parentId,omitempty"`
	EKUs      []string   `json:"ekus"`
	Subject   string     `json:"subject"`
	Issuer    string     `json:"issuer"`
	Serial    string     `json:"serial"`
	NotBefore time.Time  `json:"notBefore"`
	NotAfter  time.Time  `json:"notAfter"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	PEM       string     `json:"pem"`
}

func ekuNames(usages []x509.ExtKeyUsage) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageServerAuth: "serverAuth",
		x509.ExtKeyUsageClientAuth: "clientAuth",
	}
	out := make([]string, 0, len(usages))
	for _, u := range usages {
		if name, ok := names[u]; ok {
			out = append(out, name)
		}
	}
	return out
}

// View returns the private-key-free representation of a cert.
func (c *Cert) View() PublicView {
	v := PublicView{
		ID:       c.ID,
		Label:    c.Label,
		Kind:     c.Kind,
		IssuerID: c.IssuerID,
		ParentID: c.ParentID,
		EKUs:     ekuNames(c.EKUs),
		Subject:  c.Cert.Subject.String(),
		Issuer:   c.Cert.Issuer.String(),
		Serial:   c.Cert.SerialNumber.String(),
		NotBefore: c.Cert.NotBefore,
		NotAfter:  c.Cert.NotAfter,
		Revoked:   c.Revoked,
		PEM:       c.PEM,
	}
	if c.Revoked {
		t := c.RevokedAt
		v.RevokedAt = &t
	}
	return v
}
