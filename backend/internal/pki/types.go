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
	Key       any // *rsa.PrivateKey / *ecdsa.PrivateKey; local only
	Cert      *x509.Certificate
	PEM       string // CERTIFICATE PEM
	RevokedAt time.Time
	Revoked   bool
	Expires   time.Time
	// CRLPublished reports whether this CA node publishes revocation data.
	// False models missing CRL information for an otherwise valid CA.
	CRLPublished bool
	// CRLKnownAt is when the lab first obtained this CA's revocation
	// publication. Investigations with a knowledge cutoff earlier than
	// this moment cannot rely on the CRL even if it exists today.
	CRLKnownAt time.Time
	// CRLDelayMin shifts the CRL ThisUpdate into the future, modelling
	// revocation material that is published but not yet effective
	// ("late" revocation data).
	CRLDelayMin int
	// LearnedAt is when this certificate material was obtained by the
	// lab. Chain building for a historical investigation only uses
	// certificates learned on or before the knowledge cutoff.
	LearnedAt time.Time
	// Revocations is the append-only log of revocation claims about this
	// certificate. Each record carries the effective revocation time and
	// the moment the lab learned it; corrections add a new record with a
	// later LearnedAt instead of rewriting the old one.
	Revocations []RevocationRecord
}

// RevocationRecord is one learned claim that a certificate was revoked.
// RevokedAt is the effective (possibly backdated or corrected) revocation
// time; LearnedAt is when the claim reached the lab.
type RevocationRecord struct {
	RevokedAt time.Time `json:"revokedAt"`
	LearnedAt time.Time `json:"learnedAt"`
	Note      string    `json:"note,omitempty"`
}

// TrustEvent is one learned change of a root's trust status. The log lets
// a historical investigation reconstruct which roots were trusted as of a
// knowledge cutoff instead of using today's trust set.
type TrustEvent struct {
	RootID    string    `json:"rootId"`
	Trusted   bool      `json:"trusted"`
	LearnedAt time.Time `json:"learnedAt"`
}

// EncodePEM renders a DER certificate as PEM text.
func EncodePEM(der []byte) string {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

// PublicView is the safe representation sent over HTTP. It never contains
// private key material.
type PublicView struct {
	ID           string             `json:"id"`
	Label        string             `json:"label"`
	Kind         NodeKind           `json:"kind"`
	IssuerID     string             `json:"issuerId"`
	ParentID     string             `json:"parentId,omitempty"`
	EKUs         []string           `json:"ekus"`
	Subject      string             `json:"subject"`
	Issuer       string             `json:"issuer"`
	Serial       string             `json:"serial"`
	NotBefore    time.Time          `json:"notBefore"`
	NotAfter     time.Time          `json:"notAfter"`
	Revoked      bool               `json:"revoked"`
	RevokedAt    *time.Time         `json:"revokedAt,omitempty"`
	Revocations  []RevocationRecord `json:"revocations,omitempty"`
	CRLPublished bool               `json:"crlPublished"`
	CRLKnownAt   *time.Time         `json:"crlKnownAt,omitempty"`
	CRLDelayMin  int                `json:"crlDelayMin,omitempty"`
	LearnedAt    time.Time          `json:"learnedAt"`
	PEM          string             `json:"pem"`
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
		ID:        c.ID,
		Label:     c.Label,
		Kind:      c.Kind,
		IssuerID:  c.IssuerID,
		ParentID:  c.ParentID,
		EKUs:      ekuNames(c.EKUs),
		Subject:   c.Cert.Subject.String(),
		Issuer:    c.Cert.Issuer.String(),
		Serial:    c.Cert.SerialNumber.String(),
		NotBefore: c.Cert.NotBefore,
		NotAfter:  c.Cert.NotAfter,
		Revoked:   c.Revoked,
		PEM:       c.PEM,
	}
	if c.Revoked {
		t := c.RevokedAt
		v.RevokedAt = &t
	}
	v.Revocations = append(v.Revocations, c.Revocations...)
	v.CRLPublished = c.CRLPublished
	if !c.CRLKnownAt.IsZero() {
		t := c.CRLKnownAt
		v.CRLKnownAt = &t
	}
	v.CRLDelayMin = c.CRLDelayMin
	v.LearnedAt = c.LearnedAt
	return v
}
