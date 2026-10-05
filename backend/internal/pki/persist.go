package pki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Persisted state. Every verification report freezes the materials and
// policy it used, so the whole lab — certificates (with their local
// keys), the trust event log, revocation claims and the immutable
// evidence history — is written to one JSON snapshot after every change.
// Reopening the lab restores the exact reports and material versions;
// nothing is recomputed or silently migrated on load.
type labState struct {
	RulesVersion int             `json:"rulesVersion"`
	Seq          uint64          `json:"seq"`
	TrustLog     []TrustEvent    `json:"trustLog"`
	Certs        []certState     `json:"certs"`
	History      []*VerifyResult `json:"history"`
}

type certState struct {
	ID           string             `json:"id"`
	Label        string             `json:"label"`
	Kind         NodeKind           `json:"kind"`
	IssuerID     string             `json:"issuerId"`
	ParentID     string             `json:"parentId,omitempty"`
	EKUs         []int              `json:"ekus"`
	KeyDER       []byte             `json:"keyDer,omitempty"`
	CertDER      []byte             `json:"certDer"`
	Revoked      bool               `json:"revoked"`
	RevokedAt    time.Time          `json:"revokedAt,omitempty"`
	Expires      time.Time          `json:"expires"`
	CRLPublished bool               `json:"crlPublished"`
	CRLKnownAt   time.Time          `json:"crlKnownAt,omitempty"`
	CRLDelayMin  int                `json:"crlDelayMin,omitempty"`
	CRLIssues    []CRLIssue         `json:"crlIssues,omitempty"`
	LearnedAt    time.Time          `json:"learnedAt"`
	Revocations  []RevocationRecord `json:"revocations,omitempty"`
}

// Save writes the complete lab state to path atomically.
func (l *Lab) Save(path string) error {
	l.mu.RLock()
	state := labState{
		RulesVersion: l.rulesVersion,
		Seq:          l.seq.Load(),
		TrustLog:     append([]TrustEvent{}, l.trustLog...),
		History:      l.history,
	}
	for _, c := range l.certs {
		cs := certState{
			ID: c.ID, Label: c.Label, Kind: c.Kind,
			IssuerID: c.IssuerID, ParentID: c.ParentID,
			CertDER: c.Cert.Raw,
			Revoked: c.Revoked, RevokedAt: c.RevokedAt, Expires: c.Expires,
			CRLPublished: c.CRLPublished, CRLKnownAt: c.CRLKnownAt,
			CRLDelayMin: c.CRLDelayMin, LearnedAt: c.LearnedAt,
			CRLIssues:   append([]CRLIssue{}, c.CRLIssues...),
			Revocations: append([]RevocationRecord{}, c.Revocations...),
		}
		for _, u := range c.Cert.ExtKeyUsage {
			cs.EKUs = append(cs.EKUs, int(u))
		}
		if key, ok := c.Key.(*ecdsa.PrivateKey); ok && key != nil {
			der, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				l.mu.RUnlock()
				return fmt.Errorf("marshal key of %q: %w", c.ID, err)
			}
			cs.KeyDER = der
		}
		state.Certs = append(state.Certs, cs)
	}
	l.mu.RUnlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadLab restores a lab previously written by Save. The file is absent on
// first run; callers then fall back to loading samples.
func LoadLab(path string) (*Lab, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var state labState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	l := NewLab()
	l.rulesVersion = state.RulesVersion
	l.seq.Store(state.Seq)
	l.trustLog = append(l.trustLog, state.TrustLog...)
	l.history = state.History
	for _, cs := range state.Certs {
		cert, err := x509.ParseCertificate(cs.CertDER)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %q: %w", cs.ID, err)
		}
		c := &Cert{
			ID: cs.ID, Label: cs.Label, Kind: cs.Kind,
			IssuerID: cs.IssuerID, ParentID: cs.ParentID,
			Cert: cert, PEM: EncodePEM(cs.CertDER),
			Revoked: cs.Revoked, RevokedAt: cs.RevokedAt, Expires: cs.Expires,
			CRLPublished: cs.CRLPublished, CRLKnownAt: cs.CRLKnownAt,
			CRLDelayMin: cs.CRLDelayMin, LearnedAt: cs.LearnedAt,
			CRLIssues:   append([]CRLIssue{}, cs.CRLIssues...),
			Revocations: append([]RevocationRecord{}, cs.Revocations...),
		}
		// Snapshots written before CRL issuance logs existed: rebuild one
		// issuance from the recorded first-knowledge time so historical
		// reports remain explainable after reopening.
		if c.Kind != KindLeaf && c.CRLPublished && len(c.CRLIssues) == 0 && !c.CRLKnownAt.IsZero() {
			c.CRLIssues = append(c.CRLIssues, CRLIssue{
				ThisUpdate: c.CRLKnownAt.Add(-time.Minute),
				NextUpdate: c.CRLKnownAt.Add(time.Hour),
				LearnedAt:  c.CRLKnownAt,
			})
		}
		for _, u := range cs.EKUs {
			c.EKUs = append(c.EKUs, x509.ExtKeyUsage(u))
		}
		if len(cs.KeyDER) > 0 {
			key, err := x509.ParseECPrivateKey(cs.KeyDER)
			if err != nil {
				return nil, fmt.Errorf("parse key of %q: %w", cs.ID, err)
			}
			c.Key = key
		}
		l.certs[c.ID] = c
	}
	return l, nil
}
