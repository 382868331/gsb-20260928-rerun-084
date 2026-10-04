package pki

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Snapshot persistence: the whole lab (certificates with local keys, the
// trust log, revocation logs and every immutable evidence record) is stored
// as one JSON document. Reopening the lab therefore replays the exact
// material versions and saved reports; later materials only ever append
// new evidence, never rewrite a saved investigation.

type certSnapshot struct {
	ID           string             `json:"id"`
	Label        string             `json:"label"`
	Kind         NodeKind           `json:"kind"`
	IssuerID     string             `json:"issuerId"`
	ParentID     string             `json:"parentId,omitempty"`
	EKUs         []x509.ExtKeyUsage `json:"ekus,omitempty"`
	KeyPEM       string             `json:"keyPem,omitempty"`
	CertPEM      string             `json:"certPem"`
	Revoked      bool               `json:"revoked"`
	RevokedAt    time.Time          `json:"revokedAt,omitempty"`
	CRLPublished bool               `json:"crlPublished"`
	CRLKnownAt   time.Time          `json:"crlKnownAt,omitempty"`
	CRLDelayMin  int                `json:"crlDelayMin,omitempty"`
	LearnedAt    time.Time          `json:"learnedAt"`
	Revocations  []RevocationRecord `json:"revocations,omitempty"`
}

type snapshot struct {
	Certs        []certSnapshot  `json:"certs"`
	TrustLog     []TrustEvent    `json:"trustLog"`
	History      []*VerifyResult `json:"history"`
	RulesVersion int             `json:"rulesVersion"`
	Seq          uint64          `json:"seq"`
}

// SetStore enables snapshot persistence at the given path. Existing state
// is saved immediately.
func (l *Lab) SetStore(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.storePath = path
	return l.saveLocked()
}

func (l *Lab) saveLocked() error {
	if l.storePath == "" {
		return nil
	}
	snap := snapshot{
		TrustLog:     l.trustLog,
		History:      l.history,
		RulesVersion: l.rulesVersion,
		Seq:          l.seq.Load(),
	}
	for _, c := range l.certs {
		cs := certSnapshot{
			ID: c.ID, Label: c.Label, Kind: c.Kind,
			IssuerID: c.IssuerID, ParentID: c.ParentID,
			EKUs: c.EKUs, CertPEM: c.PEM,
			Revoked: c.Revoked, RevokedAt: c.RevokedAt,
			CRLPublished: c.CRLPublished, CRLKnownAt: c.CRLKnownAt,
			CRLDelayMin: c.CRLDelayMin, LearnedAt: c.LearnedAt,
			Revocations: c.Revocations,
		}
		if c.Key != nil {
			der, err := x509.MarshalPKCS8PrivateKey(c.Key)
			if err != nil {
				return fmt.Errorf("marshal key of %q: %w", c.ID, err)
			}
			cs.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		}
		snap.Certs = append(snap.Certs, cs)
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(l.storePath), 0o755); err != nil {
		return err
	}
	tmp := l.storePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, l.storePath)
}

// LoadLab restores a lab from a snapshot file. It returns nil (and no
// error) when the file does not exist, so callers can fall back to loading
// fresh samples.
func LoadLab(path string) (*Lab, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parse snapshot %s: %w", path, err)
	}
	l := NewLab()
	l.trustLog = snap.TrustLog
	l.history = snap.History
	l.rulesVersion = snap.RulesVersion
	l.seq.Store(snap.Seq)
	for _, cs := range snap.Certs {
		block, _ := pem.Decode([]byte(cs.CertPEM))
		if block == nil {
			return nil, fmt.Errorf("snapshot: bad certificate PEM for %q", cs.ID)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("snapshot: parse certificate %q: %w", cs.ID, err)
		}
		c := &Cert{
			ID: cs.ID, Label: cs.Label, Kind: cs.Kind,
			IssuerID: cs.IssuerID, ParentID: cs.ParentID,
			EKUs: cs.EKUs, Cert: cert, PEM: cs.CertPEM,
			Revoked: cs.Revoked, RevokedAt: cs.RevokedAt,
			CRLPublished: cs.CRLPublished, CRLKnownAt: cs.CRLKnownAt,
			CRLDelayMin: cs.CRLDelayMin, LearnedAt: cs.LearnedAt,
			Revocations: cs.Revocations, Expires: cert.NotAfter,
		}
		if cs.KeyPEM != "" {
			kblock, _ := pem.Decode([]byte(cs.KeyPEM))
			if kblock == nil {
				return nil, fmt.Errorf("snapshot: bad key PEM for %q", cs.ID)
			}
			key, err := x509.ParsePKCS8PrivateKey(kblock.Bytes)
			if err != nil {
				return nil, fmt.Errorf("snapshot: parse key %q: %w", cs.ID, err)
			}
			c.Key = key
		}
		l.certs[c.ID] = c
	}
	l.storePath = path
	return l, nil
}
