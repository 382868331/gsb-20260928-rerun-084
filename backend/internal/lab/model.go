package lab

import "time"

// Entity is a named certificate holder (root / intermediate / leaf).
// Each entity can own multiple versions, e.g. after a root rotation.
type Entity struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Kind        string   `json:"kind"` // root | intermediate | leaf
	Description string   `json:"description"`
	Versions    []string `json:"versions"` // certificate IDs, newest last
}

// Certificate is one version of an entity's key/certificate pair.
// Private keys live only in the local experiment area (private/*.key),
// never in API responses or page logs.
type Certificate struct {
	ID           string    `json:"id"`
	EntityID     string    `json:"entityId"`
	Version      int       `json:"version"`
	Serial       string    `json:"serial"`
	Subject      string    `json:"subject"`
	IssuerID     string    `json:"issuerId,omitempty"` // empty for self-signed roots
	IsCA         bool      `json:"isCA"`
	EKUs         []string  `json:"ekus"` // serverAuth | clientAuth | any
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	Revoked      bool      `json:"revoked"`
	RevokedAt    time.Time `json:"revokedAt,omitempty"`
	RevokeReason string    `json:"revokeReason,omitempty"`
	// CrossSignedBy marks this certificate as a cross-certificate issued by
	// another root (certificate ID of the issuing root version).
	CrossSignedBy string    `json:"crossSignedBy,omitempty"`
	PEM           string    `json:"pem"`
	KeyFile       string    `json:"-"` // path stays inside the experiment area
	CreatedAt     time.Time `json:"createdAt"`
}

// State is the persisted experiment. Saving and reopening the app restores
// exactly the same experiment (same serials, versions, revocations).
type State struct {
	Schema       int                     `json:"schema"`
	CreatedAt    time.Time               `json:"createdAt"`
	Entities     map[string]*Entity      `json:"entities"`
	Certificates map[string]*Certificate `json:"certificates"`
	Order        []string                `json:"order"` // entity insertion order
}

// KeyFile is never serialized: private keys (and their local paths) do not
// leave the experiment area or enter page logs.
