package lab

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Store owns the experiment state and the local experiment area on disk.
// It never reads pre-existing keys from the machine: every key is generated
// in-process and written under Dir/private with 0600 permissions.
type Store struct {
	mu  sync.Mutex
	Dir string
	st  *State
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "private"), 0o700); err != nil {
		return nil, err
	}
	s := &Store{Dir: dir}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func statePath(dir string) string { return filepath.Join(dir, "state.json") }
func keyPath(dir, id string) string {
	return filepath.Join(dir, "private", id+".key")
}

func (s *Store) load() error {
	data, err := os.ReadFile(statePath(s.Dir))
	if os.IsNotExist(err) {
		s.st = &State{Schema: 1, CreatedAt: time.Now(), Entities: map[string]*Entity{}, Certificates: map[string]*Certificate{}}
		return nil
	}
	if err != nil {
		return err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	if st.Entities == nil {
		st.Entities = map[string]*Entity{}
	}
	if st.Certificates == nil {
		st.Certificates = map[string]*Certificate{}
	}
	s.st = &st
	return nil
}

// save must be called with mu held. It writes state atomically so that
// revocation is durable immediately (no stale cached trust after restart).
func (s *Store) save() error {
	data, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath(s.Dir) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath(s.Dir))
}

func newKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func writeKey(dir, id string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return os.WriteFile(keyPath(dir, id), b, 0o600)
}

// readKey only ever reads keys this experiment itself created under Dir/private.
func readKey(dir, id string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(keyPath(dir, id))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("key %s: bad pem", id)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key %s: not ecdsa", id)
	}
	return ec, nil
}

func certID(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "c-" + hex.EncodeToString(sum[:6])
}

func entityID(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "e-" + hex.EncodeToString(sum[:4])
}

func serialString(s *x509.Certificate) string {
	return "" + s.SerialNumber.Text(16)
}

func mapEKUs(ekus []x509.ExtKeyUsage) []string {
	out := []string{}
	for _, e := range ekus {
		switch e {
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "clientAuth")
		case x509.ExtKeyUsageAny:
			out = append(out, "any")
		}
	}
	return out
}

func parseEKUs(ss []string) []x509.ExtKeyUsage {
	out := []x509.ExtKeyUsage{}
	for _, s := range ss {
		switch s {
		case "serverAuth":
			out = append(out, x509.ExtKeyUsageServerAuth)
		case "clientAuth":
			out = append(out, x509.ExtKeyUsageClientAuth)
		case "any":
			out = append(out, x509.ExtKeyUsageAny)
		}
	}
	return out
}

func (s *Store) Snapshot() *State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneState(s.st)
}

func cloneState(st *State) *State {
	b, _ := json.Marshal(st)
	var cp State
	_ = json.Unmarshal(b, &cp)
	return &cp
}

// LatestCert returns the newest version of an entity that is not itself a
// cross-certificate (cross-certs represent the same key, alternate issuer).
func (st *State) LatestCert(entityID string) (*Certificate, error) {
	e, ok := st.Entities[entityID]
	if !ok {
		return nil, fmt.Errorf("entity %s not found", entityID)
	}
	for i := len(e.Versions) - 1; i >= 0; i-- {
		c := st.Certificates[e.Versions[i]]
		if c.CrossSignedBy == "" {
			return c, nil
		}
	}
	return nil, fmt.Errorf("entity %s has no usable version", entityID)
}

func (st *State) sortedCertIDs() []string {
	ids := make([]string, 0, len(st.Certificates))
	for id := range st.Certificates {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

var _ crypto.PrivateKey = (*ecdsa.PrivateKey)(nil)
