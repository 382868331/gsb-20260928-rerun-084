package pki

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Evidence is one immutable verification record. Re-verification after a
// trust/rule change appends a new record; prior evidence is never overwritten.
type Evidence struct {
	ID        string        `json:"id"`
	CreatedAt time.Time     `json:"createdAt"`
	LeafID    string        `json:"leafId"`
	LeafLabel string        `json:"leafLabel"`
	Purpose   string        `json:"purpose"`
	Valid     bool          `json:"valid"`
	Note      string        `json:"note,omitempty"`
	Result    *VerifyResult `json:"result"`
}

// EvidenceStore is an append-only JSON-lines store of verification records.
type EvidenceStore struct {
	mu   sync.Mutex
	path string
}

func NewEvidenceStore(dir string) (*EvidenceStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &EvidenceStore{path: filepath.Join(dir, "evidence.jsonl")}, nil
}

func (s *EvidenceStore) Append(rec *Evidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	if err := enc.Encode(rec); err != nil {
		return err
	}
	return nil
}

func (s *EvidenceStore) List() ([]*Evidence, error) {
	s.mu.Lock()
	path := s.path
	s.mu.Unlock()
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return []*Evidence{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []*Evidence
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		rec := &Evidence{}
		if err := json.Unmarshal(line, rec); err != nil {
			return nil, fmt.Errorf("corrupt evidence record: %w", err)
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}
