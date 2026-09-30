package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"certlab/internal/pki"
)

type Server struct {
	Lab      *pki.Lab
	Evidence *pki.EvidenceStore
	webFS    http.Handler
	seq      atomic.Uint64
}

func NewServer(lab *pki.Lab, ev *pki.EvidenceStore, web http.Handler) *Server {
	return &Server{Lab: lab, Evidence: ev, webFS: web}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/certs", s.listCerts)
	mux.HandleFunc("POST /api/roots", s.addRoot)
	mux.HandleFunc("POST /api/intermediates", s.addIntermediate)
	mux.HandleFunc("POST /api/leaves", s.addLeaf)
	mux.HandleFunc("POST /api/leaves/rotate", s.rotateLeaf)
	mux.HandleFunc("POST /api/trust", s.setTrust)
	mux.HandleFunc("POST /api/revoke", s.revoke)
	mux.HandleFunc("POST /api/crl", s.setCRL)
	mux.HandleFunc("POST /api/verify", s.verify)
	mux.HandleFunc("GET /api/evidence", s.listEvidence)
	mux.HandleFunc("GET /api/crl/{id}", s.getCRL)
	if s.webFS != nil {
		mux.Handle("/", s.webFS)
	}
	return logRequests(mux)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

type idReq struct {
	ID string `json:"id"`
}

func (s *Server) listCerts(w http.ResponseWriter, r *http.Request) {
	certs := s.Lab.List()
	views := make([]pki.PublicView, 0, len(certs))
	for _, c := range certs {
		views = append(views, c.View())
	}
	writeJSON(w, 200, map[string]any{
		"certs": views, "trustedRoots": s.Lab.TrustedRoots(), "now": s.Lab.Now().UTC(),
	})
}

type rootReq struct {
	ID, CN string
	Years  int
}

func (s *Server) addRoot(w http.ResponseWriter, r *http.Request) {
	var req rootReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.ID == "" {
		req.ID = fmt.Sprintf("root-%d", s.seq.Add(1))
	}
	if req.Years == 0 {
		req.Years = 10
	}
	c, err := s.Lab.AddRoot(req.ID, req.CN, req.Years)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 201, c.View())
}

type intReq struct {
	ID, CN, IssuerID, CrossSubjectID string
	Years                            int
	Days                             int
}

func (s *Server) addIntermediate(w http.ResponseWriter, r *http.Request) {
	var req intReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.ID == "" {
		req.ID = fmt.Sprintf("int-%d", s.seq.Add(1))
	}
	now := s.Lab.Now()
	notBefore := now.Add(-time.Minute)
	var notAfter time.Time
	switch {
	case req.Years > 0:
		notAfter = now.AddDate(req.Years, 0, 0)
	case req.Days > 0:
		notAfter = now.AddDate(0, 0, req.Days)
	default:
		notAfter = now.AddDate(5, 0, 0)
	}
	c, err := s.Lab.AddIntermediate(req.ID, req.CN, req.IssuerID, req.CrossSubjectID, notBefore, notAfter)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 201, c.View())
}
