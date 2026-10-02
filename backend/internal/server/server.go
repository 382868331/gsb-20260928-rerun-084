package server

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"certlab/internal/pki"
)

//go:embed web/*
var webFS embed.FS

type Server struct {
	lab  *pki.Lab
	hmux *http.ServeMux
}

func New(lab *pki.Lab) *http.Server {
	s := &Server{lab: lab, hmux: http.NewServeMux()}
	s.routes()
	return &http.Server{
		Addr:              ":8080",
		Handler:           logging(s.hmux),
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func (s *Server) routes() {
	mux := s.hmux
	mux.HandleFunc("GET /api/state", s.handleState)
	mux.HandleFunc("POST /api/roots", s.handleAddRoot)
	mux.HandleFunc("POST /api/intermediates", s.handleAddIntermediate)
	mux.HandleFunc("POST /api/leaves", s.handleAddLeaf)
	mux.HandleFunc("POST /api/leaves/rotate", s.handleRotate)
	mux.HandleFunc("POST /api/certs/{id}/{action}", s.handleCertAction)
	mux.HandleFunc("GET /api/crl/{id}", s.handleCRL)
	mux.HandleFunc("POST /api/verify", s.handleVerify)
	mux.HandleFunc("GET /api/history", s.handleHistory)
	mux.HandleFunc("POST /api/samples", s.handleSamples)
	mux.HandleFunc("POST /api/reset", s.handleReset)

	static, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(static)))
}

func logging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

type stateResp struct {
	RulesVersion int              `json:"rulesVersion"`
	TrustedRoots []string         `json:"trustedRoots"`
	Now          time.Time        `json:"now"`
	Certs        []pki.PublicView `json:"certs"`
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	certs := s.lab.List()
	views := make([]pki.PublicView, 0, len(certs))
	for _, c := range certs {
		views = append(views, c.View())
	}
	writeJSON(w, http.StatusOK, stateResp{
		RulesVersion: s.lab.RulesVersion(),
		TrustedRoots: s.lab.TrustedRoots(),
		Now:          s.lab.Now().UTC(),
		Certs:        views,
	})
}

type rootReq struct {
	ID, CN string
	Years  int
}

func (s *Server) handleAddRoot(w http.ResponseWriter, r *http.Request) {
	var req rootReq
	if !decode(w, r, &req) {
		return
	}
	if req.Years == 0 {
		req.Years = 10
	}
	c, err := s.lab.AddRoot(req.ID, req.CN, req.Years)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, c.View())
}

type intermediateReq struct {
	ID, CN, IssuerID, CrossSubjectID string
	Years                            int
}

func (s *Server) handleAddIntermediate(w http.ResponseWriter, r *http.Request) {
	var req intermediateReq
	if !decode(w, r, &req) {
		return
	}
	if req.Years == 0 {
		req.Years = 5
	}
	c, err := s.lab.AddIntermediate(req.ID, req.CN, req.IssuerID, req.CrossSubjectID, req.Years)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, c.View())
}

type leafReq struct {
	ID, CN, IssuerID string
	EKUs             []string
	DNSNames         []string
	Days             int
}

func toEKUs(in []string) ([]pki.EKU, error) {
	out := make([]pki.EKU, 0, len(in))
	for _, name := range in {
		switch pki.EKU(name) {
		case pki.EKUServer, pki.EKUClient:
			out = append(out, pki.EKU(name))
		default:
			return nil, &badRequestError{"purpose must be serverAuth or clientAuth"}
		}
	}
	return out, nil
}

func (s *Server) handleAddLeaf(w http.ResponseWriter, r *http.Request) {
	var req leafReq
	if !decode(w, r, &req) {
		return
	}
	if req.Days == 0 {
		req.Days = 90
	}
	ekus, err := toEKUs(req.EKUs)
	if err != nil {
		writeErr(w, err)
		return
	}
	c, err := s.lab.AddLeaf(req.ID, req.CN, req.IssuerID, ekus, req.DNSNames, req.Days)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, c.View())
}

type rotateReq struct {
	NewID, LeafID, NewIssuerID string
	Days                       int
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	var req rotateReq
	if !decode(w, r, &req) {
		return
	}
	if req.Days == 0 {
		req.Days = 90
	}
	c, err := s.lab.RotateLeaf(req.NewID, req.LeafID, req.NewIssuerID, req.Days)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, c.View())
}

func (s *Server) handleCertAction(w http.ResponseWriter, r *http.Request) {
	id, action := r.PathValue("id"), r.PathValue("action")
	if _, ok := s.lab.Get(id); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "cert not found"})
		return
	}
	switch action {
	case "revoke":
		if err := s.lab.Revoke(id); err != nil {
			writeErr(w, err)
			return
		}
	case "trust":
		var body struct{ Trusted bool }
		if r.ContentLength != 0 && !decode(w, r, &body) {
			return
		}
		if err := s.lab.SetTrust(id, body.Trusted); err != nil {
			writeErr(w, err)
			return
		}
	case "crl":
		var body struct{ Published bool }
		if !decode(w, r, &body) {
			return
		}
		if err := s.lab.SetCRLPublished(id, body.Published); err != nil {
			writeErr(w, err)
			return
		}
	case "crldelay":
		var body struct{ Minutes int }
		if !decode(w, r, &body) {
			return
		}
		if err := s.lab.SetCRLDelay(id, body.Minutes); err != nil {
			writeErr(w, err)
			return
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown action"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	der, err := s.lab.CRL(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", `attachment; filename="`+id+".crl\"")
	w.Write(der)
}

type verifyReq struct {
	LeafID  string      `json:"leafId"`
	Purpose string      `json:"purpose"`
	Policy  *pki.Policy `json:"policy,omitempty"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyReq
	if !decode(w, r, &req) {
		return
	}
	res, err := s.lab.Verify(req.LeafID, pki.EKU(req.Purpose), req.Policy)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.lab.History())
}

func (s *Server) handleSamples(w http.ResponseWriter, r *http.Request) {
	if err := pki.LoadSamples(s.lab); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "loaded"})
}

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	s.lab.Reset()
	writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
}

type badRequestError struct{ msg string }

func (e *badRequestError) Error() string { return e.msg }

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return false
	}
	return true
}

func writeErr(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	if _, ok := err.(*badRequestError); ok {
		code = http.StatusBadRequest
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		code = http.StatusNotFound
	case strings.Contains(msg, "unknown purpose"), strings.Contains(msg, "cannot"),
		strings.Contains(msg, "not a leaf"), strings.Contains(msg, "not a root"):
		code = http.StatusBadRequest
	}
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
