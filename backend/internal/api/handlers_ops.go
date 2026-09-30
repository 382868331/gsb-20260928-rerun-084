package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"certlab/internal/pki"
)

type leafReq struct {
	ID, CN, IssuerID string
	EKUs             []string
	DNSNames         []string
	Days             int
}

func (s *Server) addLeaf(w http.ResponseWriter, r *http.Request) {
	var req leafReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.ID == "" {
		req.ID = fmt.Sprintf("leaf-%d", s.seq.Add(1))
	}
	if req.Days == 0 {
		req.Days = 90
	}
	ekus := parseEKUs(req.EKUs)
	c, err := s.Lab.AddLeaf(req.ID, req.CN, req.IssuerID, ekus, req.DNSNames, req.Days)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 201, c.View())
}

type rotateReq struct {
	OldID, NewID string
	Days         int
}

func (s *Server) rotateLeaf(w http.ResponseWriter, r *http.Request) {
	var req rotateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.NewID == "" {
		req.NewID = fmt.Sprintf("%s-rotated-%d", req.OldID, s.seq.Add(1))
	}
	if req.Days == 0 {
		req.Days = 90
	}
	c, err := s.Lab.RotateLeaf(req.OldID, req.NewID, req.Days)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 201, map[string]any{"new": c.View()})
}

type trustReq struct {
	RootID string `json:"rootId"`
	Trust  bool   `json:"trust"`
}

func (s *Server) setTrust(w http.ResponseWriter, r *http.Request) {
	var req trustReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if err := s.Lab.SetTrust(req.RootID, req.Trust); err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"rootId": req.RootID, "trust": req.Trust})
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	var req idReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if err := s.Lab.Revoke(req.ID); err != nil {
		writeErr(w, 400, err)
		return
	}
	c, _ := s.Lab.Get(req.ID)
	writeJSON(w, 200, c.View())
}

type crlReq struct {
	CAID      string `json:"caId"`
	Published bool   `json:"published"`
}

func (s *Server) setCRL(w http.ResponseWriter, r *http.Request) {
	var req crlReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if err := s.Lab.SetCRLPublished(req.CAID, req.Published); err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"caId": req.CAID, "published": req.Published})
}

func (s *Server) getCRL(w http.ResponseWriter, r *http.Request) {
	der, err := s.Lab.CRL(r.PathValue("id"))
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.WriteHeader(200)
	_, _ = w.Write(der)
}

type verifyReq struct {
	LeafID  string `json:"leafId"`
	Purpose string `json:"purpose"`
	Note    string `json:"note"`
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	var req verifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	purpose := pki.EKU(req.Purpose)
	if purpose == "" {
		purpose = pki.EKUServer
	}
	result, err := s.Lab.Verify(req.LeafID, purpose)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	label := req.LeafID
	if c, ok := s.Lab.Get(req.LeafID); ok {
		label = c.Label
	}
	rec := &pki.Evidence{
		ID:        fmt.Sprintf("ev-%d", time.Now().UnixNano()),
		CreatedAt: time.Now().UTC(),
		LeafID:    req.LeafID,
		LeafLabel: label,
		Purpose:   req.Purpose,
		Valid:     result.Valid,
		Note:      req.Note,
		Result:    result,
	}
	if err := s.Evidence.Append(rec); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, rec)
}

func (s *Server) listEvidence(w http.ResponseWriter, r *http.Request) {
	recs, err := s.Evidence.List()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"evidence": recs})
}

func parseEKUs(in []string) []pki.EKU {
	out := make([]pki.EKU, 0, len(in))
	for _, e := range in {
		switch e {
		case string(pki.EKUServer), "server":
			out = append(out, pki.EKUServer)
		case string(pki.EKUClient), "client":
			out = append(out, pki.EKUClient)
		}
	}
	if len(out) == 0 {
		out = []pki.EKU{pki.EKUServer}
	}
	return out
}
