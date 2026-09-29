package lab

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
)

type API struct {
	store *Store
}

func NewAPI(store *Store) *API { return &API{store: store} }

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", a.getState)
	mux.HandleFunc("POST /api/bootstrap", a.bootstrap)
	mux.HandleFunc("POST /api/issue", a.issue)
	mux.HandleFunc("POST /api/cross-sign", a.crossSign)
	mux.HandleFunc("POST /api/revoke", a.revoke)
	mux.HandleFunc("POST /api/verify", a.verify)
	mux.HandleFunc("POST /api/reset", a.reset)
	return withCORS(mux)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// rootsResponse lists root certificate versions so the UI can render the
// current trust configuration.
type rootsResponse struct {
	Roots []rootInfo `json:"roots"`
}

type rootInfo struct {
	CertID   string `json:"certId"`
	EntityID string `json:"entityId"`
	Subject  string `json:"subject"`
	Version  int    `json:"version"`
}

func (a *API) getState(w http.ResponseWriter, r *http.Request) {
	st := a.store.Snapshot()
	out := map[string]any{
		"createdAt": st.CreatedAt,
		"entities":  st.Entities,
		"certs":     st.Certificates,
		"order":     st.Order,
		"roots":     listRoots(st),
	}
	writeJSON(w, http.StatusOK, out)
}

func listRoots(st *State) []rootInfo {
	var roots []rootInfo
	for _, eid := range st.Order {
		e := st.Entities[eid]
		if e.Kind != "root" {
			continue
		}
		for _, cid := range e.Versions {
			c := st.Certificates[cid]
			if c.CrossSignedBy != "" {
				continue
			}
			roots = append(roots, rootInfo{CertID: c.ID, EntityID: e.ID, Subject: c.Subject, Version: c.Version})
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].Subject < roots[j].Subject })
	return roots
}

func (a *API) bootstrap(w http.ResponseWriter, r *http.Request) {
	if err := a.store.Bootstrap(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.getState(w, r)
}

type issueReq struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	IssuerID    string   `json:"issuerId"`
	EKUs        []string `json:"ekus"`
	Description string   `json:"description"`
	TTLDays     int      `json:"ttlDays"`
	StartInDays int      `json:"startInDays"` // negative => started in past; for seeding expiry
}

func (a *API) issue(w http.ResponseWriter, r *http.Request) {
	var req issueReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, errBad("name is required"))
		return
	}
	if req.Kind != "root" && req.Kind != "intermediate" && req.Kind != "leaf" {
		writeErr(w, http.StatusBadRequest, errBad("kind must be root, intermediate or leaf"))
		return
	}
	ttl := time.Duration(req.TTLDays) * 24 * time.Hour
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	nbf := time.Now().Add(time.Duration(req.StartInDays) * 24 * time.Hour)
	c, err := a.store.Issue(IssueParams{
		Name: req.Name, Kind: req.Kind, IssuerID: req.IssuerID, EKUs: req.EKUs,
		Description: req.Description, NotBefore: nbf, TTL: ttl,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cert": c})
}

type crossReq struct {
	TargetCertID string `json:"targetCertId"`
	SignerRootID string `json:"signerRootId"` // entity ID
}

func (a *API) crossSign(w http.ResponseWriter, r *http.Request) {
	var req crossReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	c, err := a.store.CrossSign(req.TargetCertID, req.SignerRootID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cert": c})
}

type revokeReq struct {
	CertID string `json:"certId"`
	Reason string `json:"reason"`
}

func (a *API) revoke(w http.ResponseWriter, r *http.Request) {
	var req revokeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	c, err := a.store.Revoke(req.CertID, req.Reason)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cert": c})
}

type verifyReq struct {
	LeafCertID string   `json:"leafCertId"`
	Purpose    string   `json:"purpose"`    // serverAuth | clientAuth
	TrustRoots []string `json:"trustRoots"` // trusted root CERT ids
	AtDays     int      `json:"atDays"`     // evaluation time offset from now
}

func (a *API) verify(w http.ResponseWriter, r *http.Request) {
	var req verifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.Purpose == "" {
		req.Purpose = "serverAuth"
	}
	res, err := a.store.Verify(req.LeafCertID, req.Purpose, req.TrustRoots, time.Now().Add(time.Duration(req.AtDays)*24*time.Hour))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *API) reset(w http.ResponseWriter, r *http.Request) {
	if err := a.store.Reset(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.getState(w, r)
}

type simpleErr string

func (e simpleErr) Error() string { return string(e) }
func errBad(s string) error       { return simpleErr(s) }
