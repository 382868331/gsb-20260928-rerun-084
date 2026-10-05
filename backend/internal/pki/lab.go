package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Lab holds the whole fictional PKI experiment in memory. Verification never
// caches its cryptographic answer, but every verification is appended to an
// immutable evidence history. Trust-rule changes bump the rule version so a
// later re-verification can never silently overwrite older evidence.
type Lab struct {
	mu           sync.RWMutex
	seq          atomic.Uint64
	certs        map[string]*Cert
	trustLog     []TrustEvent // append-only learned trust changes
	nowFunc      func() time.Time
	history      []*VerifyResult
	rulesVersion int
}

func NewLab() *Lab {
	return &Lab{
		certs:        map[string]*Cert{},
		nowFunc:      time.Now,
		rulesVersion: 1,
	}
}

func (l *Lab) Now() time.Time { return l.nowFunc() }

// SetClock overrides the lab clock (tests/demos of expiry).
func (l *Lab) SetClock(f func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nowFunc = f
}

func (l *Lab) Get(id string) (*Cert, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	c, ok := l.certs[id]
	return c, ok
}

func (l *Lab) List() []*Cert {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]*Cert, 0, len(l.certs))
	for _, c := range l.certs {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (l *Lab) put(c *Cert) { l.certs[c.ID] = c }

// AddRoot creates and trusts a new root. A root publishes CRL data by
// default; use SetCRLPublished to demonstrate missing revocation data.
func (l *Lab) AddRoot(id, cn string, years int) (*Cert, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.nowFunc()
	c, err := CreateRoot(id, cn, now.Add(-time.Minute), now.AddDate(years, 0, 0), &l.seq)
	if err != nil {
		return nil, err
	}
	c.CRLPublished = true
	c.CRLKnownAt = now.UTC()
	c.LearnedAt = now.UTC()
	l.put(c)
	l.issueCRLLocked(c, now)
	l.trustLog = append(l.trustLog, TrustEvent{RootID: id, Trusted: true, EffectiveAt: now.UTC(), LearnedAt: now.UTC()})
	l.rulesVersion++
	return c, nil
}

// AddIntermediate issues an intermediate under issuerID. When crossSubjectID
// is set, a cross certificate for that existing intermediate is created
// instead of a fresh key (used during root migration).
//
// years may be negative: the resulting certificate is already expired, which
// the lab uses for the "expired intermediate" sample.
func (l *Lab) AddIntermediate(id, cn, issuerID, crossSubjectID string, years int) (*Cert, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	issuer, ok := l.certs[issuerID]
	if !ok {
		return nil, fmt.Errorf("issuer %q not found", issuerID)
	}
	now := l.nowFunc()
	opts := IssueOptions{
		ID: id, Label: cn, CN: cn, Intermediate: true,
		NotBefore: normalizeBounds(now, years, false), NotAfter: normalizeBounds(now, years, true),
	}
	var override *Cert
	if crossSubjectID != "" {
		sub, ok := l.certs[crossSubjectID]
		if !ok {
			return nil, fmt.Errorf("cross subject %q not found", crossSubjectID)
		}
		override = sub
		opts.Label = cn
	}
	c, err := Issue(issuer, opts, override, &l.seq)
	if err != nil {
		return nil, err
	}
	c.CRLPublished = true
	c.CRLKnownAt = now.UTC()
	c.LearnedAt = now.UTC()
	l.put(c)
	l.issueCRLLocked(c, now)
	return c, nil
}

// normalizeBounds keeps NotBefore strictly before NotAfter even for the
// negative-duration (already expired) sample certificates.
func normalizeBounds(now time.Time, years int, after bool) time.Time {
	if years < 0 {
		start := now.AddDate(years*2, 0, 0)
		end := now.AddDate(years, 0, 0)
		if after {
			return end
		}
		return start
	}
	if after {
		return now.AddDate(years, 0, 0)
	}
	return now.Add(-time.Minute)
}

// AddLeaf issues an end-entity certificate for the given purposes.
func (l *Lab) AddLeaf(id, cn, issuerID string, ekus []EKU, dnsNames []string, days int) (*Cert, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.addLeafLocked(id, cn, issuerID, ekus, dnsNames, days)
}

func (l *Lab) addLeafLocked(id, cn, issuerID string, ekus []EKU, dnsNames []string, days int) (*Cert, error) {
	issuer, ok := l.certs[issuerID]
	if !ok {
		return nil, fmt.Errorf("issuer %q not found", issuerID)
	}
	if issuer.Kind == KindLeaf {
		return nil, fmt.Errorf("cannot issue from a leaf certificate")
	}
	issuer = l.canonicalIssuerLocked(issuer)
	if issuer.Kind == KindLeaf {
		return nil, fmt.Errorf("cannot issue from a leaf certificate")
	}
	now := l.nowFunc()
	c, err := Issue(issuer, IssueOptions{
		ID: id, Label: cn, CN: cn, EKUs: ekus, DNSNames: dnsNames,
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(0, 0, days),
	}, nil, &l.seq)
	if err != nil {
		return nil, err
	}
	c.LearnedAt = now.UTC()
	l.put(c)
	return c, nil
}

// canonicalIssuerLocked resolves a cross certificate node to the logical CA
// node that owns the signing key (the original intermediate). A leaf issued
// after migration is therefore signed by the same key but can still chain
// through either DN-compatible issuer certificate.
func (l *Lab) canonicalIssuerLocked(c *Cert) *Cert {
	if c.Kind == KindCross && c.ParentID != "" {
		if owner, ok := l.certs[c.ParentID]; ok {
			return owner
		}
	}
	return c
}

// RotateLeaf re-issues an end-entity certificate under newIssuerID with a new
// key, copying CN, DNS names and purposes from the previous generation. The
// old certificate remains in the lab (revoked or not) as historical
// evidence; the returned cert is the new active generation. It does not
// revoke the old leaf automatically, so experiments can compare both.
func (l *Lab) RotateLeaf(newID, leafID, newIssuerID string, days int) (*Cert, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	old, ok := l.certs[leafID]
	if !ok {
		return nil, fmt.Errorf("leaf %q not found", leafID)
	}
	if old.Kind != KindLeaf {
		return nil, fmt.Errorf("%q is not a leaf certificate", leafID)
	}
	var ekus []EKU
	for _, u := range old.Cert.ExtKeyUsage {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			ekus = append(ekus, EKUServer)
		case x509.ExtKeyUsageClientAuth:
			ekus = append(ekus, EKUClient)
		}
	}
	newCN := old.Cert.Subject.CommonName
	return l.addLeafLocked(newID, newCN, newIssuerID, ekus, old.Cert.DNSNames, days)
}

// SetTrust marks a root as trusted (anchor) or distrusted with immediate
// effect. Old and new roots can coexist during migration so both chains
// validate until cut-over. Changing trust is a rules change and bumps the
// rules version.
func (l *Lab) SetTrust(rootID string, trusted bool) error {
	return l.ScheduleTrust(rootID, trusted, time.Time{})
}

// ScheduleTrust registers a trust decision learned now but taking effect
// at effectiveAt (zero means immediately). This models a change announced
// in advance: investigations of events before effectiveAt keep the
// previous trust status even when their knowledge cutoff already includes
// the announcement, while investigations of later events apply it.
func (l *Lab) ScheduleTrust(rootID string, trusted bool, effectiveAt time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.certs[rootID]
	if !ok || c.Kind != KindRoot {
		return fmt.Errorf("root %q not found", rootID)
	}
	now := l.nowFunc().UTC()
	immediate := effectiveAt.IsZero()
	if effectiveAt.IsZero() {
		effectiveAt = now
	}
	effectiveAt = effectiveAt.UTC()
	current, _, _, known := l.trustedAtLocked(rootID, now, now)
	if immediate && known && current == trusted {
		return nil
	}
	l.trustLog = append(l.trustLog, TrustEvent{
		RootID: rootID, Trusted: trusted, EffectiveAt: effectiveAt, LearnedAt: now,
	})
	l.rulesVersion++
	return nil
}

// trustedAtLocked reconstructs the trust status of rootID in effect at
// eventTime, using only trust events learned on or before the knowledge
// cutoff. This keeps the two clocks separate: a root trusted when the
// event happened but distrusted later still counts as trusted for that
// event, and a change announced early only applies to events at or after
// its effective time. The returned times are the adopted decision's
// effective and learned moments; the final return reports whether any
// applicable decision is known at all.
func (l *Lab) trustedAtLocked(rootID string, eventTime, cutoff time.Time) (bool, time.Time, time.Time, bool) {
	var trusted bool
	var effective, learned time.Time
	known := false
	for _, ev := range l.trustLog {
		if ev.RootID != rootID || ev.LearnedAt.After(cutoff) || ev.EffectiveAt.After(eventTime) {
			continue
		}
		if !known || ev.EffectiveAt.After(effective) ||
			(ev.EffectiveAt.Equal(effective) && ev.LearnedAt.After(learned)) {
			trusted, effective, learned, known = ev.Trusted, ev.EffectiveAt, ev.LearnedAt, true
		}
	}
	return trusted, effective, learned, known
}

// trustConflictLocked reports contradictory trust decisions visible at the
// knowledge cutoff for the same root: multiple applicable decisions that
// do not agree. The investigation adopts the latest-effective one (ties
// broken by latest learned) and the note explains that basis instead of
// silently overwriting.
func (l *Lab) trustConflictLocked(rootID string, eventTime, cutoff time.Time) string {
	var applicable []TrustEvent
	for _, ev := range l.trustLog {
		if ev.RootID == rootID && !ev.LearnedAt.After(cutoff) && !ev.EffectiveAt.After(eventTime) {
			applicable = append(applicable, ev)
		}
	}
	if len(applicable) < 2 {
		return ""
	}
	adopted, _, _, _ := l.trustedAtLocked(rootID, eventTime, cutoff)
	disagree := false
	for _, ev := range applicable {
		if ev.Trusted != adopted {
			disagree = true
		}
	}
	if !disagree {
		return ""
	}
	return fmt.Sprintf("存在 %d 条相互矛盾的信任决定；采用事件时刻生效的最新决定（%s），其余保留备查",
		len(applicable), map[bool]string{true: "受信任", false: "停止受信"}[adopted])
}

// TrustLog returns the append-only trust decision history, oldest first.
func (l *Lab) TrustLog() []TrustEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]TrustEvent, len(l.trustLog))
	copy(out, l.trustLog)
	return out
}

func (l *Lab) TrustedRoots() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.trustedRootsAtLocked(l.nowFunc())
}

// trustedRootsAtLocked lists the roots whose trust decision is in effect
// at t, based on every learned trust event (including ones learned after
// t, since the current trust set is a present-day fact).
func (l *Lab) trustedRootsAtLocked(t time.Time) []string {
	var ids []string
	seen := map[string]bool{}
	for _, ev := range l.trustLog {
		seen[ev.RootID] = true
	}
	farFuture := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	for id := range seen {
		if trusted, _, _, known := l.trustedAtLocked(id, t, farFuture); known && trusted {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func (l *Lab) RulesVersion() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.rulesVersion
}

// Revoke marks a certificate revoked as of now. The claim is appended to
// the certificate's revocation log with the current time as both the
// effective and the learned time; the next live verification sees it.
func (l *Lab) Revoke(id string) error {
	return l.RevokeAt(id, time.Time{})
}

// RevokeAt registers a revocation claim learned now whose effective time
// is revokedAt (zero means now). A past revokedAt models late-arriving
// revocation material: the lab only learns today that the certificate
// stopped being valid earlier. Investigations whose knowledge cutoff
// predates this claim still reproduce the old conclusion.
func (l *Lab) RevokeAt(id string, revokedAt time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.certs[id]
	if !ok {
		return fmt.Errorf("cert %q not found", id)
	}
	now := l.nowFunc().UTC()
	if revokedAt.IsZero() {
		revokedAt = now
	}
	revokedAt = revokedAt.UTC()
	if c.Revoked && len(c.Revocations) > 0 {
		latest := c.Revocations[len(c.Revocations)-1]
		if !latest.Retracted && latest.RevokedAt.Equal(revokedAt) {
			return nil
		}
	}
	c.Revoked = true
	c.RevokedAt = revokedAt
	note := ""
	if revokedAt.Before(now.Add(-time.Minute)) {
		note = "late-arriving revocation material"
	}
	c.Revocations = append(c.Revocations, RevocationRecord{
		RevokedAt: revokedAt, LearnedAt: now, Note: note,
	})
	l.reissueIssuerCRLLocked(c, now)
	l.rulesVersion++
	return nil
}

// RetractRevocation appends a claim withdrawing the earlier revocation
// claims about a certificate. The old claims stay in the log, so
// investigations with a knowledge cutoff before the retraction still
// reproduce the revoked conclusion; newer investigations treat the
// certificate as not revoked.
func (l *Lab) RetractRevocation(id, note string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.certs[id]
	if !ok {
		return fmt.Errorf("cert %q not found", id)
	}
	if !c.Revoked {
		return fmt.Errorf("cert %q is not revoked; nothing to retract", id)
	}
	now := l.nowFunc().UTC()
	if note == "" {
		note = "retracted revocation material"
	}
	c.Revocations = append(c.Revocations, RevocationRecord{
		RevokedAt: now, LearnedAt: now, Note: note, Retracted: true,
	})
	c.Revoked = false
	c.RevokedAt = time.Time{}
	l.reissueIssuerCRLLocked(c, now)
	l.rulesVersion++
	return nil
}

// CorrectRevocation appends a corrected revocation claim: the lab learns
// now that the certificate was actually revoked at revokedAt (possibly
// earlier than the original claim). The previous record is kept, so
// investigations with a knowledge cutoff before this correction still
// reproduce the old conclusion.
func (l *Lab) CorrectRevocation(id string, revokedAt time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.certs[id]
	if !ok {
		return fmt.Errorf("cert %q not found", id)
	}
	if !c.Revoked {
		return fmt.Errorf("cert %q is not revoked; nothing to correct", id)
	}
	now := l.nowFunc().UTC()
	c.Revocations = append(c.Revocations, RevocationRecord{
		RevokedAt: revokedAt.UTC(), LearnedAt: now, Note: "corrected revocation date",
	})
	c.RevokedAt = revokedAt.UTC()
	l.reissueIssuerCRLLocked(c, now)
	l.rulesVersion++
	return nil
}

// reissueIssuerCRLLocked records a fresh CRL issuance by the CA that
// issued c, modelling the CA republishing its revocation list when the
// revocation state of one of its certificates changes.
func (l *Lab) reissueIssuerCRLLocked(c *Cert, now time.Time) {
	issuer, ok := l.certs[c.IssuerID]
	if !ok || issuer.Kind == KindLeaf || !issuer.CRLPublished {
		return
	}
	l.issueCRLLocked(issuer, now)
}

// revocationAtLocked returns the latest revocation claim learned on or
// before the knowledge cutoff. The boolean reports whether any claim is
// known at all at that cutoff. A retracted claim means the certificate
// counts as not revoked for that investigation.
func revocationAtLocked(c *Cert, cutoff time.Time) (RevocationRecord, bool) {
	var rec RevocationRecord
	known := false
	for _, r := range c.Revocations {
		if r.LearnedAt.After(cutoff) {
			continue
		}
		if !known || r.LearnedAt.After(rec.LearnedAt) {
			rec, known = r, true
		}
	}
	return rec, known
}

// revocationConflictLocked describes contradictory revocation claims
// visible at the knowledge cutoff (different effective times, or claims
// and retractions). The adopted claim is the one with the latest learned
// time; the note makes that basis explicit instead of silently letting
// the last write win.
func revocationConflictLocked(c *Cert, cutoff time.Time) string {
	var visible []RevocationRecord
	for _, r := range c.Revocations {
		if !r.LearnedAt.After(cutoff) {
			visible = append(visible, r)
		}
	}
	if len(visible) < 2 {
		return ""
	}
	conflict := false
	for i := 1; i < len(visible); i++ {
		if visible[i].Retracted != visible[0].Retracted ||
			(!visible[i].Retracted && !visible[i].RevokedAt.Equal(visible[0].RevokedAt)) {
			conflict = true
		}
	}
	if !conflict {
		return ""
	}
	adopted, _ := revocationAtLocked(c, cutoff)
	basis := "生效 " + adopted.RevokedAt.Format(time.RFC3339)
	if adopted.Retracted {
		basis = "撤回先前撤销"
	}
	return fmt.Sprintf("存在 %d 条相互矛盾的撤销材料；采用获知时间最新者（获知 %s，%s），其余保留备查",
		len(visible), adopted.LearnedAt.Format(time.RFC3339), basis)
}

// SetCRLPublished controls whether a CA publishes revocation data. Turning
// this off models "revocation information unavailable": chains through that
// CA must fail even if every signature is cryptographically correct.
func (l *Lab) SetCRLPublished(caID string, published bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.certs[caID]
	if !ok {
		return fmt.Errorf("cert %q not found", caID)
	}
	if c.Kind == KindLeaf {
		return fmt.Errorf("leaf %q cannot publish a CRL", caID)
	}
	if c.CRLPublished != published {
		c.CRLPublished = published
		if published {
			c.CRLKnownAt = l.nowFunc().UTC()
			l.issueCRLLocked(c, l.nowFunc())
		}
		l.rulesVersion++
	}
	return nil
}

// SetCRLDelay models revocation material that arrives late: the CA keeps
// publishing a CRL, but its ThisUpdate sits the given minutes in the
// future, so verifications before that moment cannot yet rely on it.
// Changing the delay is a rules change and bumps the rules version.
func (l *Lab) SetCRLDelay(caID string, minutes int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.certs[caID]
	if !ok {
		return fmt.Errorf("cert %q not found", caID)
	}
	if c.Kind == KindLeaf {
		return fmt.Errorf("leaf %q cannot publish a CRL", caID)
	}
	if minutes < 0 {
		minutes = 0
	}
	if c.CRLDelayMin != minutes {
		c.CRLDelayMin = minutes
		l.rulesVersion++
	}
	return nil
}

// CRL renders a fresh X.509 CRL for a CA node containing every currently
// revoked certificate that the CA issued. It is generated on demand, so it
// can never serve stale revocation data. Each fetch is recorded in the
// CA's issuance log so later historical investigations can cite the exact
// coverage interval that was learnable then.
func (l *Lab) CRL(caID string) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ca, ok := l.certs[caID]
	if !ok {
		return nil, fmt.Errorf("ca %q not found", caID)
	}
	if !ca.CRLPublished {
		return nil, fmt.Errorf("CA %q does not publish revocation data", caID)
	}
	return l.buildCRLLocked(ca)
}

func (l *Lab) buildCRLLocked(ca *Cert) ([]byte, error) {
	now := l.nowFunc()
	iss := l.issueCRLLocked(ca, now)
	return l.buildCRLAtLocked(ca, iss, now)
}

// issueCRLLocked records a fresh CRL issuance for ca as of now and
// returns it. The coverage interval is frozen at issuance: later queries
// with a different knowledge cutoff select among these records but never
// rewrite their times.
func (l *Lab) issueCRLLocked(ca *Cert, now time.Time) CRLIssue {
	now = now.UTC()
	iss := CRLIssue{
		ThisUpdate: now.Add(-time.Minute).Add(time.Duration(ca.CRLDelayMin) * time.Minute),
		NextUpdate: now.Add(time.Hour),
		LearnedAt:  now,
	}
	ca.CRLIssues = append(ca.CRLIssues, iss)
	return iss
}

// crlIssueCoveringLocked returns the latest CRL issuance learned on or
// before the knowledge cutoff whose coverage interval contains
// eventTime. The boolean reports whether any such issuance is known.
func crlIssueCoveringLocked(ca *Cert, eventTime, cutoff time.Time) (CRLIssue, bool) {
	var iss CRLIssue
	known := false
	for _, it := range ca.CRLIssues {
		if it.LearnedAt.After(cutoff) {
			continue
		}
		if eventTime.Before(it.ThisUpdate) || eventTime.After(it.NextUpdate) {
			continue
		}
		if !known || it.LearnedAt.After(iss.LearnedAt) {
			iss, known = it, true
		}
	}
	return iss, known
}

// crlIssueLatestLocked returns the latest CRL issuance learned on or
// before the knowledge cutoff, regardless of coverage.
func crlIssueLatestLocked(ca *Cert, cutoff time.Time) (CRLIssue, bool) {
	var iss CRLIssue
	known := false
	for _, it := range ca.CRLIssues {
		if it.LearnedAt.After(cutoff) {
			continue
		}
		if !known || it.LearnedAt.After(iss.LearnedAt) {
			iss, known = it, true
		}
	}
	return iss, known
}

// buildCRLAtLocked renders the CRL identified by iss as it was knowable
// at the knowledge cutoff: the coverage interval comes from the frozen
// issuance record, and entries only include revocation claims learned on
// or before cutoff, each with its own effective RevokedAt.
func (l *Lab) buildCRLAtLocked(ca *Cert, iss CRLIssue, cutoff time.Time) ([]byte, error) {
	entries := []x509.RevocationListEntry{}
	for _, c := range l.certs {
		if c.IssuerID != ca.ID {
			continue
		}
		if rec, ok := revocationAtLocked(c, cutoff); ok && !rec.Retracted {
			entries = append(entries, x509.RevocationListEntry{
				SerialNumber:   new(big.Int).Set(c.Cert.SerialNumber),
				RevocationTime: rec.RevokedAt,
			})
		}
	}
	tmpl := &x509.RevocationList{
		Number:                    new(big.Int).SetUint64(l.seq.Add(1)),
		ThisUpdate:                iss.ThisUpdate,
		NextUpdate:                iss.NextUpdate,
		RevokedCertificateEntries: entries,
	}
	signer, ok := ca.Key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA %q has no local signing key", ca.ID)
	}
	return x509.CreateRevocationList(rand.Reader, tmpl, ca.Cert, signer)
}

// History returns all immutable verification evidence, newest first.
func (l *Lab) History() []*VerifyResult {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]*VerifyResult, len(l.history))
	copy(out, l.history)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Reset removes all lab state (used by the sample loader).
func (l *Lab) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.certs = map[string]*Cert{}
	l.trustLog = nil
	l.history = nil
	l.seq.Store(0)
	l.rulesVersion = 1
}
