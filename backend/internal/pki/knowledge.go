package pki

import (
	"fmt"
	"time"
)

// TrustEvent is one piece of root-trust material. Every event has two
// clocks: EffectiveFrom is when the trust decision takes effect (a root can
// stop being trusted at a future or past moment), AcquiredAt is when the
// researcher obtained the material. Events are append-only: later material
// never rewrites what an earlier investigation could have known.
type TrustEvent struct {
	RootID        string    `json:"rootId"`
	Trusted       bool      `json:"trusted"`
	EffectiveFrom time.Time `json:"effectiveFrom"`
	AcquiredAt    time.Time `json:"acquiredAt"`
	Note          string    `json:"note,omitempty"`
}

// RevocationEvent is one piece of revocation material about a certificate.
// RevokedAt is the declared moment the certificate stopped being valid
// (which may be corrected by later material), AcquiredAt is when the notice
// reached the researcher. Late, corrected or contradictory notices coexist
// in the log and are shown side by side.
type RevocationEvent struct {
	CertID     string    `json:"certId"`
	RevokedAt  time.Time `json:"revokedAt"`
	AcquiredAt time.Time `json:"acquiredAt"`
	Note       string    `json:"note,omitempty"`
}

// KnowledgeView is the side-by-side listing of all trust and revocation
// material the lab has ever received.
type KnowledgeView struct {
	TrustEvents      []TrustEvent      `json:"trustEvents"`
	RevocationEvents []RevocationEvent `json:"revocationEvents"`
}

// Knowledge returns every trust/revocation material item, oldest first.
func (l *Lab) Knowledge() KnowledgeView {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := KnowledgeView{
		TrustEvents:      append([]TrustEvent{}, l.trustLog...),
		RevocationEvents: append([]RevocationEvent{}, l.revLog...),
	}
	return out
}

// trustAt evaluates root trust at (eventTime, cutoff): among material
// obtained by cutoff whose effective time covers the event, the one with
// the latest EffectiveFrom decides. found=false means no material covers
// the event moment at all, so the trust state stays undetermined.
func trustAt(events []TrustEvent, rootID string, eventTime, cutoff time.Time) (trusted, found bool, basis *TrustEvent) {
	var best *TrustEvent
	for i := range events {
		e := &events[i]
		if e.RootID != rootID || e.AcquiredAt.After(cutoff) || e.EffectiveFrom.After(eventTime) {
			continue
		}
		if best == nil || e.EffectiveFrom.After(best.EffectiveFrom) {
			best = e
		}
	}
	if best == nil {
		return false, false, nil
	}
	return best.Trusted, true, best
}

// revocationAt reports whether the certificate was revoked at eventTime
// according to material obtained by cutoff. The latest-obtained applicable
// notice decides; corrected dates therefore supersede earlier ones.
func revocationAt(events []RevocationEvent, certID string, eventTime, cutoff time.Time) (revoked bool, basis *RevocationEvent) {
	var best *RevocationEvent
	for i := range events {
		e := &events[i]
		if e.CertID != certID || e.AcquiredAt.After(cutoff) {
			continue
		}
		if best == nil || e.AcquiredAt.After(best.AcquiredAt) {
			best = e
		}
	}
	if best == nil || best.RevokedAt.After(eventTime) {
		return false, nil
	}
	return true, best
}

// recordTrust appends trust material and refreshes the current trust map
// (the "today" view) from material already acquired by now.
func (l *Lab) recordTrustLocked(ev TrustEvent) {
	l.trustLog = append(l.trustLog, ev)
	now := l.nowFunc()
	trusted, found, _ := trustAt(l.trustLog, ev.RootID, now, now)
	if found {
		if l.trust[ev.RootID] != trusted {
			l.trust[ev.RootID] = trusted
		}
	}
	l.rulesVersion++
}

// recordRevocationLocked appends revocation material and refreshes the
// current revoked view from material already acquired by now.
func (l *Lab) recordRevocationLocked(ev RevocationEvent) {
	l.revLog = append(l.revLog, ev)
	c, ok := l.certs[ev.CertID]
	if !ok {
		return
	}
	now := l.nowFunc()
	if revoked, basis := revocationAt(l.revLog, ev.CertID, now, now); revoked {
		c.Revoked = true
		c.RevokedAt = basis.RevokedAt
	}
	l.rulesVersion++
}

// SetTrustTimed records trust material with explicit effective/acquired
// times so experiments can model a root that stops being trusted before or
// after the event under investigation.
func (l *Lab) SetTrustTimed(rootID string, trusted bool, effectiveFrom, acquiredAt time.Time, note string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.certs[rootID]
	if !ok || c.Kind != KindRoot {
		return fmt.Errorf("root %q not found", rootID)
	}
	l.recordTrustLocked(TrustEvent{
		RootID: rootID, Trusted: trusted,
		EffectiveFrom: effectiveFrom.UTC(), AcquiredAt: acquiredAt.UTC(), Note: note,
	})
	return nil
}

// RevokeTimed records revocation material with explicit revoked/acquired
// times. A revokedAt earlier than an existing notice models a correction;
// an acquiredAt in the future models a late notice that already shows the
// certificate was invalid earlier.
func (l *Lab) RevokeTimed(id string, revokedAt, acquiredAt time.Time, note string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.certs[id]; !ok {
		return fmt.Errorf("cert %q not found", id)
	}
	l.recordRevocationLocked(RevocationEvent{
		CertID: id, RevokedAt: revokedAt.UTC(), AcquiredAt: acquiredAt.UTC(), Note: note,
	})
	return nil
}
