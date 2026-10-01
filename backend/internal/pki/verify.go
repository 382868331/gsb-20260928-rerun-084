package pki

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

type PathStep struct {
	ID           string    `json:"id"`
	Label        string    `json:"label"`
	Kind         NodeKind  `json:"kind"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	Expired      bool      `json:"expired"`
	Revoked      bool      `json:"revoked"`
	CRLPublished bool      `json:"crlPublished"`
	Trusted      bool      `json:"trusted,omitempty"`
}

type CheckStatus string

const (
	CheckPass    CheckStatus = "pass"
	CheckFail    CheckStatus = "fail"
	CheckUnknown CheckStatus = "unknown"
	CheckSkipped CheckStatus = "skipped"
)

type PathCheck struct {
	Name   string      `json:"name"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail"`
}

type ChainReport struct {
	Path    []PathStep  `json:"path"`
	Valid   bool        `json:"valid"`
	Unknown bool        `json:"unknown,omitempty"`
	Reason  string      `json:"reason,omitempty"`
	Checks  []PathCheck `json:"checks"`
}

type VerifyResult struct {
	EvidenceID   int           `json:"evidenceId"`
	RulesVersion int           `json:"rulesVersion"`
	LeafID       string        `json:"leafId"`
	Purpose      string        `json:"purpose"`
	CheckedAt    time.Time     `json:"checkedAt"`
	Valid        bool          `json:"valid"`
	Unknown      bool          `json:"unknown,omitempty"`
	Reason       string        `json:"reason,omitempty"`
	SelectedPath []string      `json:"selectedPath,omitempty"`
	Chains       []ChainReport `json:"chains"`
	TrustedRoots []string      `json:"trustedRoots"`
}

func (l *Lab) Verify(leafID string, purpose EKU) (*VerifyResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.nowFunc()
	leaf, ok := l.certs[leafID]
	if !ok {
		return nil, fmt.Errorf("leaf %q not found", leafID)
	}
	if leaf.Kind != KindLeaf {
		return nil, fmt.Errorf("%q is not a leaf certificate", leafID)
	}
	wantEKU := x509.ExtKeyUsageAny
	switch purpose {
	case EKUServer:
		wantEKU = x509.ExtKeyUsageServerAuth
	case EKUClient:
		wantEKU = x509.ExtKeyUsageClientAuth
	default:
		return nil, fmt.Errorf("unknown purpose %q", purpose)
	}

	res := &VerifyResult{RulesVersion: l.rulesVersion, LeafID: leafID, Purpose: string(purpose), CheckedAt: now.UTC()}
	for id := range l.trust {
		if l.trust[id] {
			res.TrustedRoots = append(res.TrustedRoots, id)
		}
	}

	var chains [][]*Cert
	l.enumerate(leaf, map[string]bool{}, nil, &chains)
	hasDeterministicFailure := false
	hasUnknownPath := false

	for _, chain := range chains {
		report := ChainReport{}
		for i := len(chain) - 1; i >= 0; i-- {
			c := chain[i]
			step := PathStep{
				ID: c.ID, Label: c.Label, Kind: c.Kind,
				Subject: c.Cert.Subject.String(), Issuer: c.Cert.Issuer.String(),
				NotBefore: c.Cert.NotBefore, NotAfter: c.Cert.NotAfter,
				Expired: now.Before(c.Cert.NotBefore) || now.After(c.Cert.NotAfter),
				Revoked: c.Revoked, CRLPublished: c.CRLPublished,
			}
			if c.Kind == KindRoot {
				step.Trusted = l.trust[c.ID]
			}
			report.Path = append(report.Path, step)
		}

		reason, unknown, checks := l.evaluateChainLocked(chain, wantEKU, now)
		report.Checks = checks
		if reason == "" {
			report.Valid = true
			res.Valid = true
			res.SelectedPath = idsOf(chain)
		} else {
			report.Reason = reason
			report.Unknown = unknown
			if unknown {
				hasUnknownPath = true
			} else {
				hasDeterministicFailure = true
			}
		}
		res.Chains = append(res.Chains, report)
	}

	if !res.Valid {
		res.Reason = summarize(res.Chains)
		res.Unknown = hasUnknownPath && !hasDeterministicFailure
	}
	l.history = append(l.history, res)
	res.EvidenceID = len(l.history)
	return res, nil
}

func idsOf(chain []*Cert) []string {
	ids := make([]string, 0, len(chain))
	for i := len(chain) - 1; i >= 0; i-- {
		ids = append(ids, chain[i].ID)
	}
	return ids
}

func summarize(reports []ChainReport) string {
	if len(reports) == 0 {
		return "no cryptographic path to any root"
	}
	seen := map[string]bool{}
	var reasons []string
	for _, report := range reports {
		if !report.Valid && !seen[report.Reason] {
			seen[report.Reason] = true
			reasons = append(reasons, report.Reason)
		}
	}
	return strings.Join(reasons, "; ")
}

func (l *Lab) evaluateChainLocked(chain []*Cert, wantEKU x509.ExtKeyUsage, now time.Time) (string, bool, []PathCheck) {
	leaf := chain[0]
	var checks []PathCheck
	var failures, unknowns []string
	failed := false
	fail := func(name, detail string) {
		failed = true
		if !contains(failures, detail) {
			failures = append(failures, detail)
		}
		checks = append(checks, PathCheck{Name: name, Status: CheckFail, Detail: detail})
	}
	unknown := func(name, detail string) {
		if !contains(unknowns, detail) {
			unknowns = append(unknowns, detail)
		}
		checks = append(checks, PathCheck{Name: name, Status: CheckUnknown, Detail: detail})
	}
	pass := func(name, detail string) {
		checks = append(checks, PathCheck{Name: name, Status: CheckPass, Detail: detail})
	}

	hasPurpose := false
	for _, usage := range leaf.Cert.ExtKeyUsage {
		if usage == wantEKU {
			hasPurpose = true
		}
	}
	if hasPurpose {
		pass("证书用途", "终端证书允许所请求的 ExtKeyUsage")
	} else {
		fail("证书用途", "purpose not permitted by certificate ExtKeyUsage")
	}

	for _, c := range chain {
		name := fmt.Sprintf("期限：%s", c.Label)
		switch {
		case now.Before(c.Cert.NotBefore):
			fail(name, fmt.Sprintf("certificate %q not yet valid until %s", c.Label, c.Cert.NotBefore.Format(time.RFC3339)))
		case now.After(c.Cert.NotAfter):
			fail(name, fmt.Sprintf("certificate %q expired at %s; checked at %s", c.Label, c.Cert.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339)))
		default:
			pass(name, "实验时刻处于证书 NotBefore/NotAfter 有效期内")
		}
		if c != leaf && !c.Cert.IsCA {
			fail(fmt.Sprintf("CA 基本约束：%s", c.Label), fmt.Sprintf("certificate %q is not a CA", c.Label))
		}
	}

	for _, c := range chain {
		name := fmt.Sprintf("本地撤销标记：%s", c.Label)
		if c.Revoked {
			fail(name, fmt.Sprintf("certificate %q revoked at %s", c.Label, c.RevokedAt.Format(time.RFC3339)))
		} else {
			pass(name, "验证时实验状态未把该证书标记为撤销")
		}
	}

	root := chain[len(chain)-1]
	if root.Kind == KindRoot && root.Cert.Subject.String() == root.Cert.Issuer.String() {
		if l.trust[root.ID] {
			pass("信任锚点", root.ID+" 在规则 v"+fmt.Sprint(l.rulesVersion)+" 的信任根集合中")
		} else {
			fail("信任锚点", fmt.Sprintf("root %q is not a trusted anchor", root.Label))
		}
	} else {
		fail("信任锚点", "chain does not end at a self-signed root")
	}

	if failed {
		checks = append(checks, PathCheck{Name: "完整密码学路径", Status: CheckSkipped, Detail: "确定性检查已失败，跳过完整链验证"})
	} else {
		roots := x509.NewCertPool()
		roots.AddCert(root.Cert)
		intermediates := x509.NewCertPool()
		for _, c := range chain[1 : len(chain)-1] {
			intermediates.AddCert(c.Cert)
		}
		if _, err := leaf.Cert.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: intermediates, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{wantEKU},
		}); err != nil {
			fail("完整密码学路径", "chain verification failed: "+err.Error())
		} else {
			pass("完整密码学路径", "x509.Certificate.Verify 已确认完整 leaf-to-root 签名链")
		}
	}

	for _, issuerNode := range chain[1:] {
		ca := l.canonicalIssuerLocked(issuerNode)
		name := fmt.Sprintf("CRL：%s", issuerNode.Label)
		if !issuerNode.CRLPublished || !ca.CRLPublished {
			unknown(name, fmt.Sprintf("revocation data missing for CA %q; revocation status cannot be determined", issuerNode.Label))
			continue
		}
		der, err := l.buildCRLLocked(ca)
		if err != nil {
			unknown(name, "CRL unavailable for "+issuerNode.Label+": "+err.Error())
			continue
		}
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			fail(name, "invalid CRL from "+issuerNode.Label)
			continue
		}
		if err := crl.CheckSignatureFrom(ca.Cert); err != nil {
			fail(name, "CRL signature invalid for "+issuerNode.Label)
			continue
		}
		if now.Before(crl.ThisUpdate) || now.After(crl.NextUpdate) {
			unknown(name, "stale CRL from "+issuerNode.Label+"; revocation status cannot be determined at the check time")
			continue
		}
		listed := false
		for _, c := range chain {
			for _, entry := range crl.RevokedCertificateEntries {
				if c.Cert.SerialNumber.Cmp(entry.SerialNumber) == 0 {
					fail(name, fmt.Sprintf("certificate %q listed on CRL of %q", c.Label, ca.Label))
					listed = true
				}
			}
		}
		if !listed {
			pass(name, "实时 CRL 签名和时效有效，链上序列号均未列入撤销名单")
		}
	}

	if failed {
		return strings.Join(failures, "; "), false, checks
	}
	if len(unknowns) > 0 {
		return strings.Join(unknowns, "; "), true, checks
	}
	return "", false, checks
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func (l *Lab) enumerate(cur *Cert, visited map[string]bool, acc []*Cert, out *[][]*Cert) {
	acc = append(append([]*Cert{}, acc...), cur)
	visited[cur.ID] = true
	selfSigned := cur.Kind == KindRoot && cur.Cert.Subject.String() == cur.Cert.Issuer.String()
	if selfSigned {
		*out = append(*out, acc)
		return
	}
	extended := false
	for _, parent := range l.certs {
		if visited[parent.ID] || !parent.Cert.IsCA {
			continue
		}
		if err := cur.Cert.CheckSignatureFrom(parent.Cert); err == nil {
			next := map[string]bool{}
			for id, ok := range visited {
				next[id] = ok
			}
			extended = true
			l.enumerate(parent, next, acc, out)
		}
	}
	if !extended {
		*out = append(*out, acc)
	}
}
