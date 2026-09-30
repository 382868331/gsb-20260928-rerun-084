package pki

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// PathStep describes one node of a candidate verification path.
type PathStep struct {
	ID             string    `json:"id"`
	Label          string    `json:"label"`
	Kind           NodeKind  `json:"kind"`
	Subject        string    `json:"subject"`
	Issuer         string    `json:"issuer"`
	NotAfter       time.Time `json:"notAfter"`
	Expired        bool      `json:"expired"`
	Revoked        bool      `json:"revoked"`
	SignatureValid bool      `json:"signatureValid"`
	Trusted        bool      `json:"trusted,omitempty"`
}

// CheckResult records one category of verification evidence for a path.
type CheckResult struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}

// ChainReport is one attempted root-to-leaf path with its evaluation.
type ChainReport struct {
	Path   []PathStep    `json:"path"`
	Valid  bool          `json:"valid"`
	Reason string        `json:"reason,omitempty"`
	Checks []CheckResult `json:"checks"`
}

// VerifyResult is the live verification answer. Nothing here is cached.
type VerifyResult struct {
	LeafID       string        `json:"leafId"`
	Purpose      string        `json:"purpose"`
	CheckedAt    time.Time     `json:"checkedAt"`
	Valid        bool          `json:"valid"`
	Reason       string        `json:"reason,omitempty"`
	SelectedPath []string      `json:"selectedPath,omitempty"`
	Chains       []ChainReport `json:"chains"`
	TrustedRoots []string      `json:"trustedRoots"`
}

// Verify performs a live verification of leafID for the requested purpose
// (serverAuth/clientAuth). It considers:
//   - purpose (ExtKeyUsage on the leaf),
//   - validity period of every certificate in the chain,
//   - trust anchor (only currently trusted roots),
//   - revocation, re-read from live state and a freshly generated CRL.
//
// Cross-signed intermediates naturally surface as multiple candidate paths
// (old chain and new chain); expired/dead-end paths are still shown so the
// lab can demonstrate why each path failed. A path passes only when every
// category of evidence passes; one correctly-signed certificate can never
// make a broken chain pass.
func (l *Lab) Verify(leafID string, purpose EKU) (*VerifyResult, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	now := l.nowFunc()
	leaf, ok := l.certs[leafID]
	if !ok {
		return nil, fmt.Errorf("leaf %q not found", leafID)
	}

	res := &VerifyResult{
		LeafID: leafID, Purpose: string(purpose), CheckedAt: now.UTC(),
	}
	for id := range l.trust {
		if l.trust[id] {
			res.TrustedRoots = append(res.TrustedRoots, id)
		}
	}

	wantEKU, ok := map[EKU]x509.ExtKeyUsage{
		EKUServer: x509.ExtKeyUsageServerAuth,
		EKUClient: x509.ExtKeyUsageClientAuth,
	}[purpose]
	if !ok {
		return nil, fmt.Errorf("unknown purpose %q", purpose)
	}

	// Enumerate every cryptographic path from the leaf to a self-signed root.
	var chains [][]*Cert
	l.enumerate(leaf, map[string]bool{}, nil, &chains)

	for _, chain := range chains {
		report := ChainReport{Valid: true}
		// chain order: leaf ... root; present root-first.
		for i := len(chain) - 1; i >= 0; i-- {
			c := chain[i]
			step := PathStep{
				ID: c.ID, Label: c.Label, Kind: c.Kind,
				Subject: c.Cert.Subject.String(), Issuer: c.Cert.Issuer.String(),
				NotAfter: c.Cert.NotAfter, Expired: now.Before(c.Cert.NotBefore) || now.After(c.Cert.NotAfter),
				Revoked: c.Revoked,
			}
			if i == len(chain)-1 {
				step.SignatureValid = c.Cert.CheckSignatureFrom(c.Cert) == nil
			} else {
				step.SignatureValid = chain[i].Cert.CheckSignatureFrom(chain[i+1].Cert) == nil
			}
			if c.Kind == KindRoot {
				step.Trusted = l.trust[c.ID]
			}
			report.Path = append(report.Path, step)
		}

		reason, checks := l.evaluateChain(chain, wantEKU, now)
		report.Checks = checks
		if reason != "" {
			report.Valid = false
			report.Reason = reason
		}

		res.Chains = append(res.Chains, report)
		if report.Valid && !res.Valid {
			res.Valid = true
			res.Reason = ""
			res.SelectedPath = idsOf(chain)
		}
	}

	if !res.Valid {
		res.Reason = summarize(res.Chains)
	}
	return res, nil
}

func idsOf(chain []*Cert) []string {
	// root-first order
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
	for _, r := range reports {
		if !r.Valid && !seen[r.Reason] {
			seen[r.Reason] = true
			reasons = append(reasons, r.Reason)
		}
	}
	return strings.Join(reasons, "; ")
}

func (l *Lab) evaluateChain(chain []*Cert, wantEKU x509.ExtKeyUsage, now time.Time) (string, []CheckResult) {
	var checks []CheckResult
	fail := func(name, detail string) (string, []CheckResult) {
		checks = append(checks, CheckResult{Name: name, Pass: false, Detail: detail})
		return detail, checks
	}
	pass := func(name, detail string) {
		checks = append(checks, CheckResult{Name: name, Pass: true, Detail: detail})
	}

	leaf := chain[0]
	hasPurpose := false
	for _, u := range leaf.Cert.ExtKeyUsage {
		if u == wantEKU {
			hasPurpose = true
		}
	}
	if !hasPurpose {
		return fail("purpose", "证书用途不包含所请求的 ExtKeyUsage")
	}
	pass("purpose", "叶子证书包含所请求的用途")

	// Every hop signature is checked individually first: one correctly
	// signed certificate must never make the whole path pass.
	for i := 0; i < len(chain); i++ {
		if i < len(chain)-1 {
			if err := chain[i].Cert.CheckSignatureFrom(chain[i+1].Cert); err != nil {
				return fail("signature", fmt.Sprintf("%q 无法由链上一级 %q 验证签名", chain[i].Label, chain[i+1].Label))
			}
		} else if err := chain[i].Cert.CheckSignatureFrom(chain[i].Cert); err != nil {
			return fail("signature", fmt.Sprintf("根 %q 自签名无效", chain[i].Label))
		}
	}
	pass("signature", "链上每张证书的签名均可由上一级公钥验证")

	root := chain[len(chain)-1]
	if root.Kind != KindRoot || root.Cert.Subject.String() != root.Cert.Issuer.String() {
		return fail("trust", "路径未能到达自签名根证书（信任路径不完整）")
	}
	for _, c := range chain {
		if now.Before(c.Cert.NotBefore) {
			return fail("validity", fmt.Sprintf("证书 %q 尚未生效（%s 起生效）", c.Label, c.Cert.NotBefore.Format(time.RFC3339)))
		}
		if now.After(c.Cert.NotAfter) {
			return fail("validity", fmt.Sprintf("证书 %q 已过期（%s 到期）", c.Label, c.Cert.NotAfter.Format(time.RFC3339)))
		}
		if c != leaf && !c.Cert.IsCA {
			return fail("basicConstraints", fmt.Sprintf("证书 %q 不是 CA 证书，不能签发下级", c.Label))
		}
	}
	pass("validity", "链上所有证书均在有效期内")

	if !l.trust[root.ID] {
		return fail("trust", fmt.Sprintf("根 %q 当前不是受信任锚点", root.Label))
	}
	pass("trust", fmt.Sprintf("到达受信任根 %q", root.Label))

	// Cryptographic confirmation via the standard library.
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	intermediates := x509.NewCertPool()
	for _, c := range chain[1 : len(chain)-1] {
		intermediates.AddCert(c.Cert)
	}
	if _, err := leaf.Cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{wantEKU},
	}); err != nil {
		return fail("pathValidation", "标准库完整链验证失败: "+err.Error())
	}
	pass("pathValidation", "x509 标准库完整链验证通过")

	// Freshly generated revocation data for every issuing CA (no cache).
	for _, c := range chain[1:] {
		if c.CRLBlocked {
			return fail("revocation", fmt.Sprintf("CA %q 未发布撤销资料（CRL 缺失）", c.Label))
		}
		der, err := l.buildCRLLocked(c)
		if err != nil {
			return fail("revocation", "无法获取 "+c.Label+" 的 CRL: "+err.Error())
		}
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			return fail("revocation", c.Label+" 的 CRL 无法解析")
		}
		if err := crl.CheckSignatureFrom(c.Cert); err != nil {
			return fail("revocation", c.Label+" 的 CRL 签名无效")
		}
		if now.Before(crl.ThisUpdate) || now.After(crl.NextUpdate) {
			return fail("revocation", c.Label+" 的 CRL 已过期")
		}
		for _, entry := range crl.RevokedCertificateEntries {
			for _, subject := range chain {
				if subject.Cert.SerialNumber.Cmp(entry.SerialNumber) == 0 {
					return fail("revocation", fmt.Sprintf("CRL 显示链上证书 %q 已撤销", subject.Label))
				}
			}
		}
	}
	pass("revocation", "所有签发 CA 的 CRL 可获取、签名有效且未列出链上证书")
	return "", checks
}

func (l *Lab) buildCRLLocked(ca *Cert) ([]byte, error) {
	now := l.nowFunc()
	var revoked []x509.RevocationListEntry
	for _, c := range l.certs {
		if c.IssuerID == ca.ID && c.Revoked {
			revoked = append(revoked, x509.RevocationListEntry{
				SerialNumber:   c.Cert.SerialNumber,
				RevocationTime: c.RevokedAt,
			})
		}
	}
	tmpl := &x509.RevocationList{
		Number:                    new(big.Int).SetUint64(l.seq.Add(1)),
		ThisUpdate:                now.Add(-time.Minute),
		NextUpdate:                now.Add(time.Hour),
		RevokedCertificateEntries: revoked,
	}
	return x509.CreateRevocationList(rand.Reader, tmpl, ca.Cert, ca.Key)
}

// enumerate DFS-walks all parents that cryptographically signed the current
// certificate. A cross certificate shares subject DN and public key with the
// original intermediate, so substituting it redirects the path to the
// cross-signing root, producing the old-root and new-root paths during root
// migration. Dead ends are still emitted as partial paths.
func (l *Lab) enumerate(cur *Cert, visited map[string]bool, acc []*Cert, out *[][]*Cert) {
	nextVisited := map[string]bool{}
	for k, v := range visited {
		nextVisited[k] = v
	}
	nextVisited[cur.ID] = true
	acc = append(append([]*Cert{}, acc...), cur)

	// Cross-certificate alternative: the cross certificate has the SAME
	// subject DN and public key as cur but a different issuer. Swap cur for
	// the cross certificate in the path and continue upward from it. The
	// shared key keeps the lower signature valid.
	for _, cross := range l.certs {
		if cross.Kind != KindCross || cross.IssuerID != cur.ID || nextVisited[cross.ID] {
			continue
		}
		replaced := append([]*Cert{}, acc[:len(acc)-1]...)
		replaced = append(replaced, cross)
		l.enumerateUp(cross, nextVisited, replaced, out)
	}

	l.enumerateUp(cur, nextVisited, acc, out)
}

// enumerateUp extends the path with cryptographic signers of cur.
func (l *Lab) enumerateUp(cur *Cert, visited map[string]bool, acc []*Cert, out *[][]*Cert) {
	selfSigned := cur.Kind == KindRoot && cur.Cert.Subject.String() == cur.Cert.Issuer.String()
	if selfSigned {
		*out = append(*out, acc)
		return
	}
	extended := false
	for _, parent := range l.certs {
		if visited[parent.ID] {
			continue
		}
		if !parent.Cert.IsCA {
			continue
		}
		// Cross certificates are reached via the explicit substitution in
		// enumerate, not as direct signers of ordinary nodes.
		if parent.Kind == KindCross {
			continue
		}
		if err := cur.Cert.CheckSignatureFrom(parent.Cert); err == nil {
			extended = true
			l.enumerate(parent, visited, acc, out)
		}
	}
	if !extended {
		// Dead end: still report the partial path so expired/broken paths are
		// visible in the UI.
		*out = append(*out, acc)
	}
}
