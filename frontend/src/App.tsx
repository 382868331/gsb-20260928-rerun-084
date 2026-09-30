import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./api";
import type { CertView, ChainReport, Evidence, NodeKind } from "./types";

const kindLabel: Record<NodeKind, string> = {
  root: "根 CA",
  intermediate: "中间 CA",
  cross: "交叉证书",
  leaf: "终端证书",
};

export function App() {
  const [certs, setCerts] = useState<CertView[]>([]);
  const [trustedRoots, setTrustedRoots] = useState<string[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [purpose, setPurpose] = useState("serverAuth");
  const [note, setNote] = useState("");
  const [lastVerify, setLastVerify] = useState<Evidence | null>(null);
  const [error, setError] = useState("");
  const [now, setNow] = useState("");

  const [newRoot, setNewRoot] = useState("");
  const [newIntCN, setNewIntCN] = useState("");
  const [newIntIssuer, setNewIntIssuer] = useState("");
  const [crossSubject, setCrossSubject] = useState("");
  const [newLeafCN, setNewLeafCN] = useState("");
  const [newLeafIssuer, setNewLeafIssuer] = useState("");

  const refresh = useCallback(async () => {
    const [c, e] = await Promise.all([api.list(), api.evidence()]);
    setCerts(c.certs);
    setTrustedRoots(c.trustedRoots);
    setNow(c.now);
    setEvidence(e.evidence);
  }, []);

  useEffect(() => {
    refresh().catch((err) => setError(String(err)));
  }, [refresh]);

  const byId = useMemo(() => {
    const m = new Map<string, CertView>();
    certs.forEach((c) => m.set(c.id, c));
    return m;
  }, [certs]);

  const leaves = certs.filter((c) => c.kind === "leaf");
  const cas = certs.filter((c) => c.kind !== "leaf");
  const roots = certs.filter((c) => c.kind === "root");
  const intermediates = certs.filter((c) => c.kind === "intermediate" || c.kind === "cross");

  async function run(action: () => Promise<unknown>) {
    setError("");
    try {
      await action();
      await refresh();
    } catch (err) {
      setError(String(err));
    }
  }

  async function doVerify() {
    if (!selected) return;
    await run(async () => {
      const ev = await api.verify(selected, purpose, note);
      setLastVerify(ev);
      setNote("");
    });
  }

  return (
    <div className="page">
      <header>
        <h1>证书生命周期实验平台</h1>
        <div className="sub">签发 · 轮换 · 交叉信任路径 · 实时验证（证据只追加，不覆盖）</div>
        <div className="now">实验当前时间：{new Date(now).toLocaleString()} · 受信任根：{trustedRoots.join(", ") || "（无）"}</div>
      </header>

      {error && <div className="error">{error}</div>}

      <section className="panel">
        <h2>1. 签发操作</h2>
        <div className="grid">
          <form onSubmit={(e) => { e.preventDefault(); run(() => api.addRoot(newRoot)).then(() => setNewRoot("")); }}>
            <h3>新建根 CA</h3>
            <input placeholder="根 CA 名称 (CN)" value={newRoot} onChange={(e) => setNewRoot(e.target.value)} />
            <button type="submit">创建并信任</button>
          </form>

          <form onSubmit={(e) => { e.preventDefault(); run(() => api.addIntermediate(newIntCN, newIntIssuer, crossSubject || undefined)).then(() => { setNewIntCN(""); setCrossSubject(""); }); }}>
            <h3>签发中间证书 / 交叉签发</h3>
            <input placeholder="中间 CA 名称 (CN)" value={newIntCN} onChange={(e) => setNewIntCN(e.target.value)} />
            <select value={newIntIssuer} onChange={(e) => setNewIntIssuer(e.target.value)}>
              <option value="">选择签发 CA…</option>
              {cas.map((c) => <option key={c.id} value={c.id}>{c.id} · {c.label}</option>)}
            </select>
            <select value={crossSubject} onChange={(e) => setCrossSubject(e.target.value)}>
              <option value="">普通签发（不交叉）</option>
              {intermediates.map((c) => <option key={c.id} value={c.id}>交叉签署已有中间证书：{c.id}</option>)}
            </select>
            <button type="submit">签发</button>
          </form>

          <form onSubmit={(e) => { e.preventDefault(); run(() => api.addLeaf(newLeafCN, newLeafIssuer, [newLeafCN])).then(() => setNewLeafCN("")); }}>
            <h3>签发终端证书</h3>
            <input placeholder="DNS / CN" value={newLeafCN} onChange={(e) => setNewLeafCN(e.target.value)} />
            <select value={newLeafIssuer} onChange={(e) => setNewLeafIssuer(e.target.value)}>
              <option value="">选择签发中间 CA…</option>
              {intermediates.filter((c) => c.kind === "intermediate").map((c) => <option key={c.id} value={c.id}>{c.id} · {c.label}</option>)}
            </select>
            <button type="submit">签发</button>
          </form>
        </div>
      </section>

      <section className="panel">
        <h2>2. 证书清单与生命周期操作</h2>
        <table>
          <thead>
            <tr><th>ID</th><th>类型</th><th>主题</th><th>签发者</th><th>有效期至</th><th>状态</th><th>操作</th></tr>
          </thead>
          <tbody>
            {certs.map((c) => (
              <tr key={c.id} className={selected === c.id ? "sel" : ""}>
                <td>{c.id}</td>
                <td><span className={`badge k-${c.kind}`}>{kindLabel[c.kind]}</span></td>
                <td>{c.label}</td>
                <td>{c.issuerId}</td>
                <td>{new Date(c.notAfter).toLocaleDateString()}</td>
                <td>
                  {c.revoked && <span className="tag bad">已撤销</span>}
                  {c.supersededBy && <span className="tag warn">已轮换 → {c.supersededBy}</span>}
                  {c.crlBlocked && <span className="tag bad">CRL 缺失</span>}
                  {c.kind === "root" && <span className={`tag ${trustedRoots.includes(c.id) ? "ok" : "bad"}`}>{trustedRoots.includes(c.id) ? "受信任" : "不信任"}</span>}
                </td>
                <td className="ops">
                  {c.kind === "leaf" && <button onClick={() => setSelected(c.id)}>选择验证</button>}
                  {c.kind === "leaf" && <button onClick={() => run(() => api.rotate(c.id))}>轮换</button>}
                  {c.kind === "root" && <button onClick={() => run(() => api.trust(c.id, !trustedRoots.includes(c.id)))}>{trustedRoots.includes(c.id) ? "取消信任" : "设为信任"}</button>}
                  {c.kind !== "root" && <button onClick={() => run(() => api.revoke(c.id))}>撤销</button>}
                  {(c.kind === "intermediate" || c.kind === "root") && (
                    <button onClick={() => run(() => api.setCRL(c.id, !c.crlBlocked))}>{c.crlBlocked ? "恢复发布 CRL" : "模拟 CRL 缺失"}</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="panel">
        <h2>3. 验证</h2>
        <div className="verifybar">
          <select value={selected} onChange={(e) => setSelected(e.target.value)}>
            <option value="">选择终端证书…</option>
            {leaves.map((c) => <option key={c.id} value={c.id}>{c.id} · {c.label}</option>)}
          </select>
          <select value={purpose} onChange={(e) => setPurpose(e.target.value)}>
            <option value="serverAuth">serverAuth 服务器身份</option>
            <option value="clientAuth">clientAuth 客户端身份</option>
          </select>
          <input className="note" placeholder="本次验证备注（如：根迁移后复检）" value={note} onChange={(e) => setNote(e.target.value)} />
          <button className="primary" onClick={doVerify} disabled={!selected}>重新验证（追加新证据）</button>
        </div>
        {lastVerify && <VerifyCard ev={lastVerify} byId={byId} />}
      </section>

      <section className="panel">
        <h2>4. 历史验证证据（{evidence.length} 条，只追加）</h2>
        <div className="evidence">
          {evidence.slice().reverse().map((ev) => (
            <details key={ev.id} className="ev">
              <summary>
                <span className={`dot ${ev.valid ? "ok" : "bad"}`} />
                <b>{ev.leafId}</b> · {ev.purpose} · {new Date(ev.createdAt).toLocaleString()}
                {ev.note ? ` · ${ev.note}` : ""}
              </summary>
              <VerifyCard ev={ev} byId={byId} compact />
            </details>
          ))}
        </div>
      </section>
    </div>
  );
}

function VerifyCard({ ev, compact }: { ev: Evidence; byId: Map<string, CertView>; compact?: boolean }) {
  const r = ev.result;
  return (
    <div className={`result ${ev.valid ? "valid" : "invalid"}`}>
      <div className="result-head">
        <span className={`big ${ev.valid ? "ok" : "bad"}`}>{ev.valid ? "验证通过 ✓" : "验证失败 ✗"}</span>
        {!compact && ev.valid && r.selectedPath && <span>采用路径：<b>{r.selectedPath.join(" → ")}</b></span>}
        {!ev.valid && r.reason && <span className="reason">{r.reason}</span>}
      </div>
      <div className="chains">
        {r.chains.map((ch, i) => <ChainView key={i} index={i} ch={ch} selected={compact ? undefined : r.selectedPath} />)}
      </div>
    </div>
  );
}

function ChainView({ index, ch, selected }: { index: number; ch: ChainReport; selected?: string[] }) {
  const ids = ch.path.map((p) => p.id);
  const isSelected = selected && selected.length === ids.length && selected.every((id, i) => id === ids[i]);
  return (
    <details open={isSelected || !ch.valid} className={`chain ${ch.valid ? "ok" : "bad"} ${isSelected ? "chosen" : ""}`}>
      <summary>
        候选路径 {index + 1}：{ch.path.slice().reverse().map((p) => p.label).join(" → ")}
        <span className={`tag ${ch.valid ? "ok" : "bad"}`}>{ch.valid ? (isSelected ? "实际采用" : "有效") : "无效"}</span>
      </summary>
      <table className="pathtable">
        <thead><tr><th>节点</th><th>签名</th><th>期限</th><th>撤销</th><th>信任</th></tr></thead>
        <tbody>
          {ch.path.map((s) => (
            <tr key={s.id}>
              <td>{s.label} <small>({s.kind})</small></td>
              <td>{s.signatureValid ? "✓" : "✗"}</td>
              <td className={s.expired ? "badtext" : ""}>{new Date(s.notAfter).toLocaleDateString()}{s.expired ? " 已过期" : ""}</td>
              <td>{s.revoked ? "已撤销" : "—"}</td>
              <td>{s.kind === "root" ? (s.trusted ? "受信任" : "不受信任") : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <ul className="checks">
        {ch.checks.map((c, i) => (
          <li key={i} className={c.pass ? "ok" : "bad"}><b>{c.name}</b>：{c.detail}</li>
        ))}
      </ul>
      {ch.reason && <div className="reason">失败原因：{ch.reason}</div>}
    </details>
  );
}
