import { useMemo, useState } from "react";
import { api } from "../api";
import type { LabState, VerifyResult } from "../types";

interface Props {
  state: LabState;
  selectedLeaf: string | null;
  setSelectedLeaf: (id: string | null) => void;
  notify: (msg: string, bad?: boolean) => void;
  refresh: () => Promise<void>;
}

export function VerifyPanel({ state, selectedLeaf, setSelectedLeaf, notify, refresh }: Props) {
  const [purpose, setPurpose] = useState("serverAuth");
  const [trust, setTrust] = useState<Record<string, boolean>>({});
  const [atDays, setAtDays] = useState(0);
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [busy, setBusy] = useState(false);

  const leaves = useMemo(
    () =>
      state.order
        .map((id) => state.entities[id])
        .filter((e) => e.kind === "leaf")
        .map((e) => state.certs[e.versions[e.versions.length - 1]])
        .filter((c) => c && !c.crossSignedBy),
    [state]
  );

  const leaf = selectedLeaf ?? leaves[0]?.id ?? null;

  function toggleTrust(certId: string) {
    setTrust((t) => ({ ...t, [certId]: !t[certId] }));
  }

  async function run() {
    if (!leaf) return;
    setBusy(true);
    try {
      const res = await api.verify({
        leafCertId: leaf,
        purpose,
        trustRoots: state.roots.filter((r) => trust[r.certId]).map((r) => r.certId),
        atDays,
      });
      setResult(res);
    } catch (e) {
      notify((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }

  async function revoke() {
    if (!leaf) return;
    const reason = window.prompt("撤销原因（例如 keyCompromise）", "keyCompromise");
    if (reason === null) return;
    try {
      await api.revoke(leaf, reason);
      await refresh();
      notify("已撤销并立即落盘，随后的验证实时读取状态，不走缓存。");
      // Re-verify automatically to prove cache cannot keep it alive.
      const res = await api.verify({
        leafCertId: leaf,
        purpose,
        trustRoots: state.roots.filter((r) => trust[r.certId]).map((r) => r.certId),
        atDays,
      });
      setResult(res);
    } catch (e) {
      notify((e as Error).message, true);
    }
  }

  const current = leaf ? state.certs[leaf] : null;

  return (
    <div>
      <h2>验证</h2>
      <div className="grid2">
        <div>
          <label>终端证书</label>
          <select value={leaf ?? ""} onChange={(e) => { setSelectedLeaf(e.target.value); setResult(null); }}>
            {leaves.map((c) => (
              <option key={c.id} value={c.id}>
                {c.subject} v{c.version}
              </option>
            ))}
          </select>

          <label>用途</label>
          <div className="row">
            {["serverAuth", "clientAuth"].map((p) => (
              <button key={p} className={purpose === p ? "primary" : ""} onClick={() => setPurpose(p)}>
                {p === "serverAuth" ? "服务器认证" : "客户端认证"}
              </button>
            ))}
          </div>

          <label>评估时间（相对今天的天数，可用于演示过期）</label>
          <input type="number" value={atDays} onChange={(e) => setAtDays(Number(e.target.value))} />

          <label>信任起点（勾选哪些根进入信任库）</label>
          <div className="trust-list">
            {state.roots.map((r) => (
              <label key={r.certId}>
                <input type="checkbox" checked={!!trust[r.certId]} onChange={() => toggleTrust(r.certId)} />
                {r.subject} v{r.version}
              </label>
            ))}
            {state.roots.length === 0 && <span className="muted">无根证书</span>}
          </div>

          <div className="row" style={{ marginTop: 12 }}>
            <button className="primary" disabled={busy || !leaf} onClick={run}>验证路径</button>
            <button className="danger" disabled={!leaf || !!current?.revoked} onClick={revoke}>撤销该版本</button>
          </div>
          {current?.revoked && <p className="bad-text" style={{ fontSize: 12 }}>该版本已撤销：{current.revokeReason}</p>}
        </div>

        <div>
          {result && (
            <div className={result.valid ? "verdict pass" : "verdict fail"}>
              {result.valid
                ? `验证通过（${result.chosenPath?.label ?? "有效链"}）`
                : "验证失败：没有任何候选链同时满足用途、有效期与信任起点"}
            </div>
          )}
          {result?.paths.map((p, i) => <PathCard key={i} path={p} state={state} />)}
          {!result && <p className="muted">选择用途与信任根后运行验证。换根期间会同时列出旧链与新链两条候选路径。</p>}
        </div>
      </div>
    </div>
  );
}

function PathCard({ path, state }: { path: import("../types").PathResult; state: LabState }) {
  return (
    <div className={`path ${path.valid ? "valid" : "invalid"}`}>
      <div className="row">
        <strong>{path.label}</strong>
        <span className={path.valid ? "ok-text" : "bad-text"}>{path.valid ? "✓ 通过" : "✗ 不通过"}</span>
        {!path.trusted && <span className="bad-text">根不受信</span>}
      </div>
      <div className="flow">
        {path.nodes.map((n, i) => (
          <span key={n.certId} className="row" style={{ gap: 6 }}>
            <span className={`node ${n.revoked || n.expired ? "bad" : ""} ${n.cross ? "cross" : ""}`} title={`${n.notBefore} ~ ${n.notAfter}`}>
              {n.subject} v{n.version}
              {n.cross ? "（交叉）" : ""}
              {n.revoked ? " 已撤销" : ""}
              {n.expired ? " 过期/未生效" : ""}
            </span>
            {i < path.nodes.length - 1 && <span className="arrow">→</span>}
          </span>
        ))}
      </div>
      {path.reasons.length > 0 && (
        <ul className="reasons">
          {path.reasons.map((r, i) => <li key={i}>{r}</li>)}
        </ul>
      )}
    </div>
  );
}
