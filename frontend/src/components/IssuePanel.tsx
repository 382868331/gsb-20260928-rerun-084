import { useState } from "react";
import { api } from "../api";
import type { LabState } from "../types";

interface Props {
  state: LabState;
  refresh: () => void;
}

export function IssuePanel({ state, refresh }: Props) {
  const [kind, setKind] = useState<"root" | "intermediate" | "leaf">("leaf");
  const [name, setName] = useState("");
  const [issuerId, setIssuerId] = useState("");
  const [ekus, setEkus] = useState<string[]>(["serverAuth"]);
  const [ttlDays, setTtlDays] = useState(90);
  const [description, setDescription] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const issuers = state.order
    .map((id) => state.entities[id])
    .filter((e) => (kind === "intermediate" ? e.kind === "root" : e.kind !== "leaf"));

  async function submit(rotate?: boolean) {
    setBusy(true);
    setError("");
    try {
      await api.issue({
        name: name.trim(),
        kind,
        issuerId: kind === "root" ? undefined : issuerId,
        ekus: kind === "leaf" ? ekus : undefined,
        ttlDays,
        description: description.trim() || undefined,
      });
      if (rotate) setName("");
      refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function toggleEku(v: string) {
    setEkus((prev) => (prev.includes(v) ? prev.filter((x) => x !== v) : [...prev, v]));
  }

  const caCerts = Object.values(state.certs).filter((c) => c.isCA && !c.crossSignedBy && c.subject);

  return (
    <div>
      <h2>签发 / 轮换</h2>
      <p className="muted">私钥仅生成并保存在本地实验区，页面与日志不接触任何密钥。</p>

      <label>类型</label>
      <div className="row">
        {(["root", "intermediate", "leaf"] as const).map((k) => (
          <button key={k} className={kind === k ? "primary" : ""} onClick={() => setKind(k)}>
            {k === "root" ? "新根 CA" : k === "intermediate" ? "中间 CA" : "终端证书"}
          </button>
        ))}
      </div>

      <label>主体名称（对已有主体再次签发即产生新版本 = 轮换）</label>
      <input value={name} onChange={(e) => setName(e.target.value)} placeholder="例如 api.lab.test" list="entity-names" />
      <datalist id="entity-names">
        {state.order.map((id) => (
          <option key={id} value={state.entities[id].name} />
        ))}
      </datalist>

      {kind !== "root" && (
        <>
          <label>签发者（主体）</label>
          <select value={issuerId} onChange={(e) => setIssuerId(e.target.value)}>
            <option value="">— 选择签发者 —</option>
            {issuers.map((e) => (
              <option key={e.id} value={e.id}>
                {e.name}（最新版本）
              </option>
            ))}
          </select>
        </>
      )}

      {kind === "leaf" && (
        <>
          <label>证书用途（ExtKeyUsage）</label>
          <div className="row">
            {["serverAuth", "clientAuth"].map((v) => (
              <button key={v} className={ekus.includes(v) ? "primary" : ""} onClick={() => toggleEku(v)}>
                {v === "serverAuth" ? "服务器认证" : "客户端认证"}
              </button>
            ))}
          </div>
        </>
      )}

      <label>有效期（天）</label>
      <input type="number" min={1} value={ttlDays} onChange={(e) => setTtlDays(Number(e.target.value))} />

      <label>备注</label>
      <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="可选" />

      <div className="row" style={{ marginTop: 12 }}>
        <button className="primary" disabled={busy || !name.trim()} onClick={() => submit()}>
          签发新版本
        </button>
      </div>
      {error && <div className="error">{error}</div>}

      <h2 style={{ marginTop: 22 }}>交叉签发</h2>
      <p className="muted">用另一根 CA 对某个中间证书的同一公钥重新签名，换根期间形成可选验证路径。</p>
      <CrossSign state={state} refresh={refresh} caCerts={caCerts.map((c) => c.id)} />
    </div>
  )
}

function CrossSign({
  state,
  refresh,
  caCerts,
}: {
  state: LabState;
  refresh: () => void;
  caCerts: string[];
}) {
  const [target, setTarget] = useState("");
  const [signer, setSigner] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const intermediates = caCerts.map((id) => state.certs[id]).filter((c) => c.issuerId);
  const roots = state.roots;

  async function run() {
    setBusy(true);
    setError("");
    try {
      await api.crossSign(target, signer);
      setTarget("");
      refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <label>目标中间证书版本</label>
      <select value={target} onChange={(e) => setTarget(e.target.value)}>
        <option value="">— 选择 —</option>
        {intermediates.map((c) => (
          <option key={c.id} value={c.id}>
            {c.subject} v{c.version}（{c.id}）
          </option>
        ))}
      </select>
      <label>签名根（新信任起点）</label>
      <select value={signer} onChange={(e) => setSigner(e.target.value)}>
        <option value="">— 选择根主体 —</option>
        {roots.map((r) => (
          <option key={r.certId} value={r.entityId}>
            {r.subject}
          </option>
        ))}
      </select>
      <div className="row" style={{ marginTop: 10 }}>
        <button disabled={busy || !target || !signer} onClick={run}>
          生成交叉证书
        </button>
      </div>
      {error && <div className="error">{error}</div>}
    </div>
  )
}
