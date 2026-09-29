import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./api";
import type { LabState } from "./types";
import { IssuePanel } from "./components/IssuePanel";
import { VerifyPanel } from "./components/VerifyPanel";
import { ChainGraph } from "./components/ChainGraph";

type Tab = "issue" | "verify";

export function App() {
  const [state, setState] = useState<LabState | null>(null);
  const [tab, setTab] = useState<Tab>("issue");
  const [leaf, setLeaf] = useState<string | null>(null);
  const [highlight, setHighlight] = useState<string[]>([]);
  const [toast, setToast] = useState<{ msg: string; bad: boolean } | null>(null);

  const refresh = useCallback(async () => {
    const s = await api.state();
    setState(s);
  }, []);

  useEffect(() => {
    refresh().catch((e) => setToast({ msg: (e as Error).message, bad: true }));
  }, [refresh]);

  const notify = useCallback((msg: string, bad = false) => {
    setToast({ msg, bad });
    window.setTimeout(() => setToast(null), 4000);
  }, []);

  async function reset() {
    if (!window.confirm("重建首轮实验链？当前实验区状态与自生成密钥将被清空。")) return;
    await api.reset();
    await api.bootstrap();
    await refresh();
    setHighlight([]);
    notify("已重置为首轮实验链。");
  }

  if (!state) return <div style={{ padding: 24 }}>加载实验状态…</div>;

  return (
    <div>
      <div className="topbar">
        <div>
          <h1>证书生命周期实验平台</h1>
          <div className="sub">虚构签发关系 · 换根 / 交叉签发 / 撤销 / 路径验证 · 私钥仅存本地实验区</div>
        </div>
        <div className="spacer" />
        <button onClick={reset}>重置实验</button>
      </div>

      <div className="layout">
        <div className="panel">
          <h2>实体与版本（点击证书查看）</h2>
          <EntityList state={state} onShowPath={setHighlight} />
        </div>

        <div className="panel">
          <div className="tabs">
            <button className={tab === "issue" ? "active" : ""} onClick={() => setTab("issue")}>签发 / 轮换 / 交叉签发</button>
            <button className={tab === "verify" ? "active" : ""} onClick={() => setTab("verify")}>验证</button>
          </div>
          {tab === "issue" ? (
            <IssuePanel state={state} refresh={refresh} />
          ) : (
            <VerifyPanel state={state} selectedLeaf={leaf} setSelectedLeaf={setLeaf} notify={notify} refresh={refresh} />
          )}

          <h2 style={{ marginTop: 22 }}>签发关系图（虚线 = 交叉签发路径）</h2>
          <ChainGraph state={state} highlightPath={highlight} />
        </div>
      </div>

      {toast && (
        <div
          style={{
            position: "fixed", bottom: 18, left: "50%", transform: "translateX(-50%)",
            background: toast.bad ? "#5a2530" : "#1e3a30", border: `1px solid ${toast.bad ? "#ff6b6b" : "#38d39f"}`,
            padding: "10px 16px", borderRadius: 10, fontSize: 13,
          }}
        >
          {toast.msg}
        </div>
      )}
    </div>
  );
}

function EntityList({ state, onShowPath }: { state: LabState; onShowPath: (ids: string[]) => void }) {
  const entities = state.order.map((id) => state.entities[id]);
  const pathOf = useCallback(
    (certId: string) => {
      const ids: string[] = [];
      let cur: string | undefined = certId;
      const guard = new Set<string>();
      while (cur && !guard.has(cur)) {
        guard.add(cur);
        ids.push(cur);
        cur = state.certs[cur]?.issuerId;
      }
      onShowPath(ids);
    },
    [state, onShowPath]
  );

  return (
    <div>
      {entities.map((e) => (
        <div key={e.id} className="entity">
          <div className="name">
            <span className={`kind-${e.kind}`}>{e.kind === "root" ? "根" : e.kind === "intermediate" ? "中间" : "终端"}</span>
            {"  "}{e.name}
          </div>
          <div className="desc">{e.description}</div>
          <div className="chips">
            {e.versions.map((cid) => {
              const c = state.certs[cid];
              return (
                <button
                  key={cid}
                  className={`chip ${c.revoked ? "revoked" : ""} ${c.crossSignedBy ? "cross" : ""}`}
                  title={`${c.notBefore} ~ ${c.notAfter}${c.revoked ? "\n已撤销: " + c.revokeReason : ""}`}
                  onClick={() => pathOf(cid)}
                >
                  v{c.version}
                  {c.crossSignedBy ? " ⤨" : ""}
                  {c.revoked ? " ✖" : ""}
                  {!c.revoked && new Date(c.notAfter).getTime() < Date.now() ? " ⏰" : ""}
                </button>
              );
            })}
          </div>
        </div>
      ))}
      {entities.length === 0 && <span className="muted">尚无实体。</span>}
    </div>
  );
}
