const $ = (s, el = document) => el.querySelector(s);

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error((data && data.error) || res.statusText);
  return data;
}

function toast(msg, ok = true) {
  const box = $("#toast");
  const el = document.createElement("div");
  el.className = `toast-item ${ok ? "ok" : "err"}`;
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

function formJSON(form) {
  const fd = new FormData(form);
  const obj = {};
  for (const [k, v] of fd.entries()) obj[k] = String(v).trim();
  return obj;
}

function fmtDate(t) {
  if (!t) return "-";
  return new Date(t).toLocaleString("zh-CN", { hour12: false });
}

async function refresh() {
  const state = await api("/api/state");
  $("#rulesVersion").textContent = state.rulesVersion;
  $("#clock").textContent = fmtDate(state.now);
  renderRows(state);
  renderVerifySelect(state);
  const history = await api("/api/history");
  renderHistory(history);
  const knowledge = await api("/api/knowledge");
  renderKnowledge(knowledge);
}

function renderKnowledge(k) {
  const box = $("#knowledge");
  const trust = (k.trustEvents || []).map(e =>
    `<li><b>${e.rootId}</b> ${e.trusted ? "受信" : "停止受信"} · 生效 ${fmtDate(e.effectiveFrom)} · 获知 ${fmtDate(e.acquiredAt)}${e.note ? ` · <span class="muted">${e.note}</span>` : ""}</li>`);
  const rev = (k.revocationEvents || []).map(e =>
    `<li><b>${e.certId}</b> 撤销生效 ${fmtDate(e.revokedAt)} · 获知 ${fmtDate(e.acquiredAt)}${e.note ? ` · <span class="muted">${e.note}</span>` : ""}</li>`);
  box.innerHTML = `
    <div class="card"><h3>根信任材料</h3><ul>${trust.join("") || "<li class='muted'>（无）</li>"}</ul></div>
    <div class="card"><h3>撤销材料</h3><ul>${rev.join("") || "<li class='muted'>（无）</li>"}</ul></div>`;
}

function renderRows(state) {
  const rows = $("#certRows");
  rows.innerHTML = "";
  for (const c of state.certs) {
    const tr = document.createElement("tr");
    const trusted = (state.trustedRoots || []).includes(c.id);
    const purposes = c.kind === "leaf" ? ((c.ekus || []).join(", ") || "-") : "CA";
    const status = [];
    if (c.kind === "root") status.push(trusted ? `<span class="ok-text">受信任</span>` : `<span class="bad-text">不信任</span>`);
    const now = new Date(state.now);
    if (now < new Date(c.notBefore) || now > new Date(c.notAfter)) status.push(`<span class="bad-text">已过期/未生效</span>`);
    if (c.revoked) status.push(`<span class="bad-text">已撤销 ${fmtDate(c.revokedAt)}</span>`);
    if (c.kind !== "leaf" && !c.crlPublished) status.push(`<span class="warn-text">撤销资料缺失</span>`);
    if (c.kind !== "leaf" && c.crlDelayMin > 0) status.push(`<span class="warn-text">撤销资料迟到 ${c.crlDelayMin} 分钟</span>`);

    const actions = [`<button class="small danger" data-act="revoke" data-id="${c.id}">撤销</button>`];
    actions.push(`<button class="small ghost" data-act="revokeTimed" data-id="${c.id}">补录撤销材料</button>`);
    if (c.kind === "root") {
      actions.push(trusted
        ? `<button class="small warn" data-act="distrust" data-id="${c.id}">取消信任</button>`
        : `<button class="small" data-act="trust" data-id="${c.id}">设为信任</button>`);
      actions.push(`<button class="small ghost" data-act="trustTimed" data-id="${c.id}">定时信任变更</button>`);
    }
    if (c.kind !== "leaf") {
      actions.push(c.crlPublished
        ? `<button class="small warn" data-act="crlOff" data-id="${c.id}">停止发布 CRL</button>`
        : `<button class="small" data-act="crlOn" data-id="${c.id}">恢复发布 CRL</button>`);
      actions.push(`<a class="small" href="/api/crl/${c.id}" target="_blank"><button class="small ghost">下载 CRL</button></a>`);
      actions.push(`<button class="small ghost" data-act="crlDelay" data-id="${c.id}">迟到 CRL</button>`);
    }

    tr.innerHTML = `
      <td><b>${c.id}</b></td>
      <td><span class="tag ${c.kind}">${c.kind}</span><br><small class="muted">${c.subject}</small></td>
      <td>${purposes}</td>
      <td><small>${fmtDate(c.notBefore)}<br>→ ${fmtDate(c.notAfter)}</small></td>
      <td>${status.join("<br>") || `<span class="ok-text">正常</span>`}</td>
      <td><div class="actions">${actions.join("")}</div></td>`;
    rows.appendChild(tr);
  }
}

function renderVerifySelect(state) {
  const sel = $("#verifyLeaf");
  const current = sel.value;
  sel.innerHTML = "";
  for (const c of state.certs.filter(c => c.kind === "leaf")) {
    const opt = document.createElement("option");
    opt.value = c.id;
    opt.textContent = `${c.id} (${c.ekus.join(",")})`;
    sel.appendChild(opt);
  }
  if (current) sel.value = current;
}

function pathArrow(step, isFirst) {
  return `<div class="step">${isFirst ? "" : "<span class=\"arrow\">↑ 由</span> "}` +
    `<b>${step.id}</b> <span class="tag ${step.kind}">${step.kind}</span> ${step.label}` +
    `<br><small>${step.subject} · 到期 ${fmtDate(step.notAfter)}` +
    (step.trusted ? " · 受信任锚点" : "") +
    (step.expired ? " · <span class=\"bad-text\">期限不满足</span>" : "") +
    (step.revoked ? " · <span class=\"bad-text\">已撤销</span>" : "") +
    (!step.crlPublished ? " · <span class=\"warn-text\">撤销资料缺失，撤销状态无法确定</span>" : "") +
    `</small></div>`;
}

function renderResult(res, target) {
  const statusText = { valid: "✓ 验证通过", undetermined: "? 尚缺依据（无法确定）", disqualified: "✗ 验证失败" };
  const verdictClass = res.status === "valid" ? "ok" : res.status === "undetermined" ? "warn" : "bad";
  const pol = res.policy || {};
  const polBits = [];
  if ((pol.allowedRoots || []).length) polBits.push("允许的根：" + pol.allowedRoots.join(", "));
  if ((pol.preferredRoots || []).length) polBits.push("根优先：" + pol.preferredRoots.join(" > "));
  if (pol.requireCrl) polBits.push("必须具备完整撤销资料");
  const selected = (res.selectedPath || []).join(" → ");
  target.innerHTML = `
    <div class="verdict ${verdictClass}">` +
      `${statusText[res.status] || (res.valid ? statusText.valid : statusText.disqualified)} · 证书 ${res.leafId} · 用途 ${res.purpose} · 证据 #${res.evidenceId} · 规则版本 ${res.rulesVersion}</div>
    <div class="muted">${res.valid ? "实际采用路径：" + selected : "结论依据：" + (res.reason || "-")}</div>
    <div class="muted">事件时刻 ${fmtDate(res.eventTime)} · 获知截止 ${fmtDate(res.knowledgeCutoff)} · 记录时间 ${fmtDate(res.checkedAt)}</div>
    <div class="muted">受信任根：${(res.trustedRoots || []).join(", ") || "（无）"}</div>
    ${polBits.length ? `<div class="muted">本次实验策略：${polBits.join(" · ")}</div>` : ""}
    ${(res.chains || []).map(ch => `
      <div class="chain ${ch.status === "valid" ? "ok" : ch.status === "undetermined" ? "warn" : "bad"}">
        <b>${chainLabel(ch, selected)}</b>
        ${ch.reason ? ` <span class="${ch.status === "undetermined" ? "warn-text" : "bad-text"}">— ${ch.reason}</span>` : ` <span class="ok-text">— 签名、期限、用途、锚点与撤销资料均满足</span>`}
        ${ch.path.map((s, i) => pathArrow(s, i === 0)).join("")}
        ${(ch.basis || []).length ? `<div class="basis"><small>采用材料（生效 / 获知）：${ch.basis.map(b =>
          `<br>· [${b.kind}] ${b.id}：${b.detail}${b.effective ? ` · 生效 ${fmtDate(b.effective)}` : ""} · 获知 ${fmtDate(b.acquiredAt)}`).join("")}</small></div>` : ""}
      </div>`).join("")}`;
}

function chainLabel(ch, selected) {
  const ids = (ch.path || []).map(s => s.id).join(" → ");
  if (ch.status === "valid") return ids === selected ? "采用路径" : "候选有效路径（未采用）";
  if (ch.status === "undetermined") return "尚缺依据（无法确定）";
  return "明确不合格";
}

function reprChain(res) {
  const chains = res.chains || [];
  return chains.find(c => c.valid) || chains[0] || null;
}

function stepMap(res) {
  const m = new Map();
  const ch = reprChain(res);
  if (ch) for (const s of ch.path || []) m.set(s.id, s);
  return m;
}

function fmtStepState(s) {
  const parts = [];
  if (s.kind === "root") parts.push(s.trusted ? "受信任锚点" : "非信任锚点");
  parts.push(s.expired ? "期限不满足" : "期限内");
  parts.push(s.revoked ? "已撤销" : "未撤销");
  if (s.kind !== "leaf") parts.push(s.crlPublished ? "撤销资料正常" : "撤销资料缺失（无法确定撤销状态）");
  return parts.join("，");
}

function renderCompare(prev, cur) {
  const lines = [];
  if (prev.rulesVersion !== cur.rulesVersion) lines.push(`规则版本 v${prev.rulesVersion} → v${cur.rulesVersion}`);
  const sources = [];
  if (prev.eventTime !== cur.eventTime) sources.push(`事件时刻移动（${fmtDate(prev.eventTime)} ⇒ ${fmtDate(cur.eventTime)}）`);
  if (prev.knowledgeCutoff !== cur.knowledgeCutoff) sources.push(`新增知识（获知截止 ${fmtDate(prev.knowledgeCutoff)} ⇒ ${fmtDate(cur.knowledgeCutoff)}）`);
  const label = r => r.status === "valid" ? "✓ 通过" : r.status === "undetermined" ? "? 尚缺依据" : "✗ 失败";
  if (label(prev) !== label(cur)) lines.push(`结论：${label(prev)} → ${label(cur)}`);
  const polStr = p => {
    const bits = [];
    if (((p || {}).allowedRoots || []).length) bits.push("允许根[" + p.allowedRoots.join(",") + "]");
    if (((p || {}).preferredRoots || []).length) bits.push("优先[" + p.preferredRoots.join(">") + "]");
    if ((p || {}).requireCrl) bits.push("必须完整撤销资料");
    return bits.join(" ") || "（默认策略）";
  };
  if (polStr(prev.policy) !== polStr(cur.policy)) {
    lines.push(`实验策略：${polStr(prev.policy)} ⇒ ${polStr(cur.policy)}`);
    sources.push("研究者改变了信任条件");
  }
  if (sources.length) lines.unshift(`结论变化来源：${sources.join("；")}`);
  const pPath = (prev.selectedPath || []).join(" → ") || "（无有效路径）";
  const cPath = (cur.selectedPath || []).join(" → ") || "（无有效路径）";
  if (pPath !== cPath) lines.push(`采用路径：${pPath} ⇒ ${cPath}`);
  const pRoots = new Set(prev.trustedRoots || []);
  const cRoots = new Set(cur.trustedRoots || []);
  for (const r of cRoots) if (!pRoots.has(r)) lines.push(`信任根新增：${r}`);
  for (const r of pRoots) if (!cRoots.has(r)) lines.push(`信任根移除：${r}`);
  const pm = stepMap(prev);
  const cm = stepMap(cur);
  for (const [id, cs] of cm) {
    const ps = pm.get(id);
    if (!ps) { lines.push(`${id}：新出现在采用路径（${fmtStepState(cs)}）`); continue; }
    const before = fmtStepState(ps);
    const after = fmtStepState(cs);
    if (before !== after) lines.push(`${id}：${before} ⇒ ${after}`);
  }
  for (const id of pm.keys()) if (!cm.has(id)) lines.push(`${id}：不再出现在采用路径`);
  if (!lines.length) lines.push("与上一条同证书证据相比，规则与路径状态无变化。");
  return `<div class="compare"><b>与证据 #${prev.evidenceId}（规则 v${prev.rulesVersion} · ${fmtDate(prev.checkedAt)}）的路径比较</b><ul>${lines.map(l => `<li>${l}</li>`).join("")}</ul></div>`;
}

function renderHistory(history) {
  const box = $("#history");
  box.innerHTML = history.length ? "" : `<p class="muted">暂无验证证据。</p>`;
  history.forEach((res, i) => {
    const prev = history.slice(i + 1).find(h => h.leafId === res.leafId && h.purpose === res.purpose);
    const details = document.createElement("details");
    details.className = "evidence";
    details.open = i === 0;
    details.innerHTML = `
      <summary>
        <span class="${res.status === "valid" ? "ok-text" : res.status === "undetermined" ? "warn-text" : "bad-text"}"><b>${res.status === "valid" ? "✓ 通过" : res.status === "undetermined" ? "? 尚缺依据" : "✗ 失败"}</b></span>
        证据 #${res.evidenceId} · 规则 v${res.rulesVersion} · ${res.leafId} · ${res.purpose} · ${fmtDate(res.checkedAt)}
        · 事件 ${fmtDate(res.eventTime)} · 截止 ${fmtDate(res.knowledgeCutoff)}
        · <a href="/api/history/${res.evidenceId}/export" target="_blank">导出</a>
        ${res.valid ? ` · 路径 ${(res.selectedPath || []).join(" → ")}` : ` · ${res.reason}`}
      </summary>
      ${prev ? renderCompare(prev, res) : ""}
      <div id="ev-${res.evidenceId}"></div>`;
    box.appendChild(details);
    renderResult(res, details.querySelector(`#ev-${res.evidenceId}`));
  });
}

function bindForms() {
  $("#rootForm").addEventListener("submit", async e => {
    e.preventDefault();
    const v = formJSON(e.target);
    try {
      await api("/api/roots", { method: "POST", body: JSON.stringify({ id: v.id, cn: v.cn, years: Number(v.years) || 0 }) });
      toast("根证书已签发并信任"); e.target.reset(); refresh();
    } catch (err) { toast(err.message, false); }
  });

  $("#intermediateForm").addEventListener("submit", async e => {
    e.preventDefault();
    const v = formJSON(e.target);
    try {
      await api("/api/intermediates", { method: "POST", body: JSON.stringify({
        id: v.id, cn: v.cn, issuerId: v.issuerId, crossSubjectId: v.crossSubjectId || "", years: Number(v.years) || 0,
      }) });
      toast(v.crossSubjectId ? "交叉签发证书已创建" : "中间证书已签发"); e.target.reset(); refresh();
    } catch (err) { toast(err.message, false); }
  });

  $("#leafForm").addEventListener("submit", async e => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const ekus = [];
    if (fd.get("server")) ekus.push("serverAuth");
    if (fd.get("client")) ekus.push("clientAuth");
    const dns = (fd.get("dns") || "").split(",").map(s => s.trim()).filter(Boolean);
    try {
      await api("/api/leaves", { method: "POST", body: JSON.stringify({
        id: fd.get("id")?.trim(), cn: fd.get("cn")?.trim(), issuerId: fd.get("issuerId")?.trim(),
        ekus, dnsNames: dns, days: Number(fd.get("days")) || 0,
      }) });
      toast("终端证书已签发"); e.target.reset(); refresh();
    } catch (err) { toast(err.message, false); }
  });

  $("#rotateForm").addEventListener("submit", async e => {
    e.preventDefault();
    const v = formJSON(e.target);
    try {
      await api("/api/leaves/rotate", { method: "POST", body: JSON.stringify({
        newId: v.newId, leafId: v.leafId, newIssuerId: v.newIssuerId, days: Number(v.days) || 0,
      }) });
      toast("已用新密钥完成轮换，旧证书保留"); e.target.reset(); refresh();
    } catch (err) { toast(err.message, false); }
  });

  $("#verifyForm").addEventListener("submit", async e => {
    e.preventDefault();
    const leafId = $("#verifyLeaf").value;
    const purpose = e.target.elements.purpose.value;
    const toRFC = v => v ? new Date(v).toISOString() : null;
    const eventTime = toRFC(e.target.elements.eventTime.value);
    const knowledgeCutoff = toRFC(e.target.elements.knowledgeCutoff.value);
    const pf = $("#policyForm");
    const csv = s => s.split(",").map(x => x.trim()).filter(Boolean);
    const policy = {
      allowedRoots: csv(pf.elements.allowedRoots.value || ""),
      preferredRoots: csv(pf.elements.preferredRoots.value || ""),
      requireCrl: pf.elements.requireCrl.checked,
    };
    try {
      const res = await api("/api/verify", { method: "POST", body: JSON.stringify({ leafId, purpose, policy, eventTime, knowledgeCutoff }) });
      renderResult(res, $("#verifyResult"));
      toast(res.valid ? `验证通过，采用路径：${res.selectedPath.join(" → ")}`
        : res.status === "undetermined" ? "尚缺依据：存在无法确定的候选路径" : "验证失败：无有效完整链");
      refresh();
    } catch (err) { toast(err.message, false); }
  });

  $("#certRows").addEventListener("click", async e => {
    const btn = e.target.closest("button[data-act]");
    if (!btn) return;
    const id = btn.dataset.id;
    try {
      switch (btn.dataset.act) {
        case "revoke":
          if (!confirm(`确认撤销 ${id}？下次验证立即生效。`)) return;
          await api(`/api/certs/${id}/revoke`, { method: "POST", body: "{}" });
          toast("已标记撤销"); break;
        case "revokeTimed": {
          const revokedAt = prompt("撤销生效时间（ISO，如 2026-10-01T00:00:00Z；空=当前）", "");
          if (revokedAt === null) return;
          const acquiredAt = prompt("材料获知时间（ISO；空=当前；未来时间=迟到材料）", "");
          if (acquiredAt === null) return;
          const note = prompt("备注（如：更正撤销日期 / 迟到通知）", "") || "";
          const body = { note };
          if (revokedAt.trim()) body.revokedAt = new Date(revokedAt).toISOString();
          if (acquiredAt.trim()) body.acquiredAt = new Date(acquiredAt).toISOString();
          await api(`/api/certs/${id}/revoke`, { method: "POST", body: JSON.stringify(body) });
          toast("已补录撤销材料（旧证据不变，可重新验证生成新版本）"); break;
        }
        case "trustTimed": {
          const trusted = confirm("确定=设为受信，取消=停止受信");
          const effectiveFrom = prompt("生效时间（ISO；空=当前）", "");
          if (effectiveFrom === null) return;
          const acquiredAt = prompt("材料获知时间（ISO；空=当前）", "");
          if (acquiredAt === null) return;
          const body = { trusted, note: "timed trust change" };
          if (effectiveFrom.trim()) body.effectiveFrom = new Date(effectiveFrom).toISOString();
          if (acquiredAt.trim()) body.acquiredAt = new Date(acquiredAt).toISOString();
          await api(`/api/certs/${id}/trust`, { method: "POST", body: JSON.stringify(body) });
          toast("已登记定时信任变更"); break;
        }
        case "trust":
          await api(`/api/certs/${id}/trust`, { method: "POST", body: JSON.stringify({ trusted: true }) });
          toast("已设为信任锚点（规则版本已更新）"); break;
        case "distrust":
          await api(`/api/certs/${id}/trust`, { method: "POST", body: JSON.stringify({ trusted: false }) });
          toast("已取消信任（规则版本已更新）"); break;
        case "crlOn":
          await api(`/api/certs/${id}/crl`, { method: "POST", body: JSON.stringify({ published: true }) });
          toast("已恢复 CRL 发布"); break;
        case "crlOff":
          await api(`/api/certs/${id}/crl`, { method: "POST", body: JSON.stringify({ published: false }) });
          toast("已模拟撤销资料缺失"); break;
        case "crlDelay": {
          const mins = Number(prompt("CRL 生效延迟分钟数（0 = 立即生效）", "30"));
          if (!Number.isFinite(mins)) return;
          await api(`/api/certs/${id}/crldelay`, { method: "POST", body: JSON.stringify({ minutes: mins }) });
          toast(mins > 0 ? `已模拟迟到 ${mins} 分钟的撤销材料` : "撤销材料已恢复即时生效");
          break;
        }
      }
      refresh();
    } catch (err) { toast(err.message, false); }
  });

  $("#loadSamples").addEventListener("click", async () => {
    await api("/api/samples", { method: "POST" });
    $("#verifyResult").innerHTML = "";
    toast("已载入：交叉签发 / 过期中间 / 撤销资料缺失");
    refresh();
  });

  $("#reset").addEventListener("click", async () => {
    if (!confirm("清空全部证书与证据？")) return;
    await api("/api/reset", { method: "POST" });
    $("#verifyResult").innerHTML = "";
    refresh();
  });
}

bindForms();
refresh().catch(err => toast(err.message, false));
