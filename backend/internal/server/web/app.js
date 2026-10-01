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
}

function renderRows(state) {
  const rows = $("#certRows");
  rows.innerHTML = "";
  for (const c of state.certs) {
    const tr = document.createElement("tr");
    const trusted = state.trustedRoots.includes(c.id);
    const purposes = c.kind === "leaf" ? (c.ekus.join(", ") || "-") : "CA";
    const status = [];
    if (c.kind === "root") status.push(trusted ? `<span class="ok-text">受信任</span>` : `<span class="bad-text">不信任</span>`);
    const now = new Date(state.now);
    if (now < new Date(c.notBefore) || now > new Date(c.notAfter)) status.push(`<span class="bad-text">已过期/未生效</span>`);
    if (c.revoked) status.push(`<span class="bad-text">已撤销 ${fmtDate(c.revokedAt)}</span>`);
    if (c.kind !== "leaf" && !c.crlPublished) status.push(`<span class="warn-text">撤销资料缺失</span>`);

    const actions = [`<button class="small danger" data-act="revoke" data-id="${c.id}">撤销</button>`];
    if (c.kind === "root") {
      actions.push(trusted
        ? `<button class="small warn" data-act="distrust" data-id="${c.id}">取消信任</button>`
        : `<button class="small" data-act="trust" data-id="${c.id}">设为信任</button>`);
    }
    if (c.kind !== "leaf") {
      actions.push(c.crlPublished
        ? `<button class="small warn" data-act="crlOff" data-id="${c.id}">停止发布 CRL</button>`
        : `<button class="small" data-act="crlOn" data-id="${c.id}">恢复发布 CRL</button>`);
      actions.push(`<a class="small" href="/api/crl/${c.id}" target="_blank"><button class="small ghost">下载 CRL</button></a>`);
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
    (!step.crlPublished ? " · <span class=\"warn-text\">撤销资料缺失，不能确定撤销状态</span>" : "") +
    `</small></div>`;
}

function verdictText(res) {
  if (res.valid) return "✓ 验证通过";
  return res.unknown ? "? 不能确定" : "✗ 验证失败";
}

function checkList(checks = []) {
  if (!checks.length) return "";
  const label = { pass: "通过", fail: "失败", unknown: "不能确定", skipped: "跳过" };
  const cls = { pass: "ok-text", fail: "bad-text", unknown: "warn-text", skipped: "muted" };
  return `<ul class="checks">${checks.map(check => `
    <li><span class="${cls[check.status] || "muted"}">${label[check.status] || check.status}</span>
    <b>${check.name}</b><small>${check.detail}</small></li>`).join("")}</ul>`;
}

function pathKey(chain) {
  return (chain.path || []).map(step => step.id).join(" → ");
}

function renderComparison(current, previous) {
  if (!previous || current.leafId !== previous.leafId || current.purpose !== previous.purpose || current.rulesVersion === previous.rulesVersion) return "";
  const currentByPath = new Map(current.chains.map(chain => [pathKey(chain), chain]));
  const previousByPath = new Map(previous.chains.map(chain => [pathKey(chain), chain]));
  const keys = Array.from(new Set([...previousByPath.keys(), ...currentByPath.keys()]));
  const state = chain => !chain ? "<span class=\"muted\">无此候选路径</span>" :
    chain.valid ? "<span class=\"ok-text\">有效</span>" :
    chain.unknown ? "<span class=\"warn-text\">不能确定</span>" : "<span class=\"bad-text\">无效</span>";
  return `<div class="comparison">
    <h4>规则变化前后路径比较</h4>
    <div>旧证据 #${previous.evidenceId} · 规则 v${previous.rulesVersion} · ${fmtDate(previous.checkedAt)} → 新证据 #${current.evidenceId} · 规则 v${current.rulesVersion} · ${fmtDate(current.checkedAt)}</div>
    ${keys.map(key => `<div class="compare-row"><b>${key || "不完整路径"}</b><span>${state(previousByPath.get(key))} → ${state(currentByPath.get(key))}</span></div>`).join("")}
    <div class="muted">信任根：${previous.trustedRoots.join(", ") || "（无）"} → ${current.trustedRoots.join(", ") || "（无）"}</div>
  </div>`;
}

function chainHeader(ch) {
  const title = ch.valid ? "可用路径" : ch.unknown ? "不能确定路径" : "无效路径";
  if (!ch.reason) return `<b>${title}</b> <span class="ok-text">— 签名、期限、用途、锚点与撤销资料均满足</span>`;
  const cls = ch.unknown ? "warn-text" : "bad-text";
  return `<b>${title}</b> <span class="${cls}">— ${ch.reason}</span>`;
}

function chainHTML(ch) {
  const stateClass = ch.valid ? "ok" : ch.unknown ? "unknown" : "bad";
  const steps = ch.path.map((step, index) => pathArrow(step, index === 0)).join("");
  return `<div class="chain ${stateClass}">${chainHeader(ch)}${checkList(ch.checks)}${steps}</div>`;
}

function renderResult(res, target, previous = null, replay = false) {
  const verdictClass = res.valid ? "ok" : res.unknown ? "unknown" : "bad";
  const reasonLabel = res.valid ? "实际采用路径：" : res.unknown ? "不能确定原因：" : "失败原因：";
  const reasonValue = res.valid ? (res.selectedPath || []).join(" → ") : (res.reason || "-");
  const chains = res.chains.map(chainHTML).join("");
  const replayBanner = replay ? `<div class="replay-banner">正在回看证据 #${res.evidenceId}：固定在 ${fmtDate(res.checkedAt)} 与规则 v${res.rulesVersion}，不会重新执行当前验证。<button type="button" id="exitReplay" class="small ghost">返回新实验</button></div>` : "";
  target.innerHTML = `${replayBanner}
    <div class="verdict ${verdictClass}">${verdictText(res)} · 证书 ${res.leafId} · 用途 ${res.purpose} · 证据 #${res.evidenceId} · 规则版本 ${res.rulesVersion}</div>
    <div class="muted">${reasonLabel}${reasonValue}</div>
    <div class="muted">受信任根：${res.trustedRoots.join(", ") || "（无）"} · 检查时间 ${fmtDate(res.checkedAt)}</div>
    ${renderComparison(res, previous)}${chains}`;
}

function renderHistory(history) {
  const box = $("#history");
  box.innerHTML = history.length ? "" : `<p class="muted">暂无验证证据。</p>`;
  history.forEach((res, index) => {
    const previous = history.slice(index + 1).find(item =>
      item.leafId === res.leafId && item.purpose === res.purpose && item.rulesVersion !== res.rulesVersion
    ) || null;
    const details = document.createElement("details");
    details.className = "evidence";
    details.open = res.evidenceId === history[0].evidenceId;
    details.innerHTML = `
      <summary>
        <span class="${res.valid ? "ok-text" : res.unknown ? "warn-text" : "bad-text"}"><b>${verdictText(res)}</b></span>
        证据 #${res.evidenceId} · 规则 v${res.rulesVersion} · ${res.leafId} · ${res.purpose} · ${fmtDate(res.checkedAt)}
        ${res.valid ? ` · 路径 ${res.selectedPath.join(" → ")}` : ` · ${res.reason}`}
      </summary>
      <div id="ev-${res.evidenceId}"></div>
      <button type="button" class="small ghost replay" data-evidence="${res.evidenceId}">在上方重看此结论</button>`;
    box.appendChild(details);
    renderResult(res, details.querySelector(`#ev-${res.evidenceId}`), previous);
    details.querySelector(`[data-evidence="${res.evidenceId}"]`).addEventListener("click", () => {
      renderResult(res, $("#verifyResult"), previous, true);
      $("#verifyResult").scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
}

function bindReplayExit() {
  document.addEventListener("click", e => {
    if (e.target.id !== "exitReplay") return;
    $("#verifyResult").innerHTML = "<div class='muted'>已返回当前实验；可选择证书后发起新的验证。</div>";
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
    try {
      const res = await api("/api/verify", { method: "POST", body: JSON.stringify({ leafId, purpose }) });
      renderResult(res, $("#verifyResult"));
      const msg = res.valid ? `验证通过，采用路径：${res.selectedPath.join(" → ")}` :
        res.unknown ? `不能确定：${res.reason}` : `验证失败：${res.reason}`;
      toast(msg, !res.unknown);
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
      }
      refresh();
    } catch (err) { toast(err.message, false); }
  });

  $("#loadSamples").addEventListener("click", async () => {
    try {
      await api("/api/samples", { method: "POST" });
      $("#verifyResult").innerHTML = "";
      toast("已载入：交叉签发 / 过期中间 / 撤销资料缺失");
      await refresh();
    } catch (err) { toast(`载入样例失败：${err.message}`, false); }
  });

  $("#reset").addEventListener("click", async () => {
    if (!confirm("清空将开始新实验；仍可先展开旧页面证据查看，确认清空？")) return;
    try {
      await api("/api/reset", { method: "POST" });
      $("#verifyResult").innerHTML = "";
      await refresh();
    } catch (err) { toast(`清空失败：${err.message}`, false); }
  });
}

bindReplayExit();
bindForms();
refresh().catch(err => toast(err.message, false));
