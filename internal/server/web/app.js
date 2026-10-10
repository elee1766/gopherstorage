"use strict";

const $ = (s) => document.querySelector(s);

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "onclick") e.addEventListener("click", v);
    else if (k === "class") e.className = v;
    else e.setAttribute(k, v);
  }
  for (const c of children) e.append(c);
  return e;
}

function fmtSize(n) {
  if (n < 1024) return n + " B";
  const u = ["KiB", "MiB", "GiB", "TiB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + " " + u[i];
}

function fmtTime(t) {
  return t ? new Date(t).toLocaleString() : "never";
}

function setStatus(msg, isError) {
  const s = $("#status");
  s.textContent = msg || "";
  s.className = isError ? "error" : "dim";
}

async function api(method, url, body) {
  const res = await fetch(url, {
    method, credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) throw Object.assign(new Error("not signed in"), { auth: true });
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch {}
    throw new Error(msg);
  }
  return res.status === 204 ? null : res.json();
}

function scopeText(scope) {
  return scope.split(" ").map((s) => {
    const [mod, lvl] = s.split(":");
    return (mod === "*" ? "everything" : mod) + (lvl === "rw" ? " (read/write)" : " (read)");
  }).join(", ");
}

async function revoke(g) {
  if (!confirm(`Disconnect ${g.client}? It will lose access to your storage.`)) return;
  try {
    await api("DELETE", "/api/grants/" + g.id);
    load();
  } catch (e) { setStatus(e.message, true); }
}

async function setQuota(u) {
  const cur = u.quota_bytes ? (u.quota_bytes / 2 ** 20).toString() : "";
  const v = prompt(`Quota for ${u.username} in MiB (empty for server default)`, cur);
  if (v === null) return;
  const bytes = v.trim() === "" ? 0 : Math.round(parseFloat(v) * 2 ** 20);
  if (!(bytes >= 0)) return setStatus("Invalid quota", true);
  try {
    await api("PUT", `/api/admin/users/${u.id}/quota`, { quota_bytes: bytes });
    loadAdmin();
  } catch (e) { setStatus(e.message, true); }
}

async function loadAdmin() {
  const data = await api("GET", "/api/admin/users");
  const tbody = $("#users tbody");
  tbody.replaceChildren();
  for (const u of data.users) {
    const q = u.quota_bytes || data.default_quota_bytes;
    tbody.append(el("tr", {},
      el("td", {}, u.username),
      el("td", { class: "num" }, fmtSize(u.used_bytes)),
      el("td", { class: "num" }, q ? fmtSize(q) + (u.quota_bytes ? "" : " (default)") : "unlimited"),
      el("td", {}, fmtTime(u.last_login)),
      el("td", { class: "ops" }, el("button", { type: "button", class: "small", onclick: () => setQuota(u) }, "Set quota")),
    ));
  }
  $("#admin").hidden = false;
}

async function load() {
  let acct;
  try {
    acct = await api("GET", "/api/account");
  } catch (e) {
    if (e.auth) {
      $("#login").hidden = false;
      $("#account").hidden = true;
      return;
    }
    return setStatus(e.message, true);
  }
  $("#login").hidden = true;
  $("#account").hidden = false;
  $("#who").replaceChildren(acct.name || acct.username, el("a", { href: "/auth/logout" }, "Sign out"));
  $("#address").textContent = acct.address;

  let usage = `${fmtSize(acct.used_bytes)} in ${acct.documents} document${acct.documents === 1 ? "" : "s"}`;
  if (acct.quota_bytes) {
    usage += ` of ${fmtSize(acct.quota_bytes)}`;
    $("#meter").hidden = false;
    $("#meter-bar").style.width = Math.min(100, (100 * acct.used_bytes) / acct.quota_bytes).toFixed(1) + "%";
  }
  $("#usage").textContent = usage;

  const tbody = $("#apps tbody");
  tbody.replaceChildren();
  for (const g of acct.grants) {
    tbody.append(el("tr", {},
      el("td", {}, el("div", {}, g.client), el("div", { class: "dim small" }, g.origin)),
      el("td", {}, scopeText(g.scope)),
      el("td", {}, fmtTime(g.last_used)),
      el("td", { class: "ops" }, el("button", { type: "button", class: "small danger", onclick: () => revoke(g) }, "Disconnect")),
    ));
  }
  $("#apps").hidden = acct.grants.length === 0;
  $("#no-apps").hidden = acct.grants.length > 0;

  if (acct.admin) loadAdmin().catch((e) => setStatus(e.message, true));
}

$("#copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("#address").textContent);
    setStatus("Copied.");
  } catch { setStatus("Copy failed, select the address manually.", true); }
});

load();
