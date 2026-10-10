"use strict";

const $ = (s) => document.querySelector(s);
let state = { mounts: [], mount: null, path: "", writable: false };

function encPath(p) {
  return p.split("/").filter(Boolean).map(encodeURIComponent).join("/");
}

function apiURL(mount, p) {
  const ep = encPath(p);
  return "/api/files/" + encodeURIComponent(mount) + (ep ? "/" + ep : "");
}

function setStatus(msg, isError) {
  const el = $("#status");
  el.textContent = msg || "";
  el.className = isError ? "error" : "";
}

async function api(method, url, body, headers) {
  const res = await fetch(url, { method, body, headers, credentials: "same-origin" });
  if (res.status === 401) {
    showLogin();
    throw new Error("not signed in");
  }
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch {}
    throw new Error(msg);
  }
  if (res.status === 204) return null;
  return res.json();
}

function fmtSize(n) {
  if (n < 1024) return n + " B";
  const u = ["KiB", "MiB", "GiB", "TiB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + " " + u[i];
}

function fmtTime(t) {
  if (!t) return "";
  return new Date(t).toLocaleString();
}

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

function showLogin() {
  $("#app").hidden = true;
  $("#login").hidden = false;
  $("#who").textContent = "";
  $("#login-link").href = "/auth/login?return=" + encodeURIComponent(location.pathname + location.hash);
}

function readHash() {
  const h = decodeURIComponent(location.hash.replace(/^#\/?/, ""));
  const [mount, ...rest] = h.split("/");
  return { mount: mount || null, path: rest.filter(Boolean).join("/") };
}

function go(mount, p) {
  location.hash = "#/" + encodeURIComponent(mount) + (p ? "/" + encPath(p) : "");
}

function renderMounts() {
  const nav = $("#mounts");
  nav.replaceChildren();
  for (const m of state.mounts) {
    const a = el("a", { href: "#/" + encodeURIComponent(m.name), class: m.name === state.mount ? "active" : "" }, m.name);
    if (!m.writable) a.title = "read only";
    nav.append(a);
  }
}

function renderCrumbs() {
  const c = $("#crumbs");
  c.replaceChildren(el("a", { href: "#/" + encodeURIComponent(state.mount) }, state.mount));
  let acc = "";
  for (const part of state.path.split("/").filter(Boolean)) {
    acc = acc ? acc + "/" + part : part;
    const target = acc;
    c.append(el("span", { class: "sep" }, "/"), el("a", { href: "#", onclick: (e) => { e.preventDefault(); go(state.mount, target); } }, part));
  }
}

async function load() {
  const { mount, path } = readHash();
  const m = state.mounts.find((x) => x.name === mount) || state.mounts[0];
  if (!m) {
    setStatus("You do not have access to any mounts.", true);
    return;
  }
  if (m.name !== mount) return go(m.name, "");
  state.mount = m.name;
  state.path = path;
  state.writable = m.writable;
  renderMounts();
  renderCrumbs();
  $("#mkdir").hidden = !m.writable;
  $("#upload-label").hidden = !m.writable;
  setStatus("Loading...");
  let data;
  try {
    data = await api("GET", apiURL(m.name, path));
  } catch (e) {
    setStatus(e.message, true);
    return;
  }
  if (!data.entry.is_dir) {
    location.href = apiURL(m.name, path);
    return;
  }
  setStatus("");
  const dirs = data.entries.filter((e) => e.is_dir);
  const files = data.entries.filter((e) => !e.is_dir);
  const tbody = $("#listing tbody");
  tbody.replaceChildren();
  for (const e of [...dirs, ...files]) tbody.append(row(e));
  $("#empty").hidden = data.entries.length > 0;
}

function row(e) {
  const full = state.path ? state.path + "/" + e.name : e.name;
  const link = e.is_dir
    ? el("a", { href: "#", onclick: (ev) => { ev.preventDefault(); go(state.mount, full); } }, e.name + "/")
    : el("a", { href: apiURL(state.mount, full), target: "_blank", rel: "noopener" }, e.name);
  const ops = el("td", { class: "ops" });
  if (!e.is_dir) {
    ops.append(el("a", { class: "button small", href: apiURL(state.mount, full) + "?download" }, "Download"));
  }
  if (state.writable) {
    ops.append(
      el("button", { class: "small", type: "button", onclick: () => rename(full, e.name) }, "Rename"),
      el("button", { class: "small danger", type: "button", onclick: () => remove(full, e.is_dir) }, "Delete"),
    );
  }
  return el("tr", { class: e.is_dir ? "dir" : "" },
    el("td", { class: "name" }, link),
    el("td", { class: "num" }, e.is_dir ? "" : fmtSize(e.size)),
    el("td", {}, fmtTime(e.mod_time)),
    ops,
  );
}

function validName(n) {
  return n && !n.includes("/") && n !== "." && n !== "..";
}

async function rename(full, name) {
  const next = prompt("Rename to", name);
  if (!next || next === name) return;
  if (!validName(next)) return setStatus("Invalid name", true);
  const to = state.path ? state.path + "/" + next : next;
  try {
    await api("POST", apiURL(state.mount, full) + "?op=move", JSON.stringify({ to }), { "Content-Type": "application/json" });
    load();
  } catch (e) { setStatus(e.message, true); }
}

async function remove(full, isDir) {
  if (!confirm("Delete " + full + (isDir ? " and everything in it" : "") + "?")) return;
  try {
    await api("DELETE", apiURL(state.mount, full) + (isDir ? "?recursive=true" : ""));
    load();
  } catch (e) { setStatus(e.message, true); }
}

async function mkdir() {
  const name = prompt("Folder name");
  if (!name) return;
  if (!validName(name)) return setStatus("Invalid name", true);
  const p = state.path ? state.path + "/" + name : name;
  try {
    await api("POST", apiURL(state.mount, p) + "?op=mkdir");
    load();
  } catch (e) { setStatus(e.message, true); }
}

async function upload(files) {
  if (!state.writable) return;
  let i = 0;
  for (const f of files) {
    i++;
    setStatus(`Uploading ${f.name} (${i}/${files.length})...`);
    const p = state.path ? state.path + "/" + f.name : f.name;
    try {
      await api("PUT", apiURL(state.mount, p), f, { "Content-Type": f.type || "application/octet-stream" });
    } catch (e) {
      setStatus(`${f.name}: ${e.message}`, true);
      return load();
    }
  }
  setStatus("");
  load();
}

async function init() {
  $("#mkdir").addEventListener("click", mkdir);
  $("#upload").addEventListener("change", (e) => { upload([...e.target.files]); e.target.value = ""; });
  const drop = $("#drop");
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); upload([...e.dataTransfer.files]); });
  window.addEventListener("hashchange", load);

  let me;
  try {
    me = await api("GET", "/api/me");
  } catch {
    return;
  }
  state.mounts = me.mounts;
  $("#who").replaceChildren(me.user.name || me.user.username, el("a", { href: "/auth/logout" }, "Sign out"));
  $("#login").hidden = true;
  $("#app").hidden = false;
  load();
}

init();
