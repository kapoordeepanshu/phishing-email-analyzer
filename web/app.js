// Runs the phishanalyzer Python package in the browser with Pyodide.
// Email contents are attacker-controlled: everything is rendered with textContent,
// and links are shown as text only - never as clickable anchors.
"use strict";

const PY_FILES = ["__init__.py", "findings.py", "domains.py", "parser.py", "headers.py",
                  "links.py", "attachments.py", "content.py", "analyzer.py"];
// Deployed site has ./phishanalyzer; when served from the repo root during development it is ../phishanalyzer
const PY_BASES = ["./phishanalyzer/", "../phishanalyzer/"];
const SAMPLE_BASES = ["./samples/", "../samples/"];
const MAX_BYTES = 30 * 1024 * 1024;
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const VERDICT_TONE = {
  "PHISHING / MALICIOUS": "--crit", "SUSPICIOUS": "--high", "LOW RISK": "--med", "NO STRONG INDICATORS": "--ok",
};

const $ = (id) => document.getElementById(id);
let pyodide = null;
let lastReport = null;

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else node.setAttribute(k, v);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function setStatus(text, isError = false) {
  const s = $("status");
  s.textContent = text;
  s.classList.toggle("error", isError);
}

function setBusy(busy) {
  document.querySelectorAll(".chip, #analyze-raw").forEach((b) => { b.disabled = busy || !pyodide; });
}

async function fetchFirst(bases, name, asText) {
  for (const base of bases) {
    try {
      const resp = await fetch(base + name, { cache: "no-cache" });
      if (resp.ok) return asText ? resp.text() : new Uint8Array(await resp.arrayBuffer());
    } catch (_) { /* try next base */ }
  }
  throw new Error(`could not load ${name}`);
}

async function boot() {
  setBusy(true);
  try {
    pyodide = await loadPyodide();
    pyodide.FS.mkdirTree("/app/phishanalyzer");
    for (const name of PY_FILES) {
      pyodide.FS.writeFile(`/app/phishanalyzer/${name}`, await fetchFirst(PY_BASES, name, true));
    }
    pyodide.runPython(`
import sys, json
sys.path.insert(0, "/app")
from phishanalyzer.analyzer import analyze_bytes
from phishanalyzer.parser import EmailParseError

def run_analysis(path, label):
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        return json.dumps(analyze_bytes(data, label).to_dict())
    except EmailParseError as e:
        return json.dumps({"error": str(e)})
`);
    setStatus("Ready. Your email is analysed locally and never leaves this page.");
  } catch (err) {
    console.error(err);
    setStatus("Could not load the analysis engine (" + err.message + "). Check your connection and reload.", true);
  } finally {
    setBusy(false);
  }
}

async function analyze(bytes, label) {
  if (!pyodide) { setStatus("The engine is still loading, one moment…"); return; }
  if (bytes.length > MAX_BYTES) { setStatus("That file is larger than 30 MB.", true); return; }
  setBusy(true);
  setStatus(`Analysing ${label}…`);
  await new Promise((r) => setTimeout(r, 20)); // let the status paint before the CPU-bound run
  try {
    pyodide.FS.writeFile("/tmp/input.eml", bytes);
    const result = JSON.parse(pyodide.globals.get("run_analysis")("/tmp/input.eml", label));
    pyodide.FS.unlink("/tmp/input.eml");
    if (result.error) { setStatus(result.error, true); return; }
    lastReport = result;
    render(result);
    setStatus(`Analysed ${label}.`);
  } catch (err) {
    console.error(err);
    setStatus("Analysis failed: " + String(err.message || err).split("\n").slice(-2).join(" "), true);
  } finally {
    setBusy(false);
  }
}

// ---------------------------------------------------------------- rendering

function sevBadge(sev, text = sev) {
  return el("span", { class: `sev ${sev}` }, text);
}

function evidenceList(items) {
  if (!items || !items.length) return null;
  const shown = items.slice(0, 6);
  return el("ul", { class: "evidence" }, shown.map((e) => el("li", {}, e)),
    items.length > 6 ? el("li", {}, `… ${items.length - 6} more`) : null);
}

function renderFindings(r) {
  const panel = $("panel-findings");
  panel.replaceChildren();
  if (!r.findings.length) {
    panel.append(el("p", { class: "empty" }, "No phishing indicators found. That does not prove the email is safe."));
    return;
  }
  for (const f of r.findings) {
    panel.append(el("div", { class: "row" },
      el("div", { class: "row-head" }, sevBadge(f.severity), el("span", { class: "row-title" }, f.title),
        el("span", { class: "cat" }, f.category)),
      f.detail ? el("p", { class: "detail" }, f.detail) : null,
      evidenceList(f.evidence)));
  }
}

function authBadge(name, value) {
  const v = value || "n/a";
  const sev = v === "pass" ? "OK" : (v === "fail" || v === "softfail") ? "HIGH" : "INFO";
  return sevBadge(sev, `${name}: ${v}`);
}

function renderSender(r) {
  const s = r.sender;
  const panel = $("panel-sender");
  panel.replaceChildren();
  const rows = [["Subject", r.subject], ["From", s.from_], ["Reply-To", s.reply_to], ["Return-Path", s.return_path],
    ["To", s.to], ["Date", s.date], ["Message-ID", s.message_id], ["Mailer", s.mailer],
    ["Originating IP", s.origin_ip], ["DKIM signed by", (s.dkim_domains || []).join(", ")]];
  const dl = el("dl", { class: "kv" });
  dl.append(el("dt", {}, "Authentication"), el("dd", {},
    Object.keys(s.auth).length
      ? el("div", { class: "auth" }, authBadge("SPF", s.auth.spf), authBadge("DKIM", s.auth.dkim),
          authBadge("DMARC", s.auth.dmarc))
      : el("span", { class: "muted" }, "No Authentication-Results header (export the full original message)")));
  for (const [k, v] of rows) if (v) dl.append(el("dt", {}, k), el("dd", { class: k === "Subject" ? "" : "mono" }, v));
  panel.append(dl);
  if (s.hops.length) {
    panel.append(el("dl", { class: "kv" }, el("dt", {}, `Relay path (${s.hops.length} hops, oldest first)`), el("dd", {})));
    panel.append(el("ol", { class: "hops" }, s.hops.map((h) =>
      el("li", { class: "mono" }, `${h.from_host || "?"}${h.ip ? " [" + h.ip + "]" : ""} → ${h.by_host || "?"}`))));
  }
}

function renderLinks(r) {
  const panel = $("panel-links");
  panel.replaceChildren();
  if (!r.links.length) { panel.append(el("p", { class: "empty" }, "No links found.")); return; }
  const sorted = [...r.links].sort((a, b) => b.flags.length - a.flags.length);
  for (const l of sorted) {
    const meta = [];
    if (l.text && l.text.trim() !== l.url) meta.push(`shown as: ${l.text}`);
    if (l.unwrapped_from) meta.push(`unwrapped from: ${l.unwrapped_from}`);
    if (!/^(body|html)$/.test(l.source)) meta.push(`found in: ${l.source}`);
    panel.append(el("div", { class: "row" },
      el("div", { class: "row-head" }, l.flags.length ? sevBadge("HIGH", "SUSPICIOUS") : sevBadge("OK", "NO FLAGS"),
        el("span", { class: "url" }, l.url)),
      meta.length ? el("p", { class: "detail" }, meta.join(" · ")) : null,
      l.flags.length ? el("ul", { class: "flags" }, l.flags.map((f) => el("li", {}, f))) : null));
  }
}

function formatSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

function renderAttachments(r) {
  const panel = $("panel-attachments");
  panel.replaceChildren();
  if (!r.attachments.length) { panel.append(el("p", { class: "empty" }, "No attachments.")); return; }
  for (const a of r.attachments) {
    panel.append(el("div", { class: "row" },
      el("div", { class: "row-head" }, a.flags.length ? sevBadge("HIGH", "RISKY") : sevBadge("OK", "NO FLAGS"),
        el("span", { class: "row-title" }, a.filename)),
      el("p", { class: "detail" },
        `${a.content_type} · ${formatSize(a.size)}${a.detected_type ? " · real type: " + a.detected_type : ""}`),
      el("ul", { class: "evidence" }, el("li", {}, `SHA-256 ${a.sha256}`), el("li", {}, `MD5 ${a.md5}`),
        a.members.length ? el("li", {}, `contains: ${a.members.slice(0, 15).join(", ")}`) : null),
      a.flags.length ? el("ul", { class: "flags" }, a.flags.map((f) => el("li", {}, f))) : null,
      el("p", { class: "detail small" }, "Check this file's reputation: search the SHA-256 on VirusTotal.")));
  }
}

function render(r) {
  $("results").hidden = false;
  $("score").textContent = r.score;
  const gauge = $("gauge");
  gauge.style.setProperty("--pct", r.score);
  gauge.style.setProperty("--tone", `var(${VERDICT_TONE[r.verdict] || "--accent"})`);
  $("verdict").textContent = r.verdict;
  $("subject").textContent = r.subject ? `“${r.subject}”` : "(no subject)";
  $("counts").replaceChildren(...SEVERITIES.map((s) => {
    const b = sevBadge(s, `${r.summary[s]} ${s}`);
    if (!r.summary[s]) b.classList.add("zero");
    return b;
  }));
  $("n-findings").textContent = `(${r.findings.length})`;
  $("n-links").textContent = `(${r.links.length})`;
  $("n-atts").textContent = `(${r.attachments.length})`;
  renderFindings(r); renderSender(r); renderLinks(r); renderAttachments(r);
  selectTab("findings");
  $("results").scrollIntoView({ behavior: "smooth", block: "start" });
}

function selectTab(name) {
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  for (const p of ["findings", "sender", "links", "attachments"]) $(`panel-${p}`).hidden = p !== name;
}

// ---------------------------------------------------------------- input wiring

function readFile(file) {
  if (!file) return;
  file.arrayBuffer().then((buf) => analyze(new Uint8Array(buf), file.name));
}

const drop = $("drop");
drop.addEventListener("click", (e) => { if (e.target.tagName !== "A") $("file").click(); });
drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("file").click(); } });
$("file").addEventListener("change", (e) => { readFile(e.target.files[0]); e.target.value = ""; });
["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((t) => drop.addEventListener(t, () => drop.classList.remove("over")));
drop.addEventListener("drop", (e) => { e.preventDefault(); readFile(e.dataTransfer.files[0]); });
// Dropping outside the zone should not navigate away to the file
window.addEventListener("dragover", (e) => e.preventDefault());
window.addEventListener("drop", (e) => e.preventDefault());

$("analyze-raw").addEventListener("click", () => {
  const raw = $("raw").value.replace(/^\s+/, "");
  if (!raw) { setStatus("Paste the full message source first.", true); return; }
  analyze(new TextEncoder().encode(raw.replace(/\r?\n/g, "\r\n")), "pasted source");
});

async function loadSample(name) {
  try {
    await analyze(await fetchFirst(SAMPLE_BASES, name, false), name);
  } catch (err) {
    setStatus("Sample not available: " + err.message, true);
  }
}

document.querySelectorAll("[data-sample]").forEach((btn) =>
  btn.addEventListener("click", () => loadSample(btn.dataset.sample)));

document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => selectTab(b.dataset.tab)));

$("download").addEventListener("click", () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
  const a = el("a", { href: URL.createObjectURL(blob), download: "phishing-report.json" });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

$("reset").addEventListener("click", () => {
  $("results").hidden = true;
  lastReport = null;
  window.scrollTo({ top: 0, behavior: "smooth" });
});

// Demo links: index.html#sample=phishing_paypal.eml opens a bundled sample (only those listed on the page)
boot().then(() => {
  const m = location.hash.match(/^#sample=([\w.-]+\.eml)$/);
  if (m && document.querySelector(`[data-sample="${m[1]}"]`)) loadSample(m[1]);
});
