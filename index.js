#!/usr/bin/env node
"use strict";

/*
 * TFN Checker
 * -----------
 * Checks TFN / tech-support-scam landing pages repeatedly (each check is a fresh
 * "refresh") and prints ONLY the toll-free "support" numbers that have not been
 * seen before, so a rotating number set can be harvested for reporting.
 *
 * Two extraction methods (method: "auto" tries decrypt first, else browser):
 *
 *  1. decrypt (default, no browser, ~0 memory) — these kits hide the real page
 *     inside an AES-encrypted blob that JS fetches and injects into an iframe. We
 *     replicate that decryption in Node (CryptoJS/OpenSSL "Salted__" scheme) and
 *     read the number from the decrypted HTML's *visible text*. No hostile code
 *     ever runs, so it can't balloon memory — important, because the revealed
 *     payload is a "browser locker" that otherwise eats many GB of RAM.
 *
 *  2. browser (fallback for pages that don't match the decrypt scheme) — opens a
 *     fresh, locked-down headless context, neuters the page's memory/CPU bombs,
 *     triggers the interaction-gated reveal, and reads the iframe. Higher memory.
 *
 * Intended for defensive / threat-intelligence use.
 *
 * Usage:
 *   node index.js                                   # every url in urls.json, in turn
 *   node index.js https://host/index.html           # ad-hoc target(s), ignores urls.json
 *   node index.js --url https://a --url https://b
 *   node index.js --urls-file other-targets.json
 *   node index.js --interval 5000 --count 20        # 20 checks per url, 5s apart
 *   node index.js --headful                         # show the browser window
 *
 * Targets (urls.json):
 *   Every url listed there is checked one at a time, round-robin, and gets its
 *   OWN record folder — a number found on one url is never filed under another.
 *
 * Output / state:
 *   records/<id>/seen-tfns.json   numbers ever seen on THAT url
 *   records/<id>/tfns.log         discovery log for THAT url
 *   records/<id>/target.json      that url's status (checks, hits, last seen)
 *   records/summary.json          every url and its numbers, at a glance
 *   seen-tfns.json / tfns.log     merged mirror of all urls (--no-combined to skip)
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { chromium } = require("playwright");

// --------------------------------------------------------------------------
// Config
// --------------------------------------------------------------------------

const DEFAULT_URLS = [
  "https://kkofuku.mkc1.cdn.digitaloceanspaces.com/index.html",
];

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

const TOLL_FREE = new Set(["800", "833", "844", "855", "866", "877", "888"]);

function printHelp() {
  console.log(`TFN Checker — collect rotating support numbers from TFN/scam pages.

Usage:
  node index.js [urls...] [options]

Targets come from urls.json (created on first run). Every URL is checked in
turn, one at a time, and keeps its own record folder under records/<id>/ so the
numbers for one URL are never mixed with another's.

Options:
  --url <u>         Check this URL instead of urls.json (repeatable)
  --urls-file <f>   Targets file: .json like urls.json, or .txt one URL per line
  --records <dir>   Where the per-URL record folders live (default records/)
  --no-combined     Don't also mirror everything into the merged store + log
  --interval <ms>   Delay between checks                (default 5000)
  --count <n>       Checks per URL; 0/Infinity = forever (default forever)
  --method <m>      auto | decrypt | browser           (default auto)
                    auto    = decrypt, fall back to browser if the kit isn't recognized
                    decrypt = Node-only, no browser, ~0 memory (recommended)
                    browser = always render in headless Chromium (uses lots of memory)
  --platform <p>    Which payload(s) to pull in decrypt mode: win | mac | both (default both)
  --settle <ms>     [browser] time to let JS render after load (default 3000)
  --timeout <ms>    Navigation / fetch timeout          (default 30000)
  --headful         [browser] show the browser window (default headless)
  --scan-html       Scan raw HTML too, not just visible text (noisier)
  --load-assets     [browser] load images/media/fonts too (default: blocked)
  --recycle <n>     [browser] relaunch every n refreshes to free memory (default 30; 0=never)
  --store <f>       Merged all-URL mirror of the numbers  (default seen-tfns.json)
  --log <f>         Merged all-URL discovery log          (default tfns.log)
  -h, --help        Show this help

Per-URL records (the authoritative, unmixed copy):
  records/<id>/seen-tfns.json   every number ever seen on THAT url
  records/<id>/tfns.log         append-only discovery log for THAT url
  records/<id>/target.json      that url's status: checks, hits, last seen…
  records/summary.json          one-glance table of every url and its numbers
`);
}

function parseArgs(argv) {
  const cfg = {
    urls: [], // set from the command line only; otherwise urls.json is used
    urlsFile: path.join(__dirname, "urls.json"),
    records: path.join(__dirname, "records"),
    combined: true, // also mirror everything into the merged store/log
    interval: 5000,
    count: Infinity,
    settle: 3000,
    timeout: 30000,
    method: "auto", // auto = decrypt then browser fallback; or "decrypt" / "browser"
    platform: "both", // which platform payload(s) to pull in decrypt mode: win|mac|both
    headful: false,
    scanHtml: false,
    blockAssets: true, // skip images/media/fonts to use less memory + bandwidth
    recycle: 30, // relaunch the browser every N refreshes to reclaim memory (0 = never)
    store: path.join(__dirname, "seen-tfns.json"),
    log: path.join(__dirname, "tfns.log"),
  };

  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    switch (a) {
      case "--url": cfg.urls.push(next()); break;
      case "--urls-file":
      case "--urls":
      case "--targets": cfg.urlsFile = path.resolve(next()); break;
      case "--records": cfg.records = path.resolve(next()); break;
      case "--no-combined": cfg.combined = false; break;
      case "--interval": cfg.interval = Number(next()); break;
      case "--count": {
        const n = Number(next());
        cfg.count = !n || n < 0 ? Infinity : n;
        break;
      }
      case "--method": {
        const m = String(next() || "").toLowerCase();
        if (!["auto", "decrypt", "browser"].includes(m)) {
          console.error(`--method must be auto|decrypt|browser`); process.exit(1);
        }
        cfg.method = m;
        break;
      }
      case "--platform": {
        const p = String(next() || "").toLowerCase();
        if (!["win", "mac", "both"].includes(p)) {
          console.error(`--platform must be win|mac|both`); process.exit(1);
        }
        cfg.platform = p;
        break;
      }
      case "--settle": cfg.settle = Number(next()); break;
      case "--timeout": cfg.timeout = Number(next()); break;
      case "--headful": cfg.headful = true; break;
      case "--scan-html": cfg.scanHtml = true; break;
      case "--load-assets": cfg.blockAssets = false; break;
      case "--recycle": cfg.recycle = Math.max(0, Number(next()) || 0); break;
      case "--store": cfg.store = next(); break;
      case "--log": cfg.log = next(); break;
      case "-h":
      case "--help": printHelp(); process.exit(0);
      default:
        if (/^https?:\/\//i.test(a)) cfg.urls.push(a);
        else { console.error(`Unknown argument: ${a}`); printHelp(); process.exit(1); }
    }
  }
  return cfg; // targets themselves are resolved later, by loadTargets()
}

// --------------------------------------------------------------------------
// Phone number extraction
// --------------------------------------------------------------------------

// North American numbers, including the "+1 (806) 382-2357" form.
// Area code and exchange must start 2-9 (valid NANP), which also filters out
// most random digit runs.
const PHONE_RE =
  /(?:\+?1[\s.\-‐-―]*)?\(?\s*([2-9]\d{2})\s*\)?[\s.\-‐-―]*([2-9]\d{2})[\s.\-‐-―]*(\d{4})(?!\d)/g;

function key(area, exch, line) {
  return `1${area}${exch}${line}`; // 11-digit canonical key
}

function pretty(area, exch, line) {
  return `+1 (${area}) ${exch}-${line}`;
}

// Pull candidate numbers from a chunk of text. Returns [{ canonical, pretty, area }].
function matchNumbers(text) {
  const out = [];
  if (!text) return out;
  let m;
  PHONE_RE.lastIndex = 0;
  while ((m = PHONE_RE.exec(text)) !== null) {
    const [, area, exch, line] = m;
    out.push({
      canonical: key(area, exch, line),
      pretty: pretty(area, exch, line),
      area,
      tollFree: TOLL_FREE.has(area),
    });
  }
  return out;
}

// Reduce an HTML string to roughly its *visible* text: drop comments, <script>
// and <style> blocks, base64/data: blobs, and all tags. This is what defeats the
// decoy numbers these payloads carry — e.g. `999-999-9999` living inside a CSS
// `z-index: 9999999999999`, or a fake number buried in a base64 image — leaving
// only the number actually shown to a visitor.
function visibleText(html) {
  return String(html)
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/\bdata:[a-z0-9.+\/-]+;base64,[A-Za-z0-9+\/=]+/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&");
}

// --------------------------------------------------------------------------
// Decrypt method (no browser) — replicate the page's own AES step in Node
// --------------------------------------------------------------------------

// Emulate CryptoJS.AES.decrypt(base64, passphrase).toString(CryptoJS.enc.Utf8).
// CryptoJS's string-passphrase mode is OpenSSL's "Salted__" format: an MD5-based
// EVP_BytesToKey KDF feeding AES-256-CBC.
function cryptoJsDecrypt(cipherB64, passphrase) {
  const data = Buffer.from(String(cipherB64), "base64");
  if (data.length < 16 || data.slice(0, 8).toString("latin1") !== "Salted__") {
    throw new Error("not a salted CryptoJS ciphertext");
  }
  const salt = data.slice(8, 16);
  const ct = data.slice(16);
  const pass = Buffer.from(passphrase, "utf8");
  let derived = Buffer.alloc(0);
  let block = Buffer.alloc(0);
  while (derived.length < 48) {
    block = crypto.createHash("md5").update(Buffer.concat([block, pass, salt])).digest();
    derived = Buffer.concat([derived, block]);
  }
  const dec = crypto.createDecipheriv("aes-256-cbc", derived.slice(0, 32), derived.slice(32, 48));
  return Buffer.concat([dec.update(ct), dec.final()]).toString("utf8");
}

// fetch() with a timeout. Returns the status alongside the body, so a target
// that is simply gone (404, DNS failure) can be reported as such instead of
// being retried in a browser that would only fail more slowly.
async function fetchText(url, timeoutMs) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(url, { headers: { "User-Agent": UA }, signal: ac.signal });
    return { ok: res.ok, status: res.status, text: await res.text() };
  } finally {
    clearTimeout(t);
  }
}

// Try to get the number(s) purely by decryption — no browser. Returns:
//   Array                     the kit was recognized; its records (may be empty)
//   { unavailable: "note" }   the page itself is gone or unreachable
//   null                      the page loaded but isn't this kit — the caller
//                             may fall back to the browser method
async function scanViaDecrypt(url, cfg) {
  let res;
  try {
    res = await fetchText(url, cfg.timeout);
  } catch (e) {
    return { unavailable: `unreachable: ${String((e && e.message) || e).split("\n")[0]}` };
  }
  if (!res.ok) return { unavailable: `http ${res.status}` };
  const html = res.text;

  const pass = /PASSPHRASE\s*=\s*["']([^"']+)["']/.exec(html)?.[1];
  const urlKey = /URL_KEY\s*=\s*["']([^"']+)["']/.exec(html)?.[1];
  const encOrigin = /ENC_DATA_ORIGIN\s*=\s*["']([^"']+)["']/.exec(html)?.[1];
  const dataPath = /DATA_ORIGIN\s*\+\s*["'](\/[^"']*)["']/.exec(html)?.[1] || "/data";
  if (!pass || !urlKey || !encOrigin) return null; // not this kit

  let origin;
  try {
    origin = cryptoJsDecrypt(encOrigin, urlKey).replace(/\/+$/, "");
  } catch {
    return null;
  }
  if (!/^https?:\/\//i.test(origin)) return null;

  const platforms = cfg.platform === "both" ? ["win", "mac"] : [cfg.platform];
  const results = new Map();
  for (const platform of platforms) {
    try {
      const data = await fetchText(`${origin}${dataPath}?platform=${platform}`, cfg.timeout);
      if (!data.ok) continue;
      const { cipher } = JSON.parse(data.text);
      const secret = cryptoJsDecrypt(cipher, pass);
      const text = cfg.scanHtml ? secret : visibleText(secret);
      for (const r of matchNumbers(text)) {
        if (!results.has(r.canonical)) {
          results.set(r.canonical, { ...r, source: `decrypt:${platform}`, pageUrl: url });
        }
      }
    } catch {
      /* one platform failed — keep going */
    }
  }
  return [...results.values()];
}

// Extract numbers from a single frame: prefer tel:/callto: links, then visible
// text, then (optionally) raw HTML.
async function extractFromFrame(frame, scanHtml) {
  let dom;
  try {
    dom = await frame.evaluate((wantHtml) => ({
      tel: Array.from(
        document.querySelectorAll('a[href^="tel:"], a[href^="callto:"]')
      ).map((a) => a.getAttribute("href") || ""),
      text: document.body ? document.body.innerText : "",
      html: wantHtml ? document.documentElement.outerHTML : "",
    }), scanHtml);
  } catch {
    return [];
  }
  const found = new Map(); // canonical -> record
  const add = (rec, source) => {
    if (!found.has(rec.canonical)) found.set(rec.canonical, { ...rec, source });
  };
  for (const href of dom.tel) for (const r of matchNumbers(href)) add(r, "tel-link");
  for (const r of matchNumbers(dom.text)) add(r, "text");
  if (scanHtml) for (const r of matchNumbers(dom.html)) add(r, "html");
  return [...found.values()];
}

// Extract numbers rendered anywhere on a page — the top document AND every
// nested frame/iframe (these pages inject the real content into a blob iframe).
async function extractFromPage(page, scanHtml) {
  const found = new Map();
  let frames;
  try {
    frames = page.frames();
  } catch {
    return [];
  }
  for (const frame of frames) {
    const recs = await extractFromFrame(frame, scanHtml);
    for (const r of recs) if (!found.has(r.canonical)) found.set(r.canonical, r);
  }
  return [...found.values()];
}

// These pages reveal their real content only after user interaction (a mousemove
// handler bound with { once:true }) and inject it into an iframe. Nudge the mouse,
// dispatch a synthetic mousemove, and call any reveal function directly as a
// belt-and-braces trigger.
async function triggerReveal(page) {
  try {
    await page.mouse.move(160, 170);
    await page.mouse.move(430, 360, { steps: 4 });
    await page.mouse.move(700, 520, { steps: 4 });
  } catch {
    /* mouse may be unavailable on some targets */
  }
  await page
    .evaluate(() => {
      try {
        window.dispatchEvent(
          new MouseEvent("mousemove", { bubbles: true, clientX: 240, clientY: 240 })
        );
        document.dispatchEvent(
          new MouseEvent("mousemove", { bubbles: true, clientX: 240, clientY: 240 })
        );
      } catch (e) {}
      // Common reveal-function names seen on these kits; call whatever exists.
      for (const fn of ["loadSecret", "reveal", "start", "init", "load"]) {
        try {
          if (typeof window[fn] === "function") window[fn]();
        } catch (e) {}
      }
    })
    .catch(() => {});
}

// --------------------------------------------------------------------------
// Persistent store
// --------------------------------------------------------------------------

function loadStore(file, keyFn) {
  try {
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    const map = new Map();
    for (const rec of data.numbers || []) map.set(keyFn ? keyFn(rec) : rec.canonical, rec);
    return map;
  } catch {
    return new Map();
  }
}

// `header` describes whose numbers these are (id/label/url for a per-URL store),
// so every record file says on its face which page it belongs to.
function saveStore(file, map, header) {
  const numbers = [...map.values()].sort(
    (a, b) => (a.firstSeen || "").localeCompare(b.firstSeen || "")
  );
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + ".tmp";
  fs.writeFileSync(
    tmp,
    JSON.stringify({ ...(header || {}), updated: nowISO(), count: numbers.length, numbers }, null, 2)
  );
  fs.renameSync(tmp, file);
}

function nowISO() {
  return new Date().toISOString();
}

// --------------------------------------------------------------------------
// Targets (urls.json)
// --------------------------------------------------------------------------
//
// urls.json holds the pages to monitor. Accepted shapes:
//   { "targets": [ { "id": "x", "label": "X", "url": "https://…", "enabled": true } ] }
//   { "targets": [ "https://a", "https://b" ] }      (or "urls" instead of "targets")
//   [ "https://a", { "url": "https://b" } ]
// A .txt file (one URL per line, # = comment) also works via --urls-file.

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

function writeJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + "\n");
  fs.renameSync(tmp, file);
}

function slugify(s) {
  return String(s)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}

// Folder name for a URL that doesn't name one itself. The short hash keeps two
// different pages on the same host from landing in the same folder.
function autoId(url) {
  let host = String(url);
  try {
    host = new URL(url).hostname.replace(/^www\./, "");
  } catch {}
  const hash = crypto.createHash("sha1").update(String(url)).digest("hex").slice(0, 6);
  return `${slugify(host) || "target"}-${hash}`;
}

function readTargetsFile(file) {
  if (!fs.existsSync(file)) return null;
  if (/\.json$/i.test(file)) {
    const data = readJson(file);
    if (data === null) throw new Error(`${file} is not valid JSON`);
    if (Array.isArray(data)) return data;
    if (Array.isArray(data.targets)) return data.targets;
    if (Array.isArray(data.urls)) return data.urls;
    throw new Error(`${file} needs a "targets" array`);
  }
  return fs
    .readFileSync(file, "utf8")
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith("#"));
}

// Turn raw entries into fully-formed targets with a unique id each. Bad entries
// are reported and skipped rather than killing the run.
function normalizeTargets(entries, source) {
  const targets = [];
  const usedIds = new Set();
  const usedUrls = new Set();
  entries.forEach((entry, i) => {
    const raw = typeof entry === "string" ? { url: entry } : entry || {};
    const url = String(raw.url || "").trim();
    const where = `${source} entry #${i + 1}`;
    if (!url) return console.error(`  ! ${where}: no "url" — skipped`);
    if (!/^https?:\/\//i.test(url))
      return console.error(`  ! ${where}: "${url}" is not an http(s) URL — skipped`);
    if (usedUrls.has(url))
      return console.error(`  ! ${where}: duplicate of an earlier url — skipped`);
    usedUrls.add(url);

    let id = slugify(raw.id || "") || autoId(url);
    if (usedIds.has(id)) {
      let n = 2;
      while (usedIds.has(`${id}-${n}`)) n++;
      id = `${id}-${n}`;
    }
    usedIds.add(id);

    targets.push({
      id,
      label: String(raw.label || raw.name || id),
      url,
      enabled: raw.enabled !== false,
      notes: raw.notes ? String(raw.notes) : "",
    });
  });
  return targets;
}

function loadTargets(cfg) {
  // URLs passed on the command line win, and are not written to urls.json.
  if (cfg.urls.length) return normalizeTargets(cfg.urls, "command line");

  let entries = readTargetsFile(cfg.urlsFile);
  if (entries === null) {
    writeJson(cfg.urlsFile, {
      _readme: "Add one entry per URL to monitor: { id, label, url, enabled, notes }.",
      targets: DEFAULT_URLS.map((url) => ({
        id: autoId(url),
        label: autoId(url),
        url,
        enabled: true,
        notes: "",
      })),
    });
    console.log(`  created ${cfg.urlsFile} — add more URLs there.`);
    entries = readTargetsFile(cfg.urlsFile) || [];
  }
  return normalizeTargets(entries, path.basename(cfg.urlsFile));
}

// --------------------------------------------------------------------------
// Per-URL records — records/<id>/{seen-tfns.json, tfns.log, target.json}
// --------------------------------------------------------------------------
//
// Each URL gets its own folder and its own "seen" set. A number already known
// for one URL still counts as NEW the first time it shows up on another, which
// is the whole point: one URL's numbers never leak into another's record.

function attachRecords(cfg, t) {
  t.dir = path.join(cfg.records, t.id);
  t.storeFile = path.join(t.dir, "seen-tfns.json");
  t.logFile = path.join(t.dir, "tfns.log");
  t.metaFile = path.join(t.dir, "target.json");
  fs.mkdirSync(t.dir, { recursive: true });

  t.seen = loadStore(t.storeFile);
  const meta = readJson(t.metaFile) || {};
  t.checks = Number(meta.checks) || 0;
  t.hits = Number(meta.hits) || 0;
  t.misses = Number(meta.misses) || 0;
  t.firstChecked = meta.firstChecked || null;
  t.lastChecked = meta.lastChecked || null;
  t.lastNew = meta.lastNew || null;
  t.errors = Number(meta.errors) || 0;
  t.lastError = meta.lastError || null;
  t.runChecks = 0; // checks so far this run (t.checks is the lifetime total)
  t.current = []; // number(s) on the page as of the most recent check
  t.newThisRun = [];
  return t;
}

function saveTarget(t) {
  saveStore(t.storeFile, t.seen, { id: t.id, label: t.label, url: t.url });
  writeJson(t.metaFile, {
    id: t.id,
    label: t.label,
    url: t.url,
    enabled: t.enabled,
    notes: t.notes,
    uniqueNumbers: t.seen.size,
    checks: t.checks,
    hits: t.hits,
    misses: t.misses,
    firstChecked: t.firstChecked,
    lastChecked: t.lastChecked,
    lastNew: t.lastNew,
    errors: t.errors,
    lastError: t.lastError,
    currentNumbers: t.current,
  });
}

function shortPath(p) {
  const r = path.relative(__dirname, p);
  return !r || r.startsWith("..") ? p : r;
}

function logDiscovery(file, rec) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(
    file,
    `${rec.firstSeen}\t${rec.pretty}\t${rec.canonical}\t${rec.foundVia}\t${rec.sourceUrl}\n`
  );
}

// records/summary.json — the at-a-glance record of every URL and its numbers.
function writeSummary(cfg, targets) {
  writeJson(path.join(cfg.records, "summary.json"), {
    updated: nowISO(),
    urlsFile: cfg.urlsFile,
    targets: targets.map((t) => ({
      id: t.id,
      label: t.label,
      url: t.url,
      enabled: t.enabled,
      records: t.dir,
      uniqueNumbers: t.seen.size,
      newThisRun: t.newThisRun.length,
      checks: t.checks,
      hits: t.hits,
      misses: t.misses,
      firstChecked: t.firstChecked,
      lastChecked: t.lastChecked,
      lastNew: t.lastNew,
      errors: t.errors,
      lastError: t.lastError,
      currentNumbers: t.current,
      numbers: [...t.seen.values()].map((r) => r.pretty),
    })),
  });
}

// One-time import of the pre-urls.json files, which held every URL's numbers in
// a single store. Records are routed by their own sourceUrl, so nothing is
// attributed to the wrong page; anything that matches no configured URL is left
// where it is. The old files are never modified.
function migrateLegacy(cfg, targets) {
  const marker = path.join(cfg.records, ".migrated");
  if (fs.existsSync(marker)) return;
  fs.mkdirSync(cfg.records, { recursive: true });

  const byUrl = new Map(targets.map((t) => [t.url, t]));
  let numbers = 0;
  let unmatched = 0;
  for (const rec of (readJson(cfg.store) || {}).numbers || []) {
    const t = byUrl.get(rec.sourceUrl);
    if (!t) {
      unmatched++;
      continue;
    }
    if (t.seen.has(rec.canonical)) continue;
    t.seen.set(rec.canonical, rec);
    numbers++;
  }

  // Log lines: tab-separated as firstSeen, pretty, canonical, foundVia, sourceUrl.
  // A number that reached the log but never the old store (an interrupted save)
  // is rebuilt from its own line, so the two old files are imported in full.
  const buckets = new Map();
  try {
    for (const line of fs.readFileSync(cfg.log, "utf8").split(/\r?\n/)) {
      const s = line.trim();
      if (!s) continue;
      const [firstSeen, pretty, canonical, foundVia, sourceUrl] = s
        .split("\t")
        .map((f) => f.trim());
      const t = byUrl.get(sourceUrl);
      if (!t) {
        unmatched++;
        continue;
      }
      if (!buckets.has(t.id)) buckets.set(t.id, []);
      buckets.get(t.id).push(s);
      if (canonical && !t.seen.has(canonical)) {
        t.seen.set(canonical, {
          canonical,
          pretty,
          tollFree: TOLL_FREE.has(canonical.slice(1, 4)),
          firstSeen,
          sourceUrl,
          foundVia,
          target: t.id,
        });
        numbers++;
      }
    }
  } catch {}
  let lines = 0;
  for (const t of targets) {
    const arr = buckets.get(t.id);
    if (!arr || fs.existsSync(t.logFile)) continue; // never double-write a log
    fs.writeFileSync(t.logFile, arr.join("\n") + "\n");
    lines += arr.length;
  }

  for (const t of targets) if (t.seen.size) saveTarget(t);
  fs.writeFileSync(
    marker,
    `${nowISO()}\timported ${numbers} number(s) and ${lines} log line(s) from ` +
      `${cfg.store} / ${cfg.log}; ${unmatched} entr(ies) belonged to no configured url\n`
  );
  if (numbers || lines) {
    console.log(
      `  imported ${numbers} existing number(s) into per-URL records` +
        (unmatched
          ? ` (${unmatched} belonged to no url in urls.json — left in ${path.basename(cfg.store)})`
          : "")
    );
  }
}

// Injected into every frame BEFORE the page's own scripts run. Neutralizes the
// memory/CPU-exhaustion tricks ("browser locker" behavior) these scam pages use
// — popup floods, history spamming, dialog/print loops, reload loops — so simply
// reading the number can't balloon the browser to gigabytes. The legitimate
// reveal (fetch + CryptoJS + an iframe) uses none of these APIs, so it still runs.
function neuterLocker() {
  try {
    const noop = function () {};
    window.open = function () { return null; };
    window.alert = noop;
    window.confirm = function () { return false; };
    window.prompt = function () { return null; };
    window.print = noop;
    window.moveTo = noop; window.resizeTo = noop;
    try { window.history.pushState = noop; } catch (e) {}
    try { window.history.replaceState = noop; } catch (e) {}
    try {
      Object.defineProperty(window.location, "reload", { configurable: true, value: noop });
    } catch (e) {}
  } catch (e) {}
}

// --------------------------------------------------------------------------
// Scan one URL once (one "refresh" in a fresh tab)
// --------------------------------------------------------------------------

async function scanOnce(browser, url, cfg) {
  const results = new Map();
  // A fresh context per refresh == a clean "new tab". If the browser itself has
  // died this throws BrowserClosed, which the caller catches to relaunch.
  const context = await browser.newContext({
    userAgent: UA,
    viewport: { width: 1280, height: 800 },
    ignoreHTTPSErrors: true,
  });

  // Run neuterLocker() first in every page/frame this context creates.
  await context.addInitScript(neuterLocker);

  // Don't download images/media/fonts — we only need text + tel: links, so
  // aborting them cuts memory and bandwidth a lot. Scripts / fetch / XHR (which
  // the reveal + number decryption need) are always allowed through.
  if (cfg.blockAssets) {
    await context.route("**/*", (route) => {
      const t = route.request().resourceType();
      if (t === "image" || t === "media" || t === "font") return route.abort();
      return route.continue();
    });
  }

  const addRecs = (recs, src) => {
    for (const r of recs) {
      if (!results.has(r.canonical)) results.set(r.canonical, { ...r, pageUrl: src });
    }
  };

  const page = await context.newPage();

  // Tabs THIS page pops open (locker popunders / auto-clicked target=_blank) are a
  // memory risk, so scan each one quickly for a number and then close it right
  // away rather than letting it live and load. Nested popups get the same
  // treatment. Using page.on("popup") — NOT context.on("page") — so the main page
  // itself is never treated as a popup and closed.
  const handlePopup = async (p) => {
    try { p.on("popup", handlePopup); } catch {}
    try {
      await p.waitForLoadState("domcontentloaded", { timeout: 2500 }).catch(() => {});
      let src; try { src = p.url(); } catch { src = url; }
      addRecs(await extractFromPage(p, cfg.scanHtml), src);
    } catch {}
    try { if (!p.isClosed()) await p.close(); } catch {}
  };
  page.on("popup", handlePopup);
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: cfg.timeout });
    await page.waitForTimeout(Math.min(cfg.settle, 1200));

    // Trigger the interaction-gated reveal that injects the real content.
    await triggerReveal(page);

    // Poll the main page (incl. its injected iframe) until a number shows up or we
    // hit a SHORT deadline — the less time the hostile page runs, the less memory
    // it can consume before we tear it down.
    const deadline = Date.now() + cfg.settle + 3000;
    do {
      if (!page.isClosed()) {
        try {
          let src; try { src = page.url(); } catch { src = url; }
          addRecs(await extractFromPage(page, cfg.scanHtml), src);
        } catch {
          /* ignore a single bad read */
        }
      }
      if (results.size > 0) break;
      await page.waitForTimeout(400);
    } while (Date.now() < deadline);
  } catch (e) {
    const msg = String(e && e.message ? e.message : e).split("\n")[0];
    process.stdout.write(`  ! load failed: ${msg}\n`);
  } finally {
    // Closing the context tears down the page and any remaining popups at once,
    // releasing this refresh's memory immediately.
    await context.close().catch(() => {});
  }
  return [...results.values()];
}

// --------------------------------------------------------------------------
// Main loop
// --------------------------------------------------------------------------

async function main() {
  const cfg = parseArgs(process.argv);

  console.log("TFN Checker");

  const targets = loadTargets(cfg).map((t) => attachRecords(cfg, t));
  if (targets.length === 0) {
    console.error(`\nNo targets. Add at least one url to ${cfg.urlsFile}.`);
    process.exit(1);
  }
  migrateLegacy(cfg, targets);

  const active = targets.filter((t) => t.enabled);
  if (active.length === 0) {
    console.error(`\nEvery target in ${cfg.urlsFile} is disabled.`);
    process.exit(1);
  }

  // The merged mirror of every URL's numbers. Keyed by number *and* url, so the
  // same number found on two pages stays two distinct rows — nothing merges
  // across URLs here either.
  const combined = cfg.combined
    ? loadStore(cfg.store, (r) => `${r.canonical}|${r.sourceUrl || ""}`)
    : null;

  const pad = Math.min(24, Math.max(...active.map((t) => t.label.length)));
  console.log(
    `  targets : ${active.length} from ${path.basename(cfg.urlsFile)}` +
      (targets.length > active.length ? ` (${targets.length - active.length} disabled)` : "") +
      ", checked in turn"
  );
  for (const t of active) {
    console.log(
      `            \x1b[36m${t.label.padEnd(pad)}\x1b[0m  ${t.url}` +
        `\n            ${" ".repeat(pad)}  \x1b[2m${t.seen.size} known → ${shortPath(t.dir)}\x1b[0m`
    );
  }
  console.log(
    `  method  : ${cfg.method}` +
      (cfg.method !== "browser" ? ` (platform=${cfg.platform})` : "")
  );
  console.log(
    `  refresh : every ${cfg.interval}ms, ` +
      `${cfg.count === Infinity ? "unlimited" : cfg.count} check(s) per URL`
  );
  console.log(`  records : ${cfg.records}`);
  if (combined) console.log(`  mirror  : ${cfg.store} (${combined.size} rows)`);
  console.log("  Press Ctrl+C to stop.\n");

  let stopping = false;

  function shutdown() {
    if (stopping) process.exit(0);
    stopping = true;
    console.log("\n\nStopping…");
    for (const t of targets) saveTarget(t);
    writeSummary(cfg, targets);
    if (combined) saveStore(cfg.store, combined);

    let totalNew = 0;
    console.log("\nThis session, per URL:");
    for (const t of active) {
      totalNew += t.newThisRun.length;
      console.log(
        `  \x1b[36m${t.label.padEnd(pad)}\x1b[0m  ${t.newThisRun.length} new, ` +
          `${t.seen.size} unique total  \x1b[2m${shortPath(t.dir)}\x1b[0m`
      );
      for (const r of t.newThisRun) {
        console.log(`    + ${r.pretty}${r.tollFree ? "  [toll-free]" : ""}`);
      }
    }
    console.log(`\n${totalNew} new number(s) across ${active.length} URL(s).`);
    process.exit(0);
  }
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  const launchBrowser = () =>
    chromium.launch({
      headless: !cfg.headful,
      args: [
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--no-sandbox",
        // trim background memory use
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-sync",
        "--mute-audio",
        "--no-first-run",
      ],
    });

  const isClosedErr = (e) =>
    /closed|crash|disconnect|Target page, context or browser/i.test(
      String(e && e.message ? e.message : e)
    );

  // The browser is launched lazily — in the default "auto"/"decrypt" path it is
  // usually never created at all, which is what keeps memory near zero.
  let browser = null;
  let browserRefreshes = 0; // scans since last (re)launch, for recycling
  let consecutiveCrashes = 0;
  // Set when the browser method turns out to be unusable (Chromium missing, or
  // it keeps crashing). The rotation then carries on decrypt-only rather than
  // ending — a browser problem on one url must not stop the others.
  let browserDown = "";

  async function closeBrowser() {
    if (browser) {
      try { await browser.close(); } catch {}
      browser = null;
    }
  }

  // One refresh via the headless browser, with crash recovery + periodic recycle.
  // Never throws: an unusable browser disables the browser method for the rest
  // of the run instead of ending the run.
  async function browserScan(url) {
    if (!browser || !browser.isConnected()) {
      await closeBrowser();
      try {
        browser = await launchBrowser();
      } catch (e) {
        browserDown = `can't launch Chromium: ${String((e && e.message) || e).split("\n")[0]}`;
        process.stdout.write(`  \x1b[33m! ${browserDown} — carrying on without it.\x1b[0m\n`);
        return [];
      }
      browserRefreshes = 0;
    }
    try {
      const recs = await scanOnce(browser, url, cfg);
      consecutiveCrashes = 0;
      browserRefreshes++;
      if (cfg.recycle > 0 && browserRefreshes >= cfg.recycle) {
        process.stdout.write(
          `\x1b[2m  · recycling browser to free memory (after ${browserRefreshes} refreshes)…\x1b[0m\n`
        );
        await closeBrowser();
      }
      return recs;
    } catch (e) {
      if (isClosedErr(e)) {
        await closeBrowser();
        if (++consecutiveCrashes > 5) {
          browserDown = "browser kept crashing";
          process.stdout.write(`  \x1b[33m! ${browserDown} — carrying on without it.\x1b[0m\n`);
          return [];
        }
        process.stdout.write(
          `\x1b[2m  · browser crashed — will relaunch (${consecutiveCrashes}/5)…\x1b[0m\n`
        );
        return [];
      }
      process.stdout.write(`  ! scan error: ${String(e.message || e).split("\n")[0]}\n`);
      return [];
    }
  }

  const decryptKnown = new Set(); // URLs confirmed to be the decrypt kit

  // One check of one target. Everything here is scoped to that target's own
  // record — its numbers, its counters, its log.
  async function checkTarget(t) {
    const url = t.url;
    t.checks++;
    t.runChecks++;
    t.lastChecked = nowISO();
    if (!t.firstChecked) t.firstChecked = t.lastChecked;
    t.current = [];

    // Prefer the memory-free decrypt method.
    let recs = null;
    let note = "no number found";
    let problem = false;

    if (cfg.method !== "browser") {
      const out = await scanViaDecrypt(url, cfg);
      if (Array.isArray(out)) {
        recs = out;
        decryptKnown.add(url);
      } else if (out && out.unavailable) {
        // The page is gone or unreachable. Record it against this url and move
        // on — it may well be back next cycle, so it keeps its slot.
        recs = [];
        note = out.unavailable;
        problem = true;
        t.errors++;
        t.lastError = { at: t.lastChecked, message: out.unavailable };
      }
    }
    // Still null => decrypt disabled, or the page is up but isn't this kit.
    if (recs === null) {
      if (cfg.method === "decrypt" || decryptKnown.has(url)) {
        // Never render a known-hostile kit in a browser (that's the memory bomb).
        note = decryptKnown.has(url)
          ? "decrypt: temporary miss — will retry"
          : "decrypt: page not recognized (try --method browser)";
        recs = [];
      } else if (browserDown) {
        note = `browser method unavailable (${browserDown})`;
        problem = true;
        recs = [];
      } else {
        recs = await browserScan(url);
      }
    }

    t.current = recs.map((r) => r.pretty);
    if (recs.length === 0) {
      t.misses++;
      const colour = problem ? "\x1b[33m" : "\x1b[2m";
      process.stdout.write(`${colour}[${t.label} #${t.checks}] ${nowISO()}  ${note}\x1b[0m\n`);
    } else {
      t.hits++;
    }

    // Print the number(s) currently on the page every check, so they always show
    // on the terminal. A number never seen *on this url* is highlighted in green
    // as [NEW] and recorded against this url only — a number already known from
    // a different url is still new here.
    for (const r of recs) {
      const tag = r.tollFree ? " [toll-free]" : "";
      if (!t.seen.has(r.canonical)) {
        const rec = {
          canonical: r.canonical,
          pretty: r.pretty,
          tollFree: r.tollFree,
          firstSeen: nowISO(),
          sourceUrl: r.pageUrl || url,
          foundVia: r.source,
          target: t.id,
        };
        t.seen.set(r.canonical, rec);
        t.newThisRun.push(rec);
        t.lastNew = rec.firstSeen;
        console.log(
          `\x1b[1;32m[NEW]\x1b[0m \x1b[36m${t.label}\x1b[0m \x1b[1m${rec.pretty}\x1b[0m${tag}` +
            `   \x1b[2m#${t.seen.size} for this url · via ${rec.foundVia}\x1b[0m`
        );
        logDiscovery(t.logFile, rec);
        if (combined) {
          combined.set(`${rec.canonical}|${rec.sourceUrl}`, rec);
          saveStore(cfg.store, combined);
          logDiscovery(cfg.log, rec);
        }
      } else {
        process.stdout.write(
          `\x1b[2m[${t.label} #${t.checks}] ${nowISO()}  ${r.pretty}${tag}  (already recorded for this url)\x1b[0m\n`
        );
      }
    }
  }

  try {
    // Serial round-robin: one check of url 1, then url 2, … through the last,
    // then back to url 1. A target that fails is logged against itself and the
    // rotation moves straight on to the next one — the cycle never stops for a
    // bad url, and every url keeps its place in the order.
    while (!stopping) {
      for (const t of active) {
        if (stopping) break;

        try {
          await checkTarget(t);
        } catch (e) {
          t.errors++;
          const msg = String((e && e.message) || e).split("\n")[0];
          t.lastError = { at: nowISO(), message: msg };
          process.stdout.write(
            `\x1b[33m[${t.label} #${t.checks}] ${nowISO()}  ! ${msg} — on to the next url\x1b[0m\n`
          );
        }

        // Persisting is best-effort too: a locked or full disk shouldn't end the run.
        try {
          saveTarget(t);
          writeSummary(cfg, targets);
        } catch (e) {
          process.stdout.write(
            `  ! could not write ${t.id} records: ${String((e && e.message) || e).split("\n")[0]}\n`
          );
        }

        // stop once every URL has had `count` checks, if a finite count was given
        if (cfg.count !== Infinity && active.every((x) => x.runChecks >= cfg.count)) {
          stopping = true;
          break;
        }

        if (!stopping) await sleep(cfg.interval);
      }
    }
  } finally {
    await closeBrowser();
  }

  console.log("\nDone.");
  for (const t of active) {
    console.log(
      `  \x1b[36m${t.label.padEnd(pad)}\x1b[0m  ${t.newThisRun.length} new this run, ` +
        `${t.seen.size} unique total  \x1b[2m${shortPath(t.dir)}\x1b[0m`
    );
  }
  for (const t of targets) saveTarget(t);
  writeSummary(cfg, targets);
  if (combined) saveStore(cfg.store, combined);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
