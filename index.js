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
 *   node index.js                                   # default target, runs until Ctrl+C
 *   node index.js https://host/index.html           # one or more URLs as positional args
 *   node index.js --url https://a --url https://b
 *   node index.js --urls-file targets.txt
 *   node index.js --interval 5000 --count 20        # 20 refreshes, 5s apart
 *   node index.js --headful                         # show the browser window
 *
 * Output / state:
 *   seen-tfns.json   persistent set of every unique number ever collected
 *   tfns.log         append-only log line for each newly discovered number
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

Options:
  --url <u>         Add a target URL (repeatable)
  --urls-file <f>   Read target URLs from a file (one per line, # = comment)
  --interval <ms>   Delay between refreshes            (default 5000)
  --count <n>       Refreshes per URL per cycle; 0/Infinity = forever (default forever)
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
  --store <f>       Path to the persistent seen-numbers JSON (default seen-tfns.json)
  --log <f>         Path to the append-only discovery log   (default tfns.log)
  -h, --help        Show this help
`);
}

function parseArgs(argv) {
  const cfg = {
    urls: [],
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
      case "--urls-file": {
        const lines = fs
          .readFileSync(next(), "utf8")
          .split(/\r?\n/)
          .map((s) => s.trim())
          .filter((s) => s && !s.startsWith("#"));
        cfg.urls.push(...lines);
        break;
      }
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
  if (cfg.urls.length === 0) cfg.urls = [...DEFAULT_URLS];
  return cfg;
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

// fetch() text with a timeout.
async function fetchText(url, timeoutMs) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(url, { headers: { "User-Agent": UA }, signal: ac.signal });
    return await res.text();
  } finally {
    clearTimeout(t);
  }
}

// Try to get the number(s) purely by decryption — no browser.
// Returns an array of records, or null if this page doesn't match the known kit
// (so the caller can fall back to the browser method).
async function scanViaDecrypt(url, cfg) {
  let html;
  try {
    html = await fetchText(url, cfg.timeout);
  } catch {
    return null; // network error: let the caller decide
  }
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
      const body = await fetchText(`${origin}${dataPath}?platform=${platform}`, cfg.timeout);
      const { cipher } = JSON.parse(body);
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

function loadStore(file) {
  try {
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    const map = new Map();
    for (const rec of data.numbers || []) map.set(rec.canonical, rec);
    return map;
  } catch {
    return new Map();
  }
}

function saveStore(file, map) {
  const numbers = [...map.values()].sort(
    (a, b) => (a.firstSeen || "").localeCompare(b.firstSeen || "")
  );
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify({ numbers }, null, 2));
  fs.renameSync(tmp, file);
}

function nowISO() {
  return new Date().toISOString();
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
  const seen = loadStore(cfg.store);

  console.log("TFN Checker");
  console.log("  targets :", cfg.urls.join(", "));
  console.log(
    `  method  : ${cfg.method}` +
      (cfg.method !== "browser" ? ` (platform=${cfg.platform})` : "")
  );
  console.log(
    `  refresh : every ${cfg.interval}ms, ` +
      `${cfg.count === Infinity ? "unlimited" : cfg.count} per cycle`
  );
  console.log(`  store   : ${cfg.store} (${seen.size} known)`);
  console.log("  Press Ctrl+C to stop.\n");

  const sessionNew = [];
  let stopping = false;

  function shutdown() {
    if (stopping) process.exit(0);
    stopping = true;
    console.log("\n\nStopping…");
    saveStore(cfg.store, seen);
    console.log(`Session discovered ${sessionNew.length} new number(s):`);
    for (const r of sessionNew) console.log(`  ${r.pretty}${r.tollFree ? "  [toll-free]" : ""}`);
    console.log(`Total unique numbers on record: ${seen.size}`);
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

  async function closeBrowser() {
    if (browser) {
      try { await browser.close(); } catch {}
      browser = null;
    }
  }

  // One refresh via the headless browser, with crash recovery + periodic recycle.
  // Throws only if the browser keeps crashing; otherwise returns records ([]).
  async function browserScan(url) {
    if (!browser || !browser.isConnected()) {
      await closeBrowser();
      browser = await launchBrowser();
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
          process.stdout.write(
            "  ! browser keeps crashing — giving up on the browser method.\n"
          );
          throw e;
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

  let refresh = 0;
  try {
    while (!stopping) {
      for (const url of cfg.urls) {
        if (stopping) break;
        refresh++;

        // Prefer the memory-free decrypt method.
        let recs = null;
        let emptyNote = "no number found";
        if (cfg.method !== "browser") {
          recs = await scanViaDecrypt(url, cfg);
          if (recs !== null) decryptKnown.add(url);
        }
        // null => decrypt disabled, kit unrecognized, or a transient fetch miss.
        if (recs === null) {
          if (cfg.method === "decrypt" || decryptKnown.has(url)) {
            // Never render a known-hostile kit in a browser (that's the memory bomb).
            emptyNote = decryptKnown.has(url)
              ? "decrypt: temporary miss — will retry"
              : "decrypt: page not recognized (try --method browser)";
            recs = [];
          } else {
            try {
              recs = await browserScan(url);
            } catch {
              stopping = true;
              break;
            }
          }
        }

        if (recs.length === 0) {
          process.stdout.write(
            `\x1b[2m[#${refresh}] ${nowISO()}  ${emptyNote}\x1b[0m\n`
          );
        }

        // Print the number(s) currently on the page every refresh, so they always
        // show on the terminal. Numbers never seen before are highlighted in green
        // as [NEW] and recorded; already-recorded ones print dimmed.
        for (const r of recs) {
          const tag = r.tollFree ? " [toll-free]" : "";
          if (!seen.has(r.canonical)) {
            const rec = {
              canonical: r.canonical,
              pretty: r.pretty,
              tollFree: r.tollFree,
              firstSeen: nowISO(),
              sourceUrl: r.pageUrl || url,
              foundVia: r.source,
            };
            seen.set(r.canonical, rec);
            sessionNew.push(rec);
            console.log(
              `\x1b[1;32m[NEW #${sessionNew.length}]\x1b[0m \x1b[1m${rec.pretty}\x1b[0m${tag}` +
                `   via ${rec.foundVia}   ${rec.sourceUrl}`
            );
            fs.appendFileSync(
              cfg.log,
              `${rec.firstSeen}\t${rec.pretty}\t${rec.canonical}\t${rec.foundVia}\t${rec.sourceUrl}\n`
            );
            saveStore(cfg.store, seen);
          } else {
            process.stdout.write(
              `\x1b[2m[#${refresh}] ${nowISO()}  ${r.pretty}${tag}  (already recorded)\x1b[0m\n`
            );
          }
        }

        // stop after `count` refreshes per URL if a finite count was given
        if (cfg.count !== Infinity && refresh >= cfg.count * cfg.urls.length) {
          stopping = true;
          break;
        }

        if (!stopping) await sleep(cfg.interval);
      }
    }
  } finally {
    await closeBrowser();
  }

  console.log(
    `\nDone. ${sessionNew.length} new this run, ${seen.size} unique total.`
  );
  saveStore(cfg.store, seen);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
