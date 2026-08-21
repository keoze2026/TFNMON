# TFN Checker

Checks a list of TFN / tech-support-scam landing pages repeatedly and prints
**only the toll-free "support" numbers it has not seen before**, so a rotating
number set can be harvested for reporting. Every URL in `urls.json` is monitored
in turn, and each keeps its own separate record.

Built for defensive / threat-intelligence work: these pages (e.g.
`*.cdn.digitaloceanspaces.com/index.html`) rotate the phone number they display on
every load. This tool collects those rotating numbers.

## Two methods

The page hides its real content inside an **AES-encrypted blob** that its
JavaScript fetches and injects into an iframe. The decrypted payload is a
"browser locker" that deliberately eats memory/CPU — rendering it in a real
browser balloons RAM to **10 GB+**.

So the tool has two extraction methods, chosen with `--method`:

| Method             | Browser? | Memory   | How it gets the number                                                   |
| ------------------ | -------- | -------- | ------------------------------------------------------------------------ |
| **decrypt** *(default)* | no  | ~200 MB  | Replicates the page's AES step in Node and reads the number from the decrypted HTML's *visible text*. The hostile code never runs. |
| **browser**        | yes      | multi-GB | Renders in a locked-down headless Chromium, neuters the memory bombs, triggers the reveal, reads the iframe. Fallback for pages that don't match the decrypt scheme. |

`--method auto` (the default) tries **decrypt** first and only falls back to
**browser** for a page it doesn't recognise — and once a URL is confirmed as a
decrypt kit, it will never be rendered in a browser (so it can't blow up memory).

## Targets — `urls.json`

`node index.js` monitors **every URL listed in `urls.json`**, one at a time, in a
serial round-robin: check url 1, wait `--interval`, check url 2, then url 3, on
through the last one, then back to url 1. Add as many as you like. A url that
fails is skipped, not dropped — it keeps its place in the rotation.

```json
{
  "targets": [
    {
      "id": "kkofuku",
      "label": "kkofuku",
      "url": "https://kkofuku.mkc1.cdn.digitaloceanspaces.com/index.html",
      "enabled": true,
      "notes": "original default target"
    },
    { "id": "subroutine", "url": "https://subroutine.lon1.cdn.digitaloceanspaces.com/index.html", "enabled": false }
  ]
}
```

| Field     | Required | Meaning                                                             |
| --------- | -------- | ------------------------------------------------------------------- |
| `url`     | yes      | The page to check                                                   |
| `id`      | no       | Folder name under `records/` — defaults to `host-<hash>`            |
| `label`   | no       | Name shown in the terminal — defaults to `id`                       |
| `enabled` | no       | `false` keeps the entry (and its records) but skips checking it     |
| `notes`   | no       | Free-form, for your own reference                                   |

A bare list of strings works too: `{ "targets": ["https://a", "https://b"] }`.
The file is created with the built-in default target the first time you run
without one. Passing URLs on the command line (`node index.js https://…`, or
`--url`) overrides `urls.json` for that run without changing the file.

## Records — one folder per URL

Each URL keeps its **own** record folder, so numbers are never mixed between
targets. A number already known for url A still counts as a fresh `[NEW]` the
first time it appears on url B, and is recorded against B only.

```
records/
  summary.json          every url and its numbers, at a glance
  <id>/
    seen-tfns.json      every number ever seen on THAT url
    tfns.log            tab-separated discovery log for THAT url
    target.json         that url's status: checks, hits, misses, last seen
```

`seen-tfns.json` and `tfns.log` in the project root are still written as a
**merged mirror** across all URLs (each row carries its own `sourceUrl`). They
are convenience copies — the per-URL folders are authoritative. Use
`--no-combined` to skip them.

If you already had a root `seen-tfns.json` / `tfns.log` from before `urls.json`
existed, the first run imports them into the per-URL folders, routing every
record by its own `sourceUrl` so nothing lands under the wrong page. The old
files are left untouched, and the import runs once (tracked by `records/.migrated`).

To reset one URL only, delete its folder under `records/`.

### When a URL fails

A URL that 404s, refuses the connection, times out, or crashes the browser is
reported and skipped — **the rotation moves straight on to the next URL, and the
failing one keeps its place in the order**, so it is tried again next cycle
(these kits come and go). Nothing that happens to one URL can end the run:

- Dead or unreachable pages print a yellow `http 404` / `unreachable: …` line,
  counted in that URL's own `errors` and `lastError` in `target.json`.
- A page that is *gone* is not retried in the browser (only a page that loads but
  isn't a recognised kit is), so a dead URL costs a fraction of a second per
  cycle instead of a full browser launch.
- If Chromium can't launch, or keeps crashing, the browser method switches off
  for the rest of the run and the cycle carries on decrypt-only.
- A record file that can't be written is reported, and the cycle continues.

Only Ctrl+C — or `--count` being reached on every URL — stops the run.

## Setup

```powershell
npm install          # installs Playwright + downloads Chromium (only needed for the browser fallback)
```

## Usage

```powershell
# Default: every url in urls.json, in turn, until Ctrl+C
node index.js

# Ad-hoc URL(s) for this run only (ignores urls.json)
node index.js https://kkofuku.mkc1.cdn.digitaloceanspaces.com/index.html

# 20 checks per url, 4 seconds apart
node index.js --count 20 --interval 4000

# Only pull the Windows-platform number (half the bandwidth)
node index.js --platform win

# Force the browser method (e.g. to inspect a page the decrypt method can't read)
node index.js --method browser --headful

# A different targets file (.json like urls.json, or .txt one URL per line)
node index.js --urls-file targets.txt
```

### Options

| Option            | Default          | Meaning                                                       |
| ----------------- | ---------------- | ------------------------------------------------------------- |
| `[urls...]`       | `urls.json`      | Positional target URLs for this run (ignores `urls.json`)     |
| `--url <u>`       | —                | Same, repeatable                                              |
| `--urls-file <f>` | `urls.json`      | Targets file: `.json` like `urls.json`, or `.txt` one per line|
| `--records <dir>` | `records/`       | Where the per-URL record folders live                         |
| `--no-combined`   | off              | Don't write the merged root `seen-tfns.json` / `tfns.log`     |
| `--method <m>`    | `auto`           | `auto` \| `decrypt` \| `browser`                              |
| `--platform <p>`  | `both`           | Which payload(s) to pull in decrypt mode: `win`\|`mac`\|`both`|
| `--interval <ms>` | `5000`           | Delay between refreshes                                       |
| `--count <n>`     | forever          | Checks per URL; `0` = run until Ctrl+C                        |
| `--timeout <ms>`  | `30000`          | Navigation / fetch timeout                                    |
| `--settle <ms>`   | `3000`           | *(browser)* time to let JS render after load                 |
| `--headful`       | off              | *(browser)* show the browser window                          |
| `--scan-html`     | off              | Scan raw HTML too, not just visible text (noisier)           |
| `--load-assets`   | off              | *(browser)* load images/media/fonts (default: blocked)       |
| `--recycle <n>`   | `30`             | *(browser)* relaunch every n refreshes to free memory; `0`=never |
| `--store <f>`     | `seen-tfns.json` | Merged all-URL mirror of the numbers                         |
| `--log <f>`       | `tfns.log`       | Merged all-URL discovery log                                 |

## Output

Every check prints the number currently on that page, tagged with the URL's
label:

- A **bright green `[NEW]`** line the first time a number is seen **on that
  URL** — a genuinely new discovery for that page, and the only case written to
  the store/log.
- A **dimmed** line with `(already recorded for this url)` when the page is
  still serving a number collected on an earlier check or run.
- A dimmed `no number found` line if a check returned nothing.
- A **yellow** line if that URL failed (`http 404`, `unreachable: …`) — the
  cycle carries straight on to the next URL.

On Ctrl+C (or when `--count` is reached) it prints a per-URL summary of what the
session found.

Each discovery is written to that URL's own `records/<id>/seen-tfns.json` and
`records/<id>/tfns.log` (tab-separated: `timestamp, pretty, canonical, source
(e.g. decrypt:win), url`), and mirrored into the merged root files.

Delete `records/<id>/` to reset a single URL, or the whole `records/` folder to
reset everything — every number then counts as new again.

## Why the decrypt method is accurate

The 3 MB decrypted payload is padded with **decoy digit-runs** that look like
phone numbers but aren't — e.g. `999-999-9999` inside a CSS `z-index:
9999999999999`, or a fake number buried in a base64 image. The tool strips
scripts, styles, comments and base64 blobs and reads only the **visible text**,
which leaves exactly the number a visitor would be told to call.

## Note

This makes real requests to the target (and, in decrypt mode, to the backend that
serves the encrypted payload) on each refresh. Keep `--interval` reasonable and
only point it at pages you are authorized to investigate.
