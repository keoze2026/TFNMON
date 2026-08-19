# TFN Checker

Checks a TFN / tech-support-scam landing page repeatedly and prints **only the
toll-free "support" numbers it has not seen before**, so a rotating number set can
be harvested for reporting.

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

## Setup

```powershell
npm install          # installs Playwright + downloads Chromium (only needed for the browser fallback)
```

## Usage

```powershell
# Default: decrypt method, no browser, runs until Ctrl+C
node index.js

# Specific URL(s)
node index.js https://kkofuku.mkc1.cdn.digitaloceanspaces.com/index.html

# 20 refreshes, 4 seconds apart
node index.js --count 20 --interval 4000

# Only pull the Windows-platform number (half the bandwidth)
node index.js --platform win

# Force the browser method (e.g. to inspect a page the decrypt method can't read)
node index.js --method browser --headful

# Many targets from a file (one URL per line, # for comments)
node index.js --urls-file targets.txt
```

### Options

| Option            | Default          | Meaning                                                       |
| ----------------- | ---------------- | ------------------------------------------------------------- |
| `[urls...]`       | built-in         | Positional target URLs                                        |
| `--url <u>`       | —                | Add a target URL (repeatable)                                 |
| `--urls-file <f>` | —                | Read target URLs from a file                                  |
| `--method <m>`    | `auto`           | `auto` \| `decrypt` \| `browser`                              |
| `--platform <p>`  | `both`           | Which payload(s) to pull in decrypt mode: `win`\|`mac`\|`both`|
| `--interval <ms>` | `5000`           | Delay between refreshes                                       |
| `--count <n>`     | forever          | Refreshes per URL; `0` = run until Ctrl+C                     |
| `--timeout <ms>`  | `30000`          | Navigation / fetch timeout                                    |
| `--settle <ms>`   | `3000`           | *(browser)* time to let JS render after load                 |
| `--headful`       | off              | *(browser)* show the browser window                          |
| `--scan-html`     | off              | Scan raw HTML too, not just visible text (noisier)           |
| `--load-assets`   | off              | *(browser)* load images/media/fonts (default: blocked)       |
| `--recycle <n>`   | `30`             | *(browser)* relaunch every n refreshes to free memory; `0`=never |
| `--store <f>`     | `seen-tfns.json` | Persistent "already seen" set                                |
| `--log <f>`       | `tfns.log`       | Append-only log of each new discovery                        |

## Output

Every refresh prints the number currently on the page to the terminal:

- A **bright green `[NEW #n]`** line the first time a number is ever seen — this
  is a genuinely new discovery, and it's the only case written to the store/log.
- A **dimmed** line showing the same number with `(already recorded)` when the
  page is still serving a number collected on an earlier refresh or run.
- A dimmed `no number found` line if a refresh returned nothing.

Files:

- `seen-tfns.json`: every unique number ever collected (survives restarts, so a
  number is only ever announced as `[NEW]` once).
- `tfns.log`: tab-separated line per **new** discovery — `timestamp, pretty,
  canonical, source (e.g. decrypt:win), url`.

Delete `seen-tfns.json` to reset — every number then counts as new again.

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
