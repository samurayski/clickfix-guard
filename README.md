# ClickFix Guard

A Manifest V3 browser extension that detects ClickFix-style social engineering —
fake CAPTCHA or "human verification" pages that silently write a command to the
clipboard and then instruct the visitor to paste it into Win+R or a terminal —
and warns the user before the command is run.

Works on Chromium-based browsers (Chrome, Edge, Brave).

## Why the browser

Nothing is downloaded in a ClickFix attack and no file lands on disk; the user is
the delivery mechanism. The browser is the last point at which the payload is
still observable. Once the command reaches the Run dialog, the page is out of the
picture.

## Architecture

```
manifest.json
_locales/                        → en, tr message catalogues
icons/idle/                      → neutral toolbar icon (16/32/48/128)
icons/alert/                     → red icon, shown only on the tab that triggered
src/
  detection/indicators.js        → shared keyword/regex list and weights
  detection/default-allowlist.js → seed allowlist shipped with the extension
  content/injected.js            → MAIN world; hooks writeText, write, execCommand('copy')
  content/content.js             → isolated world; scans the DOM via MutationObserver,
                                   scores, renders the banner
  background/service-worker.js   → logs detections to chrome.storage.local,
                                   optional webhook POST
  popup/                         → recent detections
```

### Why one layer isn't enough

**Late DOM injection.** Many ClickFix kits reveal the instructions only after the
fake verification step. A single `document_idle` scan misses this, so `content.js`
keeps a `MutationObserver` running.

**Unicode and obfuscation evasion.** Full-width characters (`Ｗｉｎ+Ｒ`) or
strings split in JavaScript (`"power"+"shell"`) defeat plain matching. The text
layer applies NFKC normalisation and strips zero-width characters; more
importantly, the real command is caught *at the moment it is written to the
clipboard*, which is independent of how the source was obfuscated.

**The strongest signal is behaviour, not text.** No legitimate site silently
writes a PowerShell or bash command to the clipboard on the user's behalf. The
clipboard hook carries far more weight than any text indicator.

### Scoring

`TEXT_PATTERNS` in `indicators.js` and the clipboard hook in `injected.js`
together produce a score. Once it crosses the threshold (default 5) the banner is
shown and the detection is logged and optionally posted to a webhook.

The clipboard signal is graded, not binary:

| Signal | Weight | Fires when |
|---|---|---|
| `clipboard` | 6 | The copied text matches a LOLBin/command keyword |
| `clipboardOpaqueBlob` | 5 | No keyword, but a whitespace-free run of ≥40 base64-alphabet characters — an opaque encoded payload rather than a readable command |
| `clipboardAfterVerifyClick` | 4 | No keyword and no blob shape, but written silently within 800 ms of a click (or Enter/Space) on a control that looks like a verification/CAPTCHA widget |

If none of the three match — a documentation site's "copy the install command"
button, for example — nothing is scored. That is deliberate; scoring it produces
far too many false positives on developer-facing sites.

There is no settings UI. `threshold`, `allowlist` and `webhookUrl` live as
`chrome.storage.local` keys. To push them centrally in a managed fleet, switch
the `chrome.storage.local.get` calls in `content.js` and `service-worker.js` to
`chrome.storage.managed.get` and deliver the values by enterprise policy.

To extend detection, add `{ re, label }` entries to `indicators.js`; `content.js`
does not need to change.

> **A false-positive class worth knowing about.** SHA-1/256/512, MD5 and git
> commit hashes are pure hex, which is a subset of the base64 alphabet — a "copy
> checksum" button used to trip `opaqueBlob` on its own and push the score to the
> threshold in a single step. `HEX_ONLY` in `injected.js` now excludes pure-hex
> strings; real `-EncodedCommand` payloads (UTF-16LE base64, mixed case, `=`
> padding) are still caught. Note that *lowering* the threshold would make this
> worse, not better. When you see a false positive, look at which signal fired
> (the `indicators` list in the popup) and fix the root cause; the threshold is a
> last resort.

## Case study: why the behavioural layer exists

A campaign observed in the wild used a compromised WordPress site as the lure and
fetched the payload from a separate host:

```js
function dc(v, i) { v = atob(v); if (i === 4) return v; return dc(v, i + 1); }
// the encoded command is fetched from the C2, never written to the DOM
var cmd = dc(cmcp, 1);              // four nested atob() calls, decoded at runtime
navigator.clipboard.writeText(cmd)  // only once the "human verification" box is clicked
```

Static text scanning cannot catch this — the command never reaches the visible
DOM or the page source, it is decoded in memory and handed straight to
`writeText()`. Hooking at API level makes the obfuscation irrelevant: whatever
the source looked like, the real decoded string is visible at call time.

The remaining gap was that the decoded command need not contain any keyword from
`SUSPICIOUS` — an attacker using a LOLBin outside the list would slip through.
That is what `clipboardAfterVerifyClick` closes: the verification checkbox and
the "verifying" overlay class flow are a recognisable pattern, so `content.js`
watches clicks and Enter/Space on such controls and scores any silent clipboard
write in the following 800 ms even when the content doesn't match.

`test-pages/level5-keywordless-behavioral.html` reproduces exactly this scenario.

**Residual risk:** `SUSPICIOUS` and `VERIFY_ELEMENT_RE` are still fixed regex
lists. An attacker who both avoids known LOLBin names *and* hides the trigger
behind a control that doesn't look like verification (a plain "Continue" button)
leaves all three clipboard signals silent. What remains is the text layer picking
up instructions elsewhere on the page. Keep all the layers; don't rely on one.

## Indicators covered

- **PowerShell:** `iex` / `Invoke-Expression`, `irm` / `iwr` / `Invoke-RestMethod`, `-EncodedCommand` / `-enc`, `-WindowStyle Hidden`, `-NoProfile`
- **Living-off-the-land binaries:** `mshta`, `certutil`, `bitsadmin`, `wscript`/`cscript`, `regsvr32`, `rundll32`, `forfiles`, `schtasks /create`, `msiexec /i http...`
- **macOS:** `osascript -e`, `curl ... | bash`, `sudo bash -c`, `xattr -c`, `chmod +x`
- **Fake verification wording:** "I'm not a robot", "verify you are human", "press and hold" and Turkish equivalents — low weight on their own, since legitimate challenges use similar wording; the value appears in combination with the clipboard signal
- **General:** `base64 -d`/`--decode`, Run dialog wording in English and Turkish

Deliberately out of scope:

- Text hidden in CSS `::before`/`::after` generated content, which is not part of
  `innerText`. Demonstrated in the level 4 test page.
- Instructions delivered as an image rather than text. OCR over a page screenshot
  would be needed, at a significant performance and privacy cost.

## Toolbar icon

An icon that is permanently red gets tuned out, so there are two sets.
`icons/idle/` is the default on every tab. `icons/alert/` is applied by
`chrome.action.setIcon({ tabId, ... })` only on the tab where the threshold was
crossed, along with a `!` badge.

A `chrome.tabs.onUpdated` listener resets the icon and badge as soon as a tab
*starts* navigating, so a past detection doesn't stay flagged forever. Known
limitation: `history.pushState` navigation inside an SPA doesn't fire
`status: loading`, so the icon can stay red until the next full page load.

## Default allowlist

`src/detection/default-allowlist.js` ships a seed list covering the
highest-false-positive categories. On an allowlisted host the extension does
nothing at all — no scanning, no clipboard listeners, not merely a suppressed
banner.

Categories: AI assistants (the biggest source of false positives, since users
genuinely ask them to write shell commands and the resulting copy button trips
the keyword list), developer documentation, package and code hosting, Q&A
communities, and a few office/productivity hosts.

Deliberately excluded: free and multi-tenant hosting domains — `github.io`,
`pages.dev`, `netlify.app`, `vercel.app`, `sites.google.com`, `notion.site`,
`wordpress.com`, `web.app`, `azurewebsites.net` and similar. These are exactly
what attackers use to put a ClickFix page behind a trustworthy-looking apex
domain. Bare apexes like `google.com` are excluded for the same reason; only
product-specific hosts are listed.

**Treat it as a starting point, not a decision.** Review it before deploying.
Edit the file and repackage for a permanent change, or push an `allowlist` key
via `chrome.storage.managed` to change it centrally without touching the code.

## Install

### From source

1. Open `chrome://extensions` and enable **Developer mode**.
2. **Load unpacked** and select the `clickfix-guard/` folder.
3. Follow `test-pages/README.md` to walk the five levels and confirm the banner
   fires when expected.

### Managed deployment

Publish to the Chrome Web Store with private or domain visibility, then
force-install by ID from the Admin console under
*Devices → Chrome → Apps and extensions → Users and browsers*.

Alternatively, self-host: serve the `.crx` and an update manifest from your own
HTTPS server, add that manifest URL to `manifest.json` as `update_url`, repack
with your own key, and force-install by ID with the custom URL. Note that after
the first install the browser follows the `update_url` baked into the packed
extension, not the one in the policy — point it at a hostname you will keep.

## Defence in depth

A browser extension can delay the user but a determined one can still paste and
run, and an attacker can reword the page to dodge the indicators. Pair it with:

- An EDR/SIEM correlation rule for `explorer.exe → powershell.exe/cmd.exe` with
  `-enc`/`-e`, especially shortly after browser activity.
- PowerShell script block logging, and Constrained Language Mode where feasible.
- The relevant Windows ASR rules, e.g. blocking execution of potentially
  obfuscated scripts.
- A real reporting path behind the banner's advice — a chat button or a ticket —
  rather than advice alone.

Disabling Win+R is generally not worth it; it breaks legitimate workflows, and
visibility is the more sustainable investment.

## Localisation

User-facing strings live in `_locales/`. English is the default; Turkish is
included. To add a language, copy `_locales/en/messages.json` to a new locale
folder and translate the `message` values.

## Licence

MIT. See `LICENSE`.
