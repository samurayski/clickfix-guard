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
  detection/indicators.js        → keyword/regex lists, weights, clipboard analysis
  detection/default-allowlist.js → built-in defaults for keys the Admin console doesn't set
  shared/policy-core.js          → Admin console policy → effective policy, allowlist rules
  content/injected.js            → MAIN world; hooks the clipboard APIs, ships raw text
                                   to content.js over a private MessagePort
  content/content.js             → isolated world; scores clipboard + DOM text,
                                   renders the banner
  background/service-worker.js   → applies the Admin console policy, logs
                                   detections, owns all storage writes, webhook
  popup/                         → recent detections, trusted sites, policy source
managed_schema.json              → the settings the Admin console can set
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
| `clipboardOpaqueBlob` | 5 | No keyword, but a single whitespace-free *token* of ≥40 base64-alphabet characters containing a digit or mixed case — an opaque encoded payload rather than a readable command |
| `clipboardAfterVerifyClick` | 4 | No keyword and no blob shape, but written silently within 800 ms of a click (or Enter/Space) on a control that looks like a verification/CAPTCHA widget |

If none of the three match — a documentation site's "copy the install command"
button, for example — nothing is scored. That is deliberate; scoring it produces
far too many false positives on developer-facing sites.

There is no settings UI in the extension. The threshold, the allowlists and the
webhook are set centrally from the Admin console (see
[Central management](#central-management-admin-console)).

To extend detection, add `{ re, label }` entries to `indicators.js`; `content.js`
does not need to change.

> **A false-positive class worth knowing about.** SHA-1/256/512, MD5 and git
> commit hashes are pure hex, which is a subset of the base64 alphabet — a "copy
> checksum" button used to trip `opaqueBlob` on its own and push the score to the
> threshold in a single step. `HEX_ONLY` in `indicators.js` now excludes pure-hex
> strings; real `-EncodedCommand` payloads (UTF-16LE base64, mixed case, `=`
> padding) are still caught. Note that *lowering* the threshold would make this
> worse, not better. When you see a false positive, look at which signal fired
> (the `indicators` list in the popup) and fix the root cause; the threshold is a
> last resort.
>
> **A second one, same signal:** `opaqueBlob` originally stripped *all*
> whitespace from the clipboard text before checking for a ≥40-character
> base64-looking run. That's fine for a single pasted blob, but it also means
> any long plain-English paragraph collapses into one giant letters-only run
> once its spaces are gone — which fits the base64 alphabet just as well as a
> real payload does. Copying a translated sentence on `translate.google.com`
> (or any long-enough prose elsewhere) could trip it with zero relation to an
> encoded command. `looksLikeOpaqueBlob()` in `indicators.js` now judges each
> whitespace-delimited *token* on its own — a real blob is written as one
> unbroken token to begin with, prose never is — and additionally requires a
> digit or mixed case, which every real base64 blob has and a long plain word
> never does. `translate.google.com` / `*.translate.goog` are deliberately
> **not** in the default allowlist despite being a common false-positive
> trigger: Google Translate's proxy domains are a documented ClickFix/phishing
> hosting vector (a lure page rendered through `translate.goog` inherits a
> trusted-looking Google domain), so the fix belongs in the detection logic,
> not in skipping instrumentation on that host.

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
`CLIPBOARD_SUSPICIOUS` — an attacker using a LOLBin outside the list would slip through.
That is what `clipboardAfterVerifyClick` closes: the verification checkbox and
the "verifying" overlay class flow are a recognisable pattern, so `content.js`
watches clicks and Enter/Space on such controls and scores any silent clipboard
write in the following 800 ms even when the content doesn't match.

`test-pages/level5-keywordless-behavioral.html` reproduces exactly this scenario.

**Residual risk:** `CLIPBOARD_SUSPICIOUS` and `VERIFY_ELEMENT_RE` are still fixed regex
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

## When the page knows about the extension

A ClickFix kit that has seen this extension can target it directly, so the
layers are built to survive that, not just to catch the naive case.

**Clipboard hooks (`injected.js`).** Hooks sit on `Clipboard.prototype`,
`Document.prototype.execCommand`, `DataTransfer.prototype.setData` and
`DataTransferItemList.prototype.add` — not on the `navigator.clipboard`
instance, which `Clipboard.prototype.writeText.call(navigator.clipboard, x)`
would simply walk around. Copy-event hijacking ("pastejacking": a `copy`
handler that swaps the data via `event.clipboardData`) is covered. Same-origin
iframes are separate JS realms with their own unhooked prototypes; they are
patched the moment the page reaches into them via `contentWindow` or
`contentDocument`.

`injected.js` shares the page's JS world, so the page can replace any builtin
— `RegExp.prototype.test`, `Array.prototype.push`, `window.postMessage` — to
blind it. Every builtin it needs is therefore captured before any page script
runs, each argument is converted to a string once and that exact string is
what reaches the real API (so a `toString()` that answers differently the
second time can't show us one thing and write another), and **no analysis
happens in the MAIN world**: the raw text goes over a private `MessagePort` to
`content.js`, which matches it in the isolated world where the page can't
touch the regexes. The port is handed over by a handshake that finishes before
any page script can intercept it.

**Banner (`content.js`).** Its contents sit in a closed shadow root — the page
can't query or click its buttons, and "Trust this site" ignores synthetic
clicks regardless (`event.isTrusted`). The host element's inline style is all
`!important`, and a guard puts the banner back if the page removes it, strips
its style/attributes, or stacks an element after it (up to 50 repairs, so two
scripts fighting can't spin forever). The red toolbar badge, set by the
service worker, is outside the page's reach either way.

**Residual risk.** A page that reaches a fresh same-origin iframe via
`window.frames[i]` (rather than `contentWindow`) before Chrome injects the
content scripts into it can still obtain unhooked prototypes; a page that
fights hard enough can cover the banner visually (e.g. with top-layer
elements). A system notification (`chrome.notifications`) would be out of the
page's reach entirely, but adding that permission triggers a permission
prompt that disables a self-hosted extension on update until each user
re-approves it — so it's deliberately not in this version.

## Central management (Admin console)

What is allowlisted, what can never be allowlisted, the score threshold,
whether users may trust sites themselves and the detection webhook are all set
as **Chrome extension policy** — from the Google Admin console, or equally
from Windows GPO/registry, Intune or a macOS configuration profile. Nothing
about it depends on a particular person's account or key: anyone holding the
right admin role can change it, the Admin console keeps an audit trail, and
users can't override it.

Admin console: *Devices → Chrome → Apps & extensions → Users & browsers →*
select the org unit → *ClickFix Guard* → **Policy for extensions**:

```json
{
  "allowlist":      { "Value": ["github.com", "stackoverflow.com"] },
  "neverAllowlist": { "Value": ["pages.dev", "sites.google.com"] },
  "threshold":      { "Value": 5 },
  "allowUserTrust": { "Value": true },
  "webhookUrl":     { "Value": "https://soc.example.com/clickfix" }
}
```

The keys are declared in `managed_schema.json`. Every key is optional: a key
that isn't set falls back to its built-in default (`default-allowlist.js`,
threshold 5, user trust on), and a key that is set **replaces** that default
rather than adding to it. Hostnames are forgiving about case, whitespace, a
leading `*.` or a pasted URL; an entry that still isn't a hostname with at
least two labels (`"com"` would allowlist every `.com` site) is dropped and
listed in the popup, so a typo is visible instead of silently ignored.

Because policy can differ per org unit, the pilot group can have
`allowUserTrust: true` while everyone else has `false`.

**Webhook.** With `webhookUrl` set, the service worker POSTs every detection
there. A Slack incoming webhook (`https://hooks.slack.com/services/...`) gets a
formatted message; any other URL gets the raw JSON
(`url`, `score`, `indicators`, `tabId`, `time`) for a SIEM or HTTP collector.
The page URL in the Slack message is defanged (`hxxps://lure[.]example`) and in
code formatting, and link unfurling is off, so nobody in the channel clicks
through to the lure and Slack's servers don't fetch it. The payload carries no
user identity. The webhook URL is distributed to every managed browser, so
treat it as semi-public: `managed_schema.json` marks it `sensitiveValue`
(masked on `chrome://policy`), but that only deters casual viewing — use a
dedicated channel and rotate the URL if it's abused.

Chrome delivers policy changes to browsers on its own schedule (typically
within a few hours; *Reload policies* on `chrome://policy` forces it on one
machine). The extension applies a change as soon as Chrome delivers it — no
extension update, no restart. The popup shows whether the organization's
settings or the built-in defaults are in effect.

### Allowlist semantics

- **Admin allowlist** (`allowlist`) is authoritative and matches the hostname
  and its subdomains. On an allowlisted host the extension turns itself off —
  no scanning, no scoring.
- **User trust** (the banner's "Trust this site", see below) is exact-hostname
  only, only counts while `allowUserTrust` is `true`, and never applies to a
  host matching `neverAllowlist` — checked against the host being visited, so
  trusting an apex like `google.com` still can't silence `sites.google.com`.
- **`neverAllowlist`** holds free and multi-tenant hosting domains — `github.io`,
  `pages.dev`, `workers.dev`, `netlify.app`, `vercel.app`, `sites.google.com`,
  `translate.goog`, `notion.site`, `web.app`, `azurewebsites.net` and similar.
  These are exactly what attackers use to put a ClickFix page behind a
  trustworthy-looking domain; without this list a lure there could simply tell
  the visitor to click "Trust this site". Bare apexes like `google.com` stay off
  the admin allowlist for the same reason.

### Trusting a site from the banner (pilot)

While `allowUserTrust` is `true`, the banner shows a **"Trust this site"** button
next to ×. It's a bigger action than closing a banner, so:

- a native `confirm()` names the hostname and the consequence first;
- the service worker — not the page's content script — does the write, after
  re-checking the policy against the sender's real URL, and serialises all
  storage writes so two tabs can't overwrite each other's additions;
- it's logged to `allowlistLog` and shown in the popup under **"Manually trusted
  from the banner"**, so a site silenced by a click never becomes invisible.

User entries live in their own `userAllowlist` key. (Up to 0.3.0 they were
merged into one `allowlist` key together with the built-in defaults, which froze
those defaults for that user; 0.4.0 migrates the user-added part over.) Setting
`allowUserTrust` to `false` hides the button everywhere **and** ignores
everything users trusted earlier — the switch for ending the pilot, or for
reviewing `allowlistLog` entries and promoting the legitimate ones to the admin
allowlist.

## Install

### From source

1. Open `chrome://extensions` and enable **Developer mode**.
2. **Load unpacked** and select the `clickfix-guard/` folder.
3. Follow `test-pages/README.md` to walk the six levels and confirm the banner
   fires when expected.

### Managed deployment

Publish to the Chrome Web Store with private or domain visibility, then
force-install by ID from the Admin console under
*Devices → Chrome → Apps and extensions → Users and browsers*, and set its
settings under **Policy for extensions** on the same page (see
[Central management](#central-management-admin-console)).

Alternatively, self-host: serve the `.crx` and an update manifest from your own
HTTPS server, add that manifest URL to `manifest.json` as `update_url`, repack
with your own key, and force-install by ID with the custom URL. Note that after
the first install the browser follows the `update_url` baked into the packed
extension, not the one in the policy — point it at a hostname you will keep
(the `ExtensionSettings` policy's `override_update_url` can redirect it later).

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
