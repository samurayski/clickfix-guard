(function () {
  const { WEIGHTS, TEXT_PATTERNS, VERIFY_ELEMENT_RE, CLIPBOARD_SUSPICIOUS, looksLikeOpaqueBlob } =
    globalThis.__CFG_INDICATORS__;
  const POLICY = globalThis.__CFG_POLICY__;

  let policy = POLICY.builtinPolicy();
  let configReady = false;
  let active = true; // false once this host turns out to be allowlisted, or the user trusts it
  let score = 0;
  const matched = new Set();
  let bannerShown = false;
  let observer = null;
  let scanTimer = 0;
  let lastVerifyClickAt = 0;
  const pendingClipboard = [];
  const MAX_PENDING = 200;
  const VERIFY_CLICK_WINDOW_MS = 800;
  const SCAN_INTERVAL_MS = 300;

  const ZERO_WIDTH_RE = new RegExp("[\\u200B-\\u200D\\uFEFF]", "g");

  function normalize(str) {
    // NFKC folds full-width/homoglyph tricks like "Ｗｉｎ+Ｒ" back to "Win+R",
    // and we strip zero-width chars used to split keywords mid-string.
    return str.normalize("NFKC").replace(ZERO_WIDTH_RE, "");
  }

  // ---- set up synchronously at document_start ------------------------------
  //
  // Everything a page could otherwise get in front of is registered here,
  // before any page script runs, instead of after the (async) policy read:
  //  - the private MessagePort to injected.js — see onOffer there;
  //  - click/keydown on window in the capture phase, so a page listener can't
  //    stopPropagation() a verification click before we see it.
  // Until the policy is known, clipboard reports are buffered, not dropped.
  // If the host turns out to be allowlisted, all of it is torn down again.

  // Handshake with injected.js — see onOffer there for why it goes both ways.
  const channels = [];
  const MAX_OFFERS = 4;

  function offerPort() {
    if (channels.length >= MAX_OFFERS) return;
    const ch = new MessageChannel();
    ch.port1.onmessage = (ev) => onClipboardWrite(ev.data);
    channels.push(ch);
    window.postMessage({ __clickfixGuardHandshake: true }, "*", [ch.port2]);
  }

  function onMainReady(ev) {
    if (ev.source !== window || !ev.data || ev.data.__clickfixGuardMainReady !== true) return;
    ev.stopImmediatePropagation();
    offerPort();
  }

  window.addEventListener("message", onMainReady, true);
  offerPort();
  window.addEventListener("click", onVerifyClick, true);
  window.addEventListener("keydown", onVerifyKeydown, true);

  function deactivate() {
    active = false;
    pendingClipboard.length = 0;
    for (const ch of channels) ch.port1.close();
    window.removeEventListener("message", onMainReady, true);
    window.removeEventListener("click", onVerifyClick, true);
    window.removeEventListener("keydown", onVerifyKeydown, true);
    stopScanning();
  }

  // ---- text layer -----------------------------------------------------------

  function scanText() {
    if (!active || bannerShown || !document.body) return;
    const text = normalize(document.body.innerText || "");
    let added = 0;
    for (const p of TEXT_PATTERNS) {
      if (!matched.has(p.label) && p.re.test(text)) {
        matched.add(p.label);
        added += WEIGHTS.text;
      }
    }
    if (TEXT_PATTERNS.every((p) => matched.has(p.label))) stopScanning();
    if (added > 0) {
      score += added;
      evaluate();
    }
  }

  // innerText forces a layout, so re-reading it on every single mutation
  // (a ticking clock, a typing indicator) is expensive on busy pages. Batch
  // mutations into at most one scan per SCAN_INTERVAL_MS. A lure's
  // instructions stay on screen far longer than that, so nothing is missed.
  function scheduleScan() {
    if (scanTimer || !active || bannerShown) return;
    scanTimer = setTimeout(() => {
      scanTimer = 0;
      scanText();
    }, SCAN_INTERVAL_MS);
  }

  function stopScanning() {
    if (observer) observer.disconnect();
    observer = null;
    clearTimeout(scanTimer);
    scanTimer = 0;
  }

  function startScanning() {
    if (!active) return;
    scanText();
    if (bannerShown || !active) return;
    observer = new MutationObserver(scheduleScan);
    observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  }

  // ---- scoring --------------------------------------------------------------

  function addScore(label, weight) {
    if (matched.has(label)) return;
    matched.add(label);
    score += weight;
    evaluate();
  }

  function evaluate() {
    if (!bannerShown && score >= policy.threshold) {
      showBanner();
      report();
    }
  }

  function report() {
    try {
      chrome.runtime.sendMessage({
        type: "clickfix-detection",
        url: location.href,
        score,
        indicators: Array.from(matched),
      });
    } catch (e) {}
  }

  // ---- clipboard layer (reports come from injected.js over the port) --------

  function onClipboardWrite(data) {
    if (!active || !data || typeof data.method !== "string" || typeof data.text !== "string") return;
    const entry = { method: data.method, text: data.text, at: Date.now() };
    if (!configReady) {
      if (pendingClipboard.length < MAX_PENDING) pendingClipboard.push(entry);
      return;
    }
    scoreClipboard(entry);
  }

  function scoreClipboard({ method, text, at }) {
    const trimmed = text.trim();
    if (!trimmed) return;
    const label = "clipboard:" + method;
    if (CLIPBOARD_SUSPICIOUS.test(normalize(trimmed))) {
      // Content itself names a LOLBin/command — strongest signal, always counts.
      addScore(label + ":keyword", WEIGHTS.clipboard);
      return;
    }
    if (looksLikeOpaqueBlob(trimmed)) {
      // Looks like an encoded payload blob even without a readable keyword.
      addScore(label + ":opaque", WEIGHTS.clipboardOpaqueBlob);
      return;
    }
    if (at - lastVerifyClickAt <= VERIFY_CLICK_WINDOW_MS) {
      // No keyword, no visible blob shape — but it was written silently right
      // after clicking something that looks like a CAPTCHA/verification
      // control. Real sites never need to copy anything for that; this is
      // the pattern used by loaders that fetch and decode the payload at
      // runtime so it never touches the DOM.
      addScore(label + ":after-verify-click", WEIGHTS.clipboardAfterVerifyClick);
    }
    // Otherwise: a silent write with no keyword, no blob shape, and no
    // verification-click context (e.g. a legitimate "copy install command"
    // button on a docs site) — intentionally not scored, to keep false
    // positives low on developer-facing sites.
  }

  function looksLikeVerifyControl(el) {
    let node = el;
    for (let depth = 0; node && depth < 4; depth++, node = node.parentElement) {
      const probe = [node.id, node.className, node.getAttribute && node.getAttribute("aria-label"), node.textContent]
        .filter((v) => typeof v === "string" && v)
        .join(" ")
        .slice(0, 200);
      if (VERIFY_ELEMENT_RE.test(probe)) return true;
    }
    return false;
  }

  function onVerifyClick(ev) {
    if (active && ev.target instanceof Element && looksLikeVerifyControl(ev.target)) lastVerifyClickAt = Date.now();
  }

  function onVerifyKeydown(ev) {
    if (!active || (ev.key !== "Enter" && ev.key !== " ")) return;
    if (ev.target instanceof Element && looksLikeVerifyControl(ev.target)) lastVerifyClickAt = Date.now();
  }

  // ---- banner ---------------------------------------------------------------
  //
  // The banner lives in the page's DOM, so the page can see it. It is built to
  // survive a lure that tries to get rid of it:
  //  - its contents sit in a CLOSED shadow root: page scripts can't query or
  //    click the buttons (and the "Trust this site" handler ignores synthetic
  //    clicks anyway — ev.isTrusted), and page CSS can't restyle them;
  //  - the host element's inline style is all !important, so page CSS can't
  //    hide it either;
  //  - a guard observer puts it back if the page removes it, strips its
  //    attributes/style, or stacks another element after it — up to
  //    MAX_REPAIRS times, so two scripts fighting can't spin forever.
  // A page that fights harder can still cover it; the red toolbar badge set
  // by the service worker is outside the page's reach either way.

  const BANNER_HOST_STYLE = [
    "all:initial",
    "display:block",
    "position:fixed",
    "top:0",
    "left:0",
    "right:0",
    "margin:0",
    "z-index:2147483647",
    "visibility:visible",
    "opacity:1",
    "pointer-events:auto",
    "transform:none",
    "filter:none",
    "clip-path:none",
  ]
    .map((d) => d + " !important")
    .join(";");

  const BANNER_CSS =
    ".bar{background:#b91c1c;color:#fff;font:14px/1.4 -apple-system,'Segoe UI',sans-serif;" +
    "padding:12px 16px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.3)}" +
    "button{font:inherit;color:#fff;background:none;cursor:pointer;vertical-align:middle}" +
    ".trust{margin-left:16px;border:1px solid #fff;border-radius:4px;font-size:12px;padding:3px 10px}" +
    ".close{margin-left:12px;border:none;font-size:18px;line-height:1}" +
    ".status{display:block;margin-top:6px;font-size:12px}";

  const MAX_REPAIRS = 50;
  let bannerHost = null;
  let bannerGuard = null;

  function showBanner() {
    bannerShown = true;
    stopScanning();

    const hostEl = document.createElement("div");
    hostEl.setAttribute("style", BANNER_HOST_STYLE);
    const root = hostEl.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = BANNER_CSS;
    const bar = document.createElement("div");
    bar.className = "bar";
    bar.setAttribute("role", "alert");
    bar.append(chrome.i18n.getMessage("bannerWarning"));

    const status = document.createElement("span");
    status.className = "status";

    // Lets the user silence a confirmed false positive at the source during
    // the pilot. Hidden when the Admin console policy switches user trust off or
    // the host is on neverAllowlist (a lure hosted on e.g. pages.dev could
    // otherwise just tell the visitor to click it). Gated behind a native
    // confirm() — one misclick here silences this hostname for good.
    if (POLICY.canUserTrust(location.hostname, policy)) {
      const trust = document.createElement("button");
      trust.className = "trust";
      trust.textContent = chrome.i18n.getMessage("bannerAllowlistButton");
      trust.addEventListener("click", (ev) => {
        if (ev.isTrusted) requestTrust(trust, status);
      });
      bar.appendChild(trust);
    }

    const close = document.createElement("button");
    close.className = "close";
    close.textContent = "×";
    close.setAttribute("aria-label", chrome.i18n.getMessage("bannerDismiss"));
    close.addEventListener("click", (ev) => {
      if (ev.isTrusted) dismissBanner();
    });
    bar.appendChild(close);
    bar.appendChild(status);
    root.append(style, bar);

    bannerHost = hostEl;
    document.documentElement.appendChild(hostEl);
    guardBanner(hostEl);
  }

  function guardBanner(hostEl) {
    let repairs = 0;
    bannerGuard = new MutationObserver(() => {
      if (bannerHost !== hostEl) return;
      const root = document.documentElement;
      let broken = false;
      for (const attr of Array.from(hostEl.attributes)) {
        if (attr.name !== "style") {
          hostEl.removeAttribute(attr.name); // hidden, inert, popover...
          broken = true;
        }
      }
      if (hostEl.getAttribute("style") !== BANNER_HOST_STYLE) {
        hostEl.setAttribute("style", BANNER_HOST_STYLE);
        broken = true;
      }
      if (hostEl.parentNode !== root || root.lastElementChild !== hostEl) {
        root.appendChild(hostEl);
        broken = true;
      }
      if (broken && ++repairs >= MAX_REPAIRS) bannerGuard.disconnect();
    });
    bannerGuard.observe(document.documentElement, { childList: true });
    bannerGuard.observe(hostEl, { attributes: true });
  }

  function dismissBanner() {
    if (bannerGuard) bannerGuard.disconnect();
    bannerGuard = null;
    if (bannerHost) bannerHost.remove();
    bannerHost = null;
  }

  function requestTrust(button, status) {
    const host = location.hostname;
    if (!window.confirm(chrome.i18n.getMessage("bannerAllowlistConfirm", [host]))) return;
    button.disabled = true;
    // The service worker does the write (and re-checks the policy against the
    // sender's real URL) so concurrent tabs can't overwrite each other's
    // additions — see handleAllowlistAdd there.
    chrome.runtime.sendMessage(
      { type: "clickfix-allowlist-add", score, indicators: Array.from(matched) },
      (res) => {
        if (chrome.runtime.lastError || !res || !res.ok) {
          status.textContent = chrome.i18n.getMessage("bannerAllowlistRejected");
          return;
        }
        status.textContent = chrome.i18n.getMessage("bannerAllowlistAdded", [host]);
        deactivate();
        setTimeout(dismissBanner, 2500);
      }
    );
  }

  // ---- boot -----------------------------------------------------------------

  function boot() {
    chrome.storage.local.get({ policy: null, userAllowlist: [] }, (cfg) => {
      // Written by the service worker from the Admin console policy (see
      // syncManagedPolicy there); checked here only as a guard against a
      // corrupt entry.
      policy = POLICY.sanitizeStoredPolicy(cfg.policy) || POLICY.builtinPolicy();
      if (POLICY.isHostAllowlisted(location.hostname, policy, cfg.userAllowlist)) {
        deactivate();
        return;
      }
      configReady = true;
      for (const entry of pendingClipboard.splice(0)) scoreClipboard(entry);
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", startScanning);
      } else {
        startScanning();
      }
    });
  }

  boot();
})();
