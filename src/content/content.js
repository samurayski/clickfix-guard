(function () {
  const { WEIGHTS, TEXT_PATTERNS, VERIFY_ELEMENT_RE } = globalThis.__CFG_INDICATORS__;

  let threshold = 5;
  let allowlist = [];
  let score = 0;
  const matched = new Set();
  let bannerShown = false;
  let observer = null;
  let lastVerifyClickAt = 0;
  const VERIFY_CLICK_WINDOW_MS = 800;

  const ZERO_WIDTH_RE = new RegExp("[\\u200B-\\u200D\\uFEFF]", "g");

  function normalize(str) {
    // NFKC folds full-width/homoglyph tricks like "Ｗｉｎ+Ｒ" back to "Win+R",
    // and we strip zero-width chars used to split keywords mid-string.
    return str.normalize("NFKC").replace(ZERO_WIDTH_RE, "");
  }

  function isAllowlisted() {
    return allowlist.some((h) => location.hostname === h || location.hostname.endsWith("." + h));
  }

  function scanText() {
    if (!document.body) return;
    const text = normalize(document.body.innerText || "");
    let added = 0;
    for (const p of TEXT_PATTERNS) {
      if (!matched.has(p.label) && p.re.test(text)) {
        matched.add(p.label);
        added += WEIGHTS.text;
      }
    }
    if (added > 0) {
      score += added;
      evaluate();
    }
  }

  function evaluate() {
    if (!bannerShown && score >= threshold) {
      showBanner();
      report();
    }
  }

  function showBanner() {
    bannerShown = true;
    const el = document.createElement("div");
    el.id = "__clickfix_guard_banner__";
    el.setAttribute(
      "style",
      "position:fixed;top:0;left:0;right:0;z-index:2147483647;" +
        "background:#b91c1c;color:#fff;font:14px/1.4 -apple-system,Segoe UI,sans-serif;" +
        "padding:12px 16px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.3);"
    );
    el.textContent = chrome.i18n.getMessage("bannerWarning");
    const close = document.createElement("button");
    close.textContent = "×";
    close.setAttribute("aria-label", chrome.i18n.getMessage("bannerDismiss"));
    close.setAttribute(
      "style",
      "margin-left:12px;background:none;border:none;color:#fff;font-size:18px;cursor:pointer;vertical-align:middle;"
    );
    close.onclick = () => el.remove();
    el.appendChild(close);
    document.documentElement.appendChild(el);
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

  function looksLikeVerifyControl(el) {
    let node = el;
    for (let depth = 0; node && depth < 4; depth++, node = node.parentElement) {
      const probe = [node.id, node.className, node.getAttribute && node.getAttribute("aria-label"), node.textContent]
        .filter(Boolean)
        .join(" ")
        .slice(0, 200);
      if (VERIFY_ELEMENT_RE.test(probe)) return true;
    }
    return false;
  }

  function addScore(label, weight) {
    if (matched.has(label)) return;
    matched.add(label);
    score += weight;
    evaluate();
  }

  function onClipboardMessage(ev) {
    if (ev.source !== window) return;
    const data = ev.data;
    if (!data || !data.__clickfixGuard) return;
    if (data.type !== "clipboard-write") return;

    const label = "clipboard:" + data.method;
    if (data.keywordMatch) {
      // Content itself names a LOLBin/command — strongest signal, always counts.
      addScore(label + ":keyword", WEIGHTS.clipboard);
      return;
    }
    if (data.opaqueBlob) {
      // Looks like an encoded payload blob even without a readable keyword.
      addScore(label + ":opaque", WEIGHTS.clipboardOpaqueBlob);
      return;
    }
    if (Date.now() - lastVerifyClickAt <= VERIFY_CLICK_WINDOW_MS) {
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

  function onVerifyClick(ev) {
    if (ev.target && looksLikeVerifyControl(ev.target)) lastVerifyClickAt = Date.now();
  }

  function onVerifyKeydown(ev) {
    if ((ev.key === "Enter" || ev.key === " ") && ev.target && looksLikeVerifyControl(ev.target)) {
      lastVerifyClickAt = Date.now();
    }
  }

  function start() {
    // All listeners are registered here (post-allowlist-check) rather than at
    // top level, so an allowlisted domain gets zero instrumentation, not just
    // a suppressed banner.
    document.addEventListener("click", onVerifyClick, true);
    document.addEventListener("keydown", onVerifyKeydown, true);
    window.addEventListener("message", onClipboardMessage);
    scanText();
    observer = new MutationObserver(() => scanText());
    observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  }

  function boot() {
    const defaultAllowlist = globalThis.__CFG_DEFAULT_ALLOWLIST__ || [];
    chrome.storage.local.get({ allowlist: defaultAllowlist, threshold: 5 }, (cfg) => {
      allowlist = cfg.allowlist || [];
      threshold = cfg.threshold || 5;
      if (isAllowlisted()) return;
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", start);
      } else {
        start();
      }
    });
  }

  boot();
})();
