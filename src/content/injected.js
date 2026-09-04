// Runs in the page's MAIN world (declared via manifest "world": "MAIN"),
// so it executes before the page's own scripts and can see the real
// clipboard APIs before a lure page has a chance to hide/replace them.
(function () {
  const SUSPICIOUS =
    /powershell|pwsh|cmd(\.exe)?\s|mshta|certutil|bitsadmin|wscript|cscript|regsvr32|rundll32|msiexec|msbuild|installutil|regasm|regsvcs|schtasks|forfiles|conhost|explorer\.exe|\biex\b|invoke-expression|invoke-restmethod|\birm\b|\biwr\b|curl(\.exe)?\s|sudo\s|osascript|bash\s+-c|xattr\s+-c|chmod\s+\+x|-enc(odedcommand)?\b|-w(indowstyle)?\s+hidden|-noprofile|base64/i;

  // A long run of base64-alphabet characters with no whitespace looks like an
  // opaque encoded blob rather than a human-typed/readable command — common
  // in "powershell -enc <blob>" style payloads even when no LOLBin keyword
  // survives in the visible portion of the string.
  const OPAQUE_BLOB = /^[A-Za-z0-9+/=]{40,}$/;

  // SHA-1/256/512, MD5, git commit SHAs, etc. are pure hex and are a subset
  // of the base64 alphabet, so they'd otherwise match OPAQUE_BLOB — a "copy
  // checksum" button is extremely common and legitimate. Real -EncodedCommand
  // style payloads almost always use letters outside a-f or +/=, so excluding
  // pure-hex strings removes this false-positive class without weakening
  // detection of actual encoded commands.
  const HEX_ONLY = /^[0-9a-fA-F]+$/;

  function post(payload) {
    window.postMessage(Object.assign({ __clickfixGuard: true }, payload), "*");
  }

  function inspect(text, method) {
    if (typeof text !== "string" || !text.trim()) return;
    const trimmed = text.trim();
    const keywordMatch = SUSPICIOUS.test(trimmed);
    const cleaned = trimmed.replace(/\s+/g, "");
    const opaqueBlob = !keywordMatch && OPAQUE_BLOB.test(cleaned) && !HEX_ONLY.test(cleaned);
    // Report every clipboard write, not just ones that already match a
    // keyword — content.js correlates non-matching writes with page context
    // (e.g. a fake-verification click) to catch payloads whose LOLBin name
    // never appears in the final decoded string (see the case study in the README).
    post({
      type: "clipboard-write",
      method,
      sample: trimmed.slice(0, 500),
      keywordMatch,
      opaqueBlob,
    });
  }

  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      const orig = navigator.clipboard.writeText.bind(navigator.clipboard);
      navigator.clipboard.writeText = function (text) {
        inspect(text, "clipboard.writeText");
        return orig(text);
      };
    }
    if (navigator.clipboard && navigator.clipboard.write) {
      const origWrite = navigator.clipboard.write.bind(navigator.clipboard);
      navigator.clipboard.write = function (items) {
        try {
          for (const item of items) {
            if (item.types && item.types.includes("text/plain")) {
              item.getType("text/plain").then((blob) => blob.text()).then((t) => inspect(t, "clipboard.write"));
            }
          }
        } catch (e) {}
        return origWrite(items);
      };
    }
    const origExec = document.execCommand.bind(document);
    document.execCommand = function (cmd, ...args) {
      if (String(cmd).toLowerCase() === "copy") {
        let sel = "";
        try {
          sel = window.getSelection ? window.getSelection().toString() : "";
        } catch (e) {}
        // Legacy copy trick: a hidden <textarea>/<input> holds the payload and
        // is selected right before execCommand('copy') is called.
        if (!sel && document.activeElement && "value" in document.activeElement) {
          sel = document.activeElement.value || "";
        }
        inspect(sel, "execCommand.copy");
      }
      return origExec(cmd, ...args);
    };
  } catch (e) {
    // Some pages freeze/override these before we run; fail open (no detection
    // from this layer) rather than break the page.
  }
})();
