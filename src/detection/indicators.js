// Shared indicator list for ClickFix-style lures. Loaded before content.js
// into the same isolated-world execution context, so this global is visible there.
(function () {
  const WEIGHTS = {
    text: 1,
    clipboard: 6, // clipboard write whose content matches a known LOLBin/command keyword
    clipboardOpaqueBlob: 5, // clipboard write of an opaque base64-looking blob, no keyword needed
    clipboardAfterVerifyClick: 4, // silent clipboard write immediately after a fake-verification click
    captchaUi: 2,
  };

  // Used to recognize "I'm not a robot" / CAPTCHA-style controls by their
  // id/class/aria-label/text, independent of the TEXT_PATTERNS scan below —
  // this correlates a click with a clipboard write that follows it.
  const VERIFY_ELEMENT_RE = /verify|doğrula|robot|human|captcha|human-chk|not.?a.?robot/i;

  const TEXT_PATTERNS = [
    // keyboard shortcuts / OS dialogs that ClickFix lures always name explicitly
    { re: /\bwin(dows)?\s*\+\s*r\b/i, label: "Win+R" },
    { re: /⊞\s*\+?\s*r/i, label: "Win+R (symbol)" },
    { re: /run\s+dialog|çalı[şs]tır\s+penceresi|çalı[şs]tır\s+kutusu/i, label: "Run dialog" },
    { re: /\bctrl\s*\+\s*v\b|⌘\s*\+?\s*v\b|cmd\s*\+\s*v\b/i, label: "Paste shortcut" },
    { re: /\bcmd\s*\+\s*space\b|⌘\s*\+?\s*space\b|spotlight/i, label: "macOS Spotlight" },
    { re: /open\s+(windows\s+)?terminal|terminal(’i|'i|'ı)?\s+aç|uçbirim\s+aç|terminal\.app/i, label: "Open Terminal" },
    { re: /open\s+powershell|powershell(’i|'i)?\s+aç/i, label: "Open PowerShell" },
    { re: /open\s+command\s+prompt|komut\s+istemini?\s+aç/i, label: "Open Command Prompt" },
    { re: /paste\s+(the\s+)?(code|command|text|script)|kodu\s+yapı[şs]tır|komutu\s+yapı[şs]tır/i, label: "Paste instruction" },
    { re: /press\s+enter|enter'?a\s+bas/i, label: "Press Enter" },
    { re: /copy\s+the\s+(code|command|text)\s+below|aşağıdaki\s+kodu\s+kopyala/i, label: "Copy the code below" },

    // fake human-verification wording
    { re: /i'?m\s+not\s+a\s+robot|verify\s+you\s+are\s+human|human\s+verification|robot\s+değilim|insan\s+doğrulama|ek\s+doğrulama\s+gerekli/i, label: "Fake verification wording" },
    { re: /press\s+and\s+hold|basılı\s+tut/i, label: "Press-and-hold captcha" },

    // Windows command substrings
    { re: /\bpowershell\b|\bpwsh\b/i, label: "powershell keyword" },
    { re: /\bmshta\b/i, label: "mshta" },
    { re: /\bcertutil\b/i, label: "certutil" },
    { re: /\bbitsadmin\b/i, label: "bitsadmin" },
    { re: /\b(wscript|cscript)\b/i, label: "wscript/cscript" },
    { re: /\bregsvr32\b/i, label: "regsvr32" },
    { re: /\brundll32\b/i, label: "rundll32" },
    { re: /\biex\b|invoke-expression/i, label: "iex / Invoke-Expression" },
    { re: /invoke-restmethod|\birm\b|\biwr\b/i, label: "irm / iwr" },
    { re: /-enc(odedcommand)?\b/i, label: "-EncodedCommand" },
    { re: /-w(indowstyle)?\s+hidden|-noprofile/i, label: "hidden window flag" },
    { re: /schtasks\s+\/create/i, label: "schtasks /create" },
    { re: /msiexec\s+\/i\s+http/i, label: "remote msiexec" },
    { re: /forfiles\s+\/p/i, label: "forfiles" },

    // cross-platform / macOS
    { re: /curl\.exe|curl\s+(-\w+\s+)*-?s\S*.*\|\s*(bash|sh|zsh)/i, label: "curl pipe shell" },
    { re: /sudo\s+bash|osascript\s+-e/i, label: "macOS shell/osascript" },
    { re: /xattr\s+-c|chmod\s+\+x/i, label: "macOS gatekeeper bypass" },
    { re: /\bbase64\s*(-d|--decode)\b/i, label: "base64 decode" },
  ];

  // Clipboard content analysis. injected.js (MAIN world) only captures the
  // raw string and hands it over; the matching happens here in the isolated
  // world, where the page can't tamper with RegExp/String builtins to blind it.
  const CLIPBOARD_SUSPICIOUS =
    /powershell|pwsh|cmd(\.exe)?\s|mshta|certutil|bitsadmin|wscript|cscript|regsvr32|rundll32|msiexec|msbuild|installutil|regasm|regsvcs|schtasks|forfiles|conhost|explorer\.exe|\biex\b|invoke-expression|invoke-restmethod|\birm\b|\biwr\b|curl(\.exe)?\s|sudo\s|osascript|bash\s+-c|xattr\s+-c|chmod\s+\+x|-enc(odedcommand)?\b|-w(indowstyle)?\s+hidden|-noprofile|base64/i;

  // A long run of base64-alphabet characters with no whitespace looks like an
  // opaque encoded blob rather than a human-typed/readable command — common
  // in "powershell -enc <blob>" style payloads even when no LOLBin keyword
  // survives in the visible portion of the string. This must be judged per
  // whitespace-delimited TOKEN, not by stripping all whitespace from the
  // whole clipboard text first: ordinary prose is many short words, and once
  // every space is removed a long, entirely-plain-letters paragraph (e.g. a
  // translated sentence copied from translate.google.com) collapses into one
  // giant run that also happens to fit the base64 alphabet, even though it
  // has nothing to do with an encoded payload. A genuine blob, in contrast,
  // is written as a single unbroken token to begin with.
  const OPAQUE_BLOB_TOKEN = /^[A-Za-z0-9+/=]{40,}$/;

  // SHA-1/256/512, MD5, git commit SHAs, etc. are pure hex and are a subset
  // of the base64 alphabet, so they'd otherwise match OPAQUE_BLOB_TOKEN — a
  // "copy checksum" button is extremely common and legitimate. Real
  // -EncodedCommand style payloads almost always use letters outside a-f or
  // +/=, so excluding pure-hex strings removes this false-positive class
  // without weakening detection of actual encoded commands.
  const HEX_ONLY = /^[0-9a-fA-F]+$/;

  // Real base64 blobs reliably contain a digit or mix upper/lower case within
  // any run this long — especially -EncodedCommand payloads, which base64
  // whatever is being encoded (frequently UTF-16LE), guaranteeing both.
  // A run of plain letters that long (a long word, a hyphen-free compound, a
  // sentence with the spaces stripped) never does. Requiring this closes the
  // gap the token split alone doesn't: an unusually long single "word".
  function hasDigitOrMixedCase(s) {
    return /[0-9]/.test(s) || (/[a-z]/.test(s) && /[A-Z]/.test(s));
  }

  // Judged per token (see OPAQUE_BLOB_TOKEN above), not across the whole
  // clipboard text.
  function looksLikeOpaqueBlob(text) {
    for (const token of text.split(/\s+/)) {
      if (!OPAQUE_BLOB_TOKEN.test(token)) continue;
      if (HEX_ONLY.test(token)) continue; // checksum / git SHA — legitimate
      if (!hasDigitOrMixedCase(token)) continue; // a long plain-letter word/sentence, not an encoded blob
      return true;
    }
    return false;
  }

  globalThis.__CFG_INDICATORS__ = {
    WEIGHTS,
    TEXT_PATTERNS,
    VERIFY_ELEMENT_RE,
    CLIPBOARD_SUSPICIOUS,
    looksLikeOpaqueBlob,
  };
})();
