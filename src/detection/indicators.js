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

  globalThis.__CFG_INDICATORS__ = { WEIGHTS, TEXT_PATTERNS, VERIFY_ELEMENT_RE };
})();
