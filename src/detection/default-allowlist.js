// Built-in policy defaults for ClickFix Guard. Entries are hostnames; an
// allowlist entry matches the hostname itself and any of its subdomains, and
// scanning is skipped entirely on a match (see policy-core.js / content.js).
//
// The organization's Admin console lists are added to these (see policy-core.js
// and "Central management" in the README), and can take individual entries
// out with removeFromBuiltin. The allowlist is a SEED list to cut
// down false positives on sites that legitimately show/copy shell-like text
// (AI coding assistants, dev docs, package registries, Q&A sites) — not a
// guarantee. Read the NEVER_ALLOWLIST block at the bottom before adding more.
(function () {
  // Vendor apexes (openai.com, anthropic.com, claude.com) cover their own
  // docs/consoles too — e.g. code.claude.com's install page, whose
  // "curl … | bash" copy button was a reported false positive. Only the
  // vendors' own hosts: generated previews and shared artifacts run in
  // iframes on separate user-content domains (claudeusercontent.com etc.),
  // which stay scanned — anyone can publish content there.
  const AI_ASSISTANTS = [
    "chatgpt.com",
    "openai.com",
    "claude.ai",
    "claude.com",
    "anthropic.com",
    "gemini.google.com",
    "aistudio.google.com",
    "ai.google.dev",
    "copilot.microsoft.com",
    "m365.cloud.microsoft",
    "chat.deepseek.com",
    "chat.mistral.ai",
    "grok.com",
    "huggingface.co",
    "perplexity.ai",
    "poe.com",
    "you.com",
  ];

  // Translation tools copy back whatever the user put in — translate an IT
  // article and the "copy translation" button writes a PowerShell command to
  // the clipboard, exactly like a lure. translate.goog (Google's proxy for
  // translated third-party SITES) is on NEVER_ALLOWLIST instead.
  const TRANSLATION = ["translate.google.com", "deepl.com"];

  const DEV_DOCS = [
    "developer.mozilla.org",
    "learn.microsoft.com",
    "docs.microsoft.com",
    "cloud.google.com",
    "docs.aws.amazon.com",
    "kubernetes.io",
    "developer.hashicorp.com",
    "docs.docker.com",
    "redis.io",
    "postgresql.org",
    "nodejs.org",
    "go.dev",
    "docs.python.org",
    "doc.rust-lang.org",
    "developer.apple.com",
  ];

  const CODE_HOSTING_AND_PACKAGES = [
    "github.com",
    "gitlab.com",
    "npmjs.com",
    "pypi.org",
    "packagist.org",
    "rubygems.org",
    "crates.io",
    "hub.docker.com",
    "readthedocs.io",
  ];

  const QA_COMMUNITIES = ["stackoverflow.com", "superuser.com", "serverfault.com", "askubuntu.com"];

  // Single-tenant-style product domains with no general-purpose user content
  // hosting on these exact hosts — lower risk than the "do NOT allowlist"
  // category below.
  const PRODUCTIVITY = ["office.com", "outlook.com", "teams.microsoft.com", "slack.com", "zoom.us"];

  // Free/user-content hosting platforms that attackers already abuse to host
  // phishing/ClickFix pages behind a trusted-looking apex domain. This list is
  // enforced, and it wins over the allowlists (see isHostAllowlisted in
  // policy-core.js): a host here is scanned even if an admin allowlists a
  // broader entry like "google.com", and the banner's "Trust this site"
  // button is hidden on it — otherwise a lure hosted here could simply tell
  // the visitor to click it and silence itself. The Admin console can add to
  // this list (neverAllowlist) or take entries out (removeFromBuiltin).
  const NEVER_ALLOWLIST = [
    // user content served by AI tools: shared artifacts, generated previews, Spaces
    "claudeusercontent.com",
    "oaiusercontent.com",
    "usercontent.goog",
    "hf.space",
    "github.io",
    "gitlab.io",
    "pages.dev",
    "workers.dev",
    "r2.dev",
    "trycloudflare.com",
    "netlify.app",
    "vercel.app",
    "sites.google.com",
    "script.google.com",
    "forms.google.com",
    "googleusercontent.com",
    "translate.goog",
    "storage.googleapis.com",
    "appspot.com",
    "firebaseapp.com",
    "web.app",
    "notion.site",
    "herokuapp.com",
    "onrender.com",
    "glitch.me",
    "replit.app",
    "surge.sh",
    "ngrok.io",
    "ngrok-free.app",
    "blogspot.com",
    "wordpress.com",
    "weebly.com",
    "wixsite.com",
    "azurewebsites.net",
    "blob.core.windows.net",
    "s3.amazonaws.com",
  ];
  // Allowlisting one of these (or a parent like plain "google.com") has no
  // effect on the hosts listed here; take a host off this list only with the
  // understanding that anyone can publish a page there.

  globalThis.__CFG_DEFAULT_ALLOWLIST__ = [
    ...AI_ASSISTANTS,
    ...TRANSLATION,
    ...DEV_DOCS,
    ...CODE_HOSTING_AND_PACKAGES,
    ...QA_COMMUNITIES,
    ...PRODUCTIVITY,
  ];
  globalThis.__CFG_DEFAULT_NEVER_ALLOWLIST__ = NEVER_ALLOWLIST;
})();
