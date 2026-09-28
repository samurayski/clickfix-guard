// Built-in policy defaults for ClickFix Guard. Entries are hostnames; an
// allowlist entry matches the hostname itself and any of its subdomains, and
// scanning is skipped entirely on a match (see policy-core.js / content.js).
//
// These apply for every key the organization hasn't set in the Admin console
// (see policy-core.js and "Central management" in the README); a key set
// there replaces the list here. The allowlist is a SEED list to cut
// down false positives on sites that legitimately show/copy shell-like text
// (AI coding assistants, dev docs, package registries, Q&A sites) — not a
// guarantee. Read the NEVER_ALLOWLIST block at the bottom before adding more.
(function () {
  const AI_ASSISTANTS = [
    "chat.openai.com",
    "chatgpt.com",
    "platform.openai.com",
    "claude.ai",
    "console.anthropic.com",
    "docs.anthropic.com",
    "gemini.google.com",
    "copilot.microsoft.com",
    "huggingface.co",
    "perplexity.ai",
    "poe.com",
    "you.com",
  ];

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
  // phishing/ClickFix pages behind a trusted-looking apex domain. These are
  // never on the allowlist, and — unlike the list above, which only seeds
  // the built-in defaults — this one is also enforced: the banner's "Trust
  // this site" button is hidden on them and a user-added entry that matches
  // one is ignored (see policy-core.js). Otherwise a lure hosted here could
  // simply tell the visitor to click "Trust this site" and silence itself.
  // The Admin console can replace this list (neverAllowlist).
  const NEVER_ALLOWLIST = [
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
  // Do not add these (or their parent apex, e.g. plain "google.com") to the
  // allowlist without understanding that anyone can publish a page there.

  globalThis.__CFG_DEFAULT_ALLOWLIST__ = [
    ...AI_ASSISTANTS,
    ...DEV_DOCS,
    ...CODE_HOSTING_AND_PACKAGES,
    ...QA_COMMUNITIES,
    ...PRODUCTIVITY,
  ];
  globalThis.__CFG_DEFAULT_NEVER_ALLOWLIST__ = NEVER_ALLOWLIST;
})();
