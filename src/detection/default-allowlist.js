// Default allowlist for ClickFix Guard. Entries are hostnames — isAllowlisted()
// in content.js matches the hostname itself and any of its subdomains, and
// scanning/hooking is skipped entirely on a match (see content.js `start()`).
//
// This is a SEED list to cut down false positives on sites that legitimately
// show/copy shell-like text (AI coding assistants, dev docs, package
// registries, Q&A sites) — not a guarantee. Review before relying on it, and
// read the "do NOT allowlist" block at the bottom before adding more.
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

  // Intentionally NOT included, on purpose — free/user-content hosting
  // platforms that attackers already abuse to host phishing/ClickFix pages
  // behind a trusted-looking apex domain. Allowlisting these would let an
  // attacker bypass detection just by hosting on them:
  //   github.io, gitlab.io, pages.dev, netlify.app, vercel.app,
  //   sites.google.com, script.google.com, forms.google.com, notion.site,
  //   herokuapp.com, blogspot.com, wordpress.com, weebly.com, wixsite.com,
  //   firebaseapp.com, web.app, azurewebsites.net, s3.amazonaws.com
  // Do not add these (or their parent apex, e.g. plain "google.com") without
  // understanding that anyone can publish a page there.

  globalThis.__CFG_DEFAULT_ALLOWLIST__ = [
    ...AI_ASSISTANTS,
    ...DEV_DOCS,
    ...CODE_HOSTING_AND_PACKAGES,
    ...QA_COMMUNITIES,
    ...PRODUCTIVITY,
  ];
})();
