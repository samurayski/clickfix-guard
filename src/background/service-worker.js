importScripts("../detection/default-allowlist.js", "../shared/policy-core.js");

const POLICY = globalThis.__CFG_POLICY__;

const ICONS = {
  idle: { 16: "icons/idle/icon16.png", 32: "icons/idle/icon32.png", 48: "icons/idle/icon48.png" },
  alert: { 16: "icons/alert/icon16.png", 32: "icons/alert/icon32.png", 48: "icons/alert/icon48.png" },
};

const MAX_LOG = 200;
const MAX_USER_ALLOWLIST = 500;

// ---- serialized storage writes -----------------------------------------------
//
// Every read-modify-write of chrome.storage.local goes through this queue. The
// service worker is the only writer of these keys, so this is what stops two
// tabs (or a detection and a policy sync) from reading the same old value
// and one of them silently overwriting the other's change.

let storageQueue = Promise.resolve();

function withStorageLock(fn) {
  const run = storageQueue.then(() => fn());
  storageQueue = run.catch(() => {});
  return run;
}

// ---- policy from the Admin console -------------------------------------------
//
// The organization sets the policy as Chrome extension policy (Admin console
// → Apps & extensions → this extension → "Policy for extensions", or GPO/MDM),
// which Chrome exposes as the read-only chrome.storage.managed area. It is
// turned into the effective policy here and stored as `policy` in
// chrome.storage.local for the content scripts. Chrome fires
// storage.onChanged for the "managed" area whenever the admin changes it, so
// new values apply without an extension update. With nothing configured (an
// unmanaged browser) the built-in defaults apply.

async function readManaged() {
  try {
    return (await chrome.storage.managed.get(null)) || {};
  } catch (e) {
    return {};
  }
}

async function syncManagedPolicy() {
  const policy = POLICY.policyFromManaged(await readManaged());
  await withStorageLock(() => chrome.storage.local.set({ policy }));
}

// Up to 0.3.0 a single `allowlist` key held the built-in defaults merged with
// whatever the banner button added (and froze the defaults at that moment), plus
// a `threshold` key. Keep only what users added; everything else now comes from
// the policy.
async function migrateLegacyStorage() {
  await withStorageLock(async () => {
    const { allowlist, userAllowlist } = await chrome.storage.local.get({ allowlist: null, userAllowlist: [] });
    if (!Array.isArray(allowlist)) return;
    const builtin = new Set(globalThis.__CFG_DEFAULT_ALLOWLIST__ || []);
    // User entries are exact-host matches (see isHostAllowlisted), so unlike
    // admin entries they don't need the two-label rule — "localhost" is fine.
    const added = allowlist.filter((h) => typeof h === "string" && h && !builtin.has(h) && !userAllowlist.includes(h));
    await chrome.storage.local.set({ userAllowlist: userAllowlist.concat(added).slice(-MAX_USER_ALLOWLIST) });
    await chrome.storage.local.remove(["allowlist", "threshold"]);
  });
}

chrome.runtime.onInstalled.addListener(() => {
  migrateLegacyStorage().finally(syncManagedPolicy);
});
chrome.runtime.onStartup.addListener(syncManagedPolicy);
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "managed") syncManagedPolicy();
});

// ---- messages from content scripts ---------------------------------------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || sender.id !== chrome.runtime.id) return;

  if (msg.type === "clickfix-detection") {
    handleDetection(msg, sender);
    return;
  }

  if (msg.type === "clickfix-allowlist-add") {
    handleAllowlistAdd(msg, sender).then(sendResponse, (e) =>
      sendResponse({ ok: false, error: String((e && e.message) || e) })
    );
    return true; // async sendResponse
  }
});

function handleDetection(msg, sender) {
  const entry = {
    url: msg.url,
    score: msg.score,
    indicators: msg.indicators,
    tabId: sender.tab ? sender.tab.id : null,
    time: Date.now(),
  };

  withStorageLock(async () => {
    const { log } = await chrome.storage.local.get({ log: [] });
    await chrome.storage.local.set({ log: log.concat([entry]).slice(-MAX_LOG) });
  });

  postWebhook(entry);

  if (sender.tab && sender.tab.id != null) {
    // The toolbar icon stays neutral (icons/idle) at rest — only the tab that
    // actually triggered a detection flips to the red alert icon, so the
    // icon isn't a permanent "something's wrong" signal that gets tuned out.
    chrome.action.setIcon({ tabId: sender.tab.id, path: ICONS.alert });
    chrome.action.setBadgeText({ tabId: sender.tab.id, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: "#b91c1c" });
  }
}

// The Admin console's webhookUrl (HTTPS only) wins over the older local
// `webhookUrl` storage key.
async function postWebhook(entry) {
  const managed = await readManaged();
  let url = "";
  if (typeof managed.webhookUrl === "string" && /^https:\/\//i.test(managed.webhookUrl)) {
    url = managed.webhookUrl;
  } else {
    url = (await chrome.storage.local.get({ webhookUrl: "" })).webhookUrl;
  }
  if (!url) return;
  fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(SLACK_INCOMING_WEBHOOK_RE.test(url) ? slackMessage(entry) : entry),
  }).catch(() => {});
}

// Slack incoming webhooks reject arbitrary JSON (a message needs `text`), so a
// hooks.slack.com/services/... URL gets a formatted message; anything else
// (SIEM / HTTP collectors) gets the raw detection entry.
const SLACK_INCOMING_WEBHOOK_RE = /^https:\/\/hooks\.slack\.com\/services\//i;

// The page URL is a lure, and the message is read by people in a security
// channel: it's defanged (hxxps://evil[.]example) and put in code formatting so
// nobody clicks through by accident, and unfurling is off so Slack's servers
// don't fetch it either.
function defang(url) {
  return String(url).slice(0, 300).replace(/^http/i, "hxxp").replace(/\./g, "[.]").replace(/`/g, "'");
}

function slackEscape(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function slackMessage(entry) {
  const t = (key) => chrome.i18n.getMessage(key);
  let host = "";
  try {
    host = new URL(entry.url).hostname;
  } catch (e) {}
  const lines = [
    "*🚨 " + t("slackTitle") + "*",
    "*" + t("slackPage") + ":* `" + slackEscape(defang(entry.url)) + "`",
    "*" + t("slackScore") + ":* " + entry.score,
    "*" + t("slackIndicators") + ":* " + slackEscape((entry.indicators || []).join(", ")),
    "*" + t("slackTime") + ":* " + new Date(entry.time).toLocaleString(chrome.i18n.getUILanguage()),
  ];
  return {
    text: "🚨 " + t("slackTitle") + ": " + slackEscape(defang(host || entry.url)),
    blocks: [{ type: "section", text: { type: "mrkdwn", text: lines.join("\n") } }],
    unfurl_links: false,
    unfurl_media: false,
  };
}

// A user trusted a site from the banner. The hostname comes from the sender's
// real frame URL, not from the message, and the policy is re-checked here: the
// content script's view of it may be stale, and this is the one place that
// decides what gets written.
async function handleAllowlistAdd(msg, sender) {
  let host = "";
  try {
    host = new URL(sender.url).hostname;
  } catch (e) {}

  const result = await withStorageLock(async () => {
    const cfg = await chrome.storage.local.get({ policy: null, userAllowlist: [], allowlistLog: [] });
    const policy = POLICY.sanitizeStoredPolicy(cfg.policy) || POLICY.builtinPolicy();
    if (!POLICY.canUserTrust(host, policy)) return { ok: false, error: "not allowed by policy" };

    const userAllowlist = cfg.userAllowlist.includes(host)
      ? cfg.userAllowlist
      : cfg.userAllowlist.concat([host]).slice(-MAX_USER_ALLOWLIST);
    // Logged separately from `log` (detections) so the popup can show "what
    // fired" and "what got silenced" as two distinct trails — see README.
    const entry = {
      url: sender.url,
      hostname: host,
      score: msg.score,
      indicators: msg.indicators,
      tabId: sender.tab ? sender.tab.id : null,
      time: Date.now(),
    };
    await chrome.storage.local.set({
      userAllowlist,
      allowlistLog: cfg.allowlistLog.concat([entry]).slice(-MAX_LOG),
    });
    return { ok: true, hostname: host };
  });

  if (result.ok && sender.tab && sender.tab.id != null) {
    // The user just said "I trust this site" — drop the alert icon
    // immediately rather than waiting for the next navigation.
    chrome.action.setIcon({ tabId: sender.tab.id, path: ICONS.idle });
    chrome.action.setBadgeText({ tabId: sender.tab.id, text: "" });
  }
  return result;
}

// Reset a tab back to the neutral icon/badge as soon as it starts navigating
// to a new page, so a past detection doesn't stay flagged forever.
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status !== "loading") return;
  chrome.action.setIcon({ tabId, path: ICONS.idle });
  chrome.action.setBadgeText({ tabId, text: "" });
});
