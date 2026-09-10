const ICONS = {
  idle: { 16: "icons/idle/icon16.png", 32: "icons/idle/icon32.png", 48: "icons/idle/icon48.png" },
  alert: { 16: "icons/alert/icon16.png", 32: "icons/alert/icon32.png", 48: "icons/alert/icon48.png" },
};

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (!msg) return;

  if (msg.type === "clickfix-detection") {
    const entry = {
      url: msg.url,
      score: msg.score,
      indicators: msg.indicators,
      tabId: sender.tab ? sender.tab.id : null,
      time: Date.now(),
    };

    chrome.storage.local.get({ log: [] }, ({ log }) => {
      log.push(entry);
      if (log.length > 200) log.shift();
      chrome.storage.local.set({ log });
    });

    chrome.storage.local.get({ webhookUrl: "" }, ({ webhookUrl }) => {
      if (!webhookUrl) return;
      fetch(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(entry),
      }).catch(() => {});
    });

    if (sender.tab && sender.tab.id != null) {
      // The toolbar icon stays neutral (icons/idle) at rest — only the tab that
      // actually triggered a detection flips to the red alert icon, so the
      // icon isn't a permanent "something's wrong" signal that gets tuned out.
      chrome.action.setIcon({ tabId: sender.tab.id, path: ICONS.alert });
      chrome.action.setBadgeText({ tabId: sender.tab.id, text: "!" });
      chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: "#b91c1c" });
    }
    return;
  }

  if (msg.type === "clickfix-allowlist-add") {
    // A user manually silenced this hostname from the banner. Logged
    // separately from `log` (detections) so the popup can show "what fired"
    // and "what got dismissed" as two distinct trails — see README.
    const entry = {
      url: msg.url,
      hostname: msg.hostname,
      score: msg.score,
      indicators: msg.indicators,
      tabId: sender.tab ? sender.tab.id : null,
      time: Date.now(),
    };

    chrome.storage.local.get({ allowlistLog: [] }, ({ allowlistLog }) => {
      allowlistLog.push(entry);
      if (allowlistLog.length > 200) allowlistLog.shift();
      chrome.storage.local.set({ allowlistLog });
    });

    if (sender.tab && sender.tab.id != null) {
      // The user just said "I trust this site" — drop the alert icon
      // immediately rather than waiting for the next navigation.
      chrome.action.setIcon({ tabId: sender.tab.id, path: ICONS.idle });
      chrome.action.setBadgeText({ tabId: sender.tab.id, text: "" });
    }
  }
});

// Reset a tab back to the neutral icon/badge as soon as it starts navigating
// to a new page, so a past detection doesn't stay flagged forever.
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status !== "loading") return;
  chrome.action.setIcon({ tabId, path: ICONS.idle });
  chrome.action.setBadgeText({ tabId, text: "" });
});
