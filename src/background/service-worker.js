const ICONS = {
  idle: { 16: "icons/idle/icon16.png", 32: "icons/idle/icon32.png", 48: "icons/idle/icon48.png" },
  alert: { 16: "icons/alert/icon16.png", 32: "icons/alert/icon32.png", 48: "icons/alert/icon48.png" },
};

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (!msg || msg.type !== "clickfix-detection") return;

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
});

// Reset a tab back to the neutral icon/badge as soon as it starts navigating
// to a new page, so a past detection doesn't stay flagged forever.
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status !== "loading") return;
  chrome.action.setIcon({ tabId, path: ICONS.idle });
  chrome.action.setBadgeText({ tabId, text: "" });
});
