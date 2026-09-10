document.getElementById("title").textContent = chrome.i18n.getMessage("popupTitle");

const list = document.getElementById("list");
list.textContent = chrome.i18n.getMessage("popupEmpty");

function renderEntries(container, entries, urlKey) {
  container.textContent = "";
  entries
    .slice()
    .reverse()
    .slice(0, 10)
    .forEach((e) => {
      const div = document.createElement("div");
      div.className = "entry";
      const url = document.createElement("div");
      url.className = "url";
      url.textContent = e[urlKey];
      const meta = document.createElement("div");
      meta.className = "meta";
      meta.textContent =
        new Date(e.time).toLocaleString() +
        " – " +
        chrome.i18n.getMessage("popupScore") +
        " " +
        e.score +
        " – " +
        (e.indicators || []).join(", ");
      div.appendChild(url);
      div.appendChild(meta);
      container.appendChild(div);
    });
}

chrome.storage.local.get({ log: [] }, ({ log }) => {
  if (!log.length) return;
  list.classList.remove("empty");
  renderEntries(list, log, "url");
});

// Sites a person silenced from the banner's "Trust this site" button — kept
// visible here (not just in `log`) so nothing about a detection getting
// permanently muted is invisible after the fact.
const allowlistSection = document.getElementById("allowlist-section");
const allowlistTitle = document.getElementById("allowlist-title");
const allowlistList = document.getElementById("allowlist-list");
allowlistTitle.textContent = chrome.i18n.getMessage("popupAllowlistTitle");

chrome.storage.local.get({ allowlistLog: [] }, ({ allowlistLog }) => {
  if (!allowlistLog.length) return;
  allowlistSection.hidden = false;
  renderEntries(allowlistList, allowlistLog, "hostname");
});
