document.getElementById("title").textContent = chrome.i18n.getMessage("popupTitle");

const list = document.getElementById("list");
list.textContent = chrome.i18n.getMessage("popupEmpty");

chrome.storage.local.get({ log: [] }, ({ log }) => {
  if (!log.length) return;
  list.classList.remove("empty");
  list.textContent = "";
  log
    .slice()
    .reverse()
    .slice(0, 10)
    .forEach((e) => {
      const div = document.createElement("div");
      div.className = "entry";
      const url = document.createElement("div");
      url.className = "url";
      url.textContent = e.url;
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
      list.appendChild(div);
    });
});
