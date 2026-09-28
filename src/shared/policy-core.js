// Policy logic shared by the content script (isolated world) and the service
// worker (via importScripts). Pure functions only — no chrome.* calls — so the
// same rules decide "is this host allowlisted" everywhere.
//
// The policy is managed centrally from the organization's Admin console (or
// GPO / MDM) as Chrome extension policy — chrome.storage.managed, schema in
// managed_schema.json. The admin's allowlist/neverAllowlist are ADDED to the
// built-in lists in default-allowlist.js (removeFromBuiltin takes built-in
// entries out); threshold/allowUserTrust fall back to the built-in default
// when unset. The service worker turns what the admin set into this shape and
// stores it as `policy` in chrome.storage.local:
//
//   {
//     source: "managed" | "builtin",
//     threshold: <int 1..100>,
//     allowUserTrust: <bool — pilot switch for the banner's "Trust this site">,
//     allowlist: [hostname...],      // effective list; matches host + subdomains
//     neverAllowlist: [hostname...], // effective list; always scanned, wins over allowlist
//     ignored: [string...],          // admin entries with no effect, for the popup
//   }
(function () {
  const DEFAULT_THRESHOLD = 5;
  const POLICY_KEYS = ["allowlist", "neverAllowlist", "removeFromBuiltin", "threshold", "allowUserTrust"];

  // Lowercase DNS name with at least two labels. Single-label entries are
  // rejected on purpose: "com" would allowlist every .com site.
  const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

  function isValidHost(h) {
    return typeof h === "string" && HOST_RE.test(h);
  }

  // Admins type these by hand, so be forgiving about case, surrounding
  // whitespace, a leading "*." or a pasted URL — but nothing beyond that.
  // Anything that still isn't a plain hostname is dropped and reported, not
  // guessed at.
  function normalizeHost(entry) {
    if (typeof entry !== "string") return null;
    let h = entry.trim().toLowerCase();
    if (/^[a-z][a-z0-9+.-]*:\/\//.test(h)) {
      try {
        h = new URL(h).hostname;
      } catch (e) {
        return null;
      }
    }
    if (h.startsWith("*.")) h = h.slice(2);
    if (h.endsWith(".")) h = h.slice(0, -1);
    return isValidHost(h) ? h : null;
  }

  function normalizeHostList(list, field, ignored) {
    const out = [];
    for (const entry of list) {
      const h = normalizeHost(entry);
      if (!h) ignored.push(field + ": " + JSON.stringify(entry));
      else if (!out.includes(h)) out.push(h);
    }
    return out;
  }

  // What applies when the organization hasn't configured anything.
  function builtinPolicy() {
    return {
      source: "builtin",
      threshold: DEFAULT_THRESHOLD,
      allowUserTrust: true,
      allowlist: (globalThis.__CFG_DEFAULT_ALLOWLIST__ || []).slice(),
      neverAllowlist: (globalThis.__CFG_DEFAULT_NEVER_ALLOWLIST__ || []).slice(),
      ignored: [],
    };
  }

  // `managed` is what chrome.storage.managed.get(null) returns: only the keys
  // the admin actually set.
  //
  // The admin's lists are ADDED to the built-in ones rather than replacing
  // them. Replacing meant a short list pasted into the Admin console silently
  // dropped every built-in entry — including most of neverAllowlist — and
  // that entries added to the built-in lists in later releases never reached
  // managed browsers unless someone re-pasted the whole list. Taking a
  // built-in entry out is a separate, explicit key (removeFromBuiltin, exact
  // hostnames). One mistyped hostname drops that entry, not the list.
  function policyFromManaged(managed) {
    const m = managed && typeof managed === "object" ? managed : {};
    const policy = builtinPolicy();
    if (!POLICY_KEYS.some((k) => k in m)) return policy;

    policy.source = "managed";
    const ignored = policy.ignored;
    if ("removeFromBuiltin" in m) {
      if (Array.isArray(m.removeFromBuiltin)) {
        for (const h of normalizeHostList(m.removeFromBuiltin, "removeFromBuiltin", ignored)) {
          if (!policy.allowlist.includes(h) && !policy.neverAllowlist.includes(h)) {
            ignored.push("removeFromBuiltin: " + JSON.stringify(h) + " (not a built-in entry)");
            continue;
          }
          policy.allowlist = policy.allowlist.filter((x) => x !== h);
          policy.neverAllowlist = policy.neverAllowlist.filter((x) => x !== h);
        }
      } else {
        ignored.push("removeFromBuiltin: not a list");
      }
    }
    for (const field of ["allowlist", "neverAllowlist"]) {
      if (!(field in m)) continue;
      if (!Array.isArray(m[field])) {
        ignored.push(field + ": not a list");
        continue;
      }
      for (const h of normalizeHostList(m[field], field, ignored)) {
        if (!policy[field].includes(h)) policy[field].push(h);
      }
    }
    if ("threshold" in m) {
      if (Number.isInteger(m.threshold) && m.threshold >= 1 && m.threshold <= 100) policy.threshold = m.threshold;
      else ignored.push("threshold: " + JSON.stringify(m.threshold));
    }
    if ("allowUserTrust" in m) {
      if (typeof m.allowUserTrust === "boolean") policy.allowUserTrust = m.allowUserTrust;
      else ignored.push("allowUserTrust: " + JSON.stringify(m.allowUserTrust));
    }
    // neverAllowlist wins over the allowlist (see isHostAllowlisted), so an
    // allowlist entry that sits entirely inside it has no effect. Say so in
    // the popup rather than let the admin believe it's active.
    for (const h of policy.allowlist) {
      if (matchesAny(h, policy.neverAllowlist)) ignored.push("allowlist: " + JSON.stringify(h) + " (neverAllowlist)");
    }
    return policy;
  }

  // Guard for the copy the content script reads back from storage.
  function sanitizeStoredPolicy(p) {
    if (!p || typeof p !== "object") return null;
    const hostList = (l) => Array.isArray(l) && l.every((h) => typeof h === "string");
    if (!hostList(p.allowlist) || !hostList(p.neverAllowlist)) return null;
    if (!Number.isInteger(p.threshold) || p.threshold < 1 || typeof p.allowUserTrust !== "boolean") return null;
    return p;
  }

  function hostMatches(host, entry) {
    return host === entry || host.endsWith("." + entry);
  }

  function matchesAny(host, list) {
    return list.some((e) => hostMatches(host, e));
  }

  // neverAllowlist is checked first and against the host being visited, so it
  // holds even against a broad entry: allowlisting "google.com" (by an admin)
  // or trusting it (by a user) still can't silence sites.google.com. To really
  // allowlist something on it, an admin has to take it off neverAllowlist —
  // a deliberate decision rather than a side effect.
  // The admin allowlist matches subdomains. A user's own "Trust this site"
  // entries are narrower: exact hostname only, and only while the policy
  // allows user trust at all.
  function isHostAllowlisted(host, policy, userAllowlist) {
    if (!host) return false;
    if (matchesAny(host, policy.neverAllowlist)) return false;
    if (matchesAny(host, policy.allowlist)) return true;
    if (!policy.allowUserTrust) return false;
    return (userAllowlist || []).includes(host);
  }

  function canUserTrust(host, policy) {
    return !!host && policy.allowUserTrust && !matchesAny(host, policy.neverAllowlist);
  }

  globalThis.__CFG_POLICY__ = {
    isValidHost,
    normalizeHost,
    builtinPolicy,
    policyFromManaged,
    sanitizeStoredPolicy,
    hostMatches,
    matchesAny,
    isHostAllowlisted,
    canUserTrust,
  };
})();
