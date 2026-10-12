/**
 * sentinelbit Browser Extension - Background Service Worker (Manifest V3)
 * - Session State & Memory Vault Security (Bitwarden-Parität)
 * - Keyboard Shortcuts (Ctrl+Shift+L / Cmd+Shift+L)
 * - Context Menus (Rechtsklick-Autofill)
 * - Active Domain Badge Counter
 * - Auto-Lock Timer via chrome.alarms
 */

// =============================================================
// 1. LIFECYCLE & CONTEXT MENUS SETUP
// =============================================================

chrome.runtime.onInstalled.addListener(() => {
  // Set default configuration if unset
  chrome.storage.local.get(["server_url", "auto_lock_minutes"], (res) => {
    if (!res.server_url) {
      chrome.storage.local.set({ server_url: "http://127.0.0.1:8000" });
    }
    if (!res.auto_lock_minutes) {
      chrome.storage.local.set({ auto_lock_minutes: 15 });
    }
  });

  // Setup Context Menus
  try {
    chrome.contextMenus.removeAll(() => {
      chrome.contextMenus.create({
        id: "sentinelbit_root",
        title: "sentinelbit",
        contexts: ["editable", "page"]
      });

      chrome.contextMenus.create({
        id: "sentinelbit_autofill",
        parentId: "sentinelbit_root",
        title: "⚡ Zugangsdaten ausfüllen (Ctrl+Shift+L)",
        contexts: ["editable", "page"]
      });

      chrome.contextMenus.create({
        id: "sentinelbit_open_sidepanel",
        parentId: "sentinelbit_root",
        title: "🪟 In Seitenleiste öffnen",
        contexts: ["all"]
      });

      chrome.contextMenus.create({
        id: "sentinelbit_open_vault",
        parentId: "sentinelbit_root",
        title: "🌐 Web-Tresor öffnen",
        contexts: ["all"]
      });
    });
  } catch (e) {
    console.debug("Context menu setup error:", e);
  }

  // Setup periodic auto-lock check alarm (every 1 minute)
  chrome.alarms.create("sentinelbit_autolock_check", { periodInMinutes: 1 });
});

// Auto-lock when system is locked or user becomes idle (#20)
if (chrome.idle) {
  chrome.idle.onStateChanged.addListener((newState) => {
    if (newState === "locked") {
      if (chrome.storage.session) {
        chrome.storage.session.clear();
      }
      chrome.storage.local.set({ last_active_time: 0 });
      chrome.action.setBadgeText({ text: "" });
      console.log("SentinelBit: Vault automatically locked on OS lock.");
    }
  });
}

// =============================================================
// 2. CONTEXT MENU ACTIONS
// =============================================================

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "sentinelbit_autofill") {
    if (tab && tab.id) {
      autofillTab(tab);
    }
  } else if (info.menuItemId === "sentinelbit_open_sidepanel") {
    if (chrome.sidePanel && tab && tab.id) {
      chrome.sidePanel.open({ tabId: tab.id });
    }
  } else if (info.menuItemId === "sentinelbit_open_vault") {
    chrome.storage.local.get(["server_url"], (res) => {
      const url = res.server_url || "http://127.0.0.1:8000";
      chrome.tabs.create({ url });
    });
  }
});

// =============================================================
// 3. KEYBOARD SHORTCUT COMMANDS (Ctrl+Shift+L)
// =============================================================

chrome.commands.onCommand.addListener(async (command) => {
  if (command === "autofill_active_tab") {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.id) {
      autofillTab(tab);
    }
  }
});

// =============================================================
// 4. AUTOFILL ENGINE VIA BACKGROUND
// =============================================================

async function autofillTab(tab) {
  if (!tab.url || tab.url.startsWith("chrome://") || tab.url.startsWith("edge://")) return;

  const session = await getSessionData();
  const items = session.vault_cache || [];
  const passkeys = session.vault_passkeys || [];

  if (items.length === 0 && passkeys.length === 0) {
    flashBadge(tab.id, "🔒", "#ef4444");
    return;
  }

  const hostname = extractDomain(tab.url);
  const match = findBestMatch(items, hostname);
  const matchingPasskeys = passkeys.filter(pk => matchesDomain({ url: pk.rp_id, title: pk.rp_name }, hostname));

  if (!match && matchingPasskeys.length === 0) {
    flashBadge(tab.id, "0", "#6b7280");
    return;
  }

  try {
    chrome.tabs.sendMessage(
      tab.id,
      {
        action: "AUTOFILL",
        username: match ? match.username : (matchingPasskeys[0]?.username || ""),
        password: match ? match.password : "",
        totp: match ? (match.totp || "") : "",
        passkey: matchingPasskeys[0] || null
      },
      (response) => {
        if (chrome.runtime.lastError) {
          flashBadge(tab.id, "!", "#f59e0b");
          return;
        }
        if (response && response.status === "ok") {
          flashBadge(tab.id, "✓", "#10b981");
        }
      }
    );
  } catch (e) {
    console.debug("Autofill tab error:", e);
  }
}

// =============================================================
// 5. DOMAIN MATCHING & HELPER FUNCTIONS
// =============================================================

function extractDomain(urlStr) {
  if (!urlStr) return "";
  try {
    let clean = urlStr.trim();
    if (!clean.startsWith("http://") && !clean.startsWith("https://")) {
      clean = "https://" + clean;
    }
    const parsed = new URL(clean);
    return parsed.hostname.toLowerCase().replace(/^www\./, "");
  } catch (e) {
    return "";
  }
}

function getBaseDomain(domain) {
  if (!domain) return "";
  const parts = domain.toLowerCase().split(".");
  if (parts.length <= 2) return domain;
  const commonDoubleTlds = ["co.uk", "com.de", "com.au", "co.jp", "co.nz", "org.uk", "gov.uk"];
  const lastTwo = parts.slice(-2).join(".");
  if (commonDoubleTlds.includes(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

function matchesDomain(item, currentHostname) {
  if (!currentHostname) return true;
  const currentClean = currentHostname.toLowerCase().replace(/^www\./, "");
  const currentBase = getBaseDomain(currentClean);
  const currentName = currentBase.split(".")[0];

  if (item.url) {
    const itemDomain = extractDomain(item.url);
    const itemBase = getBaseDomain(itemDomain);
    if (itemDomain === currentClean || itemBase === currentBase) return true;
    if (currentClean.endsWith("." + itemDomain) || itemDomain.endsWith("." + currentClean)) return true;
    if (itemDomain.includes(currentBase) || currentClean.includes(itemBase)) return true;
  }

  if (item.title && currentName && currentName.length >= 3) {
    const cleanTitle = item.title.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (cleanTitle === currentName || cleanTitle.includes(currentName) || currentName.includes(cleanTitle)) {
      return true;
    }
  }

  return false;
}

function findBestMatch(items, hostname) {
  if (!hostname) return items[0] || null;
  const matched = items.filter(it => matchesDomain(it, hostname));
  return matched[0] || null;
}

// =============================================================
// 6. BADGE COUNTER & TAB EVENTS
// =============================================================

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    updateBadgeForTab(tab);
  } catch (e) {}
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab) {
    updateBadgeForTab(tab);
  }
});

async function updateBadgeForTab(tab) {
  if (!tab || !tab.id || !tab.url || tab.url.startsWith("chrome://") || tab.url.startsWith("edge://")) {
    try {
      chrome.action.setBadgeText({ text: "", tabId: tab?.id });
    } catch (e) {}
    return;
  }

  const session = await getSessionData();
  const items = session.vault_cache || [];
  const passkeys = session.vault_passkeys || [];

  if (items.length === 0 && passkeys.length === 0) {
    chrome.action.setBadgeText({ text: "", tabId: tab.id });
    return;
  }

  const hostname = extractDomain(tab.url);
  const countLogins = items.filter(it => matchesDomain(it, hostname)).length;
  const countPasskeys = passkeys.filter(pk => matchesDomain({ url: pk.rp_id, title: pk.rp_name }, hostname)).length;
  const total = countLogins + countPasskeys;

  if (total > 0) {
    chrome.action.setBadgeText({ text: String(total), tabId: tab.id });
    chrome.action.setBadgeBackgroundColor({ color: countPasskeys > 0 ? "#8b5cf6" : "#3b82f6", tabId: tab.id });
  } else {
    chrome.action.setBadgeText({ text: "", tabId: tab.id });
  }
}

function flashBadge(tabId, text, color) {
  try {
    chrome.action.setBadgeText({ text, tabId });
    chrome.action.setBadgeBackgroundColor({ color, tabId });
    setTimeout(() => {
      chrome.tabs.get(tabId, (tab) => {
        if (!chrome.runtime.lastError && tab) {
          updateBadgeForTab(tab);
        }
      });
    }, 2000);
  } catch (e) {}
}

// =============================================================
// 7. IN-MEMORY SESSION & AUTO-LOCK MANAGEMENT
// =============================================================

async function getSessionData() {
  if (chrome.storage.session) {
    return new Promise((resolve) => {
      chrome.storage.session.get(null, (res) => resolve(res || {}));
    });
  }
  return new Promise((resolve) => {
    chrome.storage.local.get(["vault_cache", "vault_passkeys"], (res) => resolve(res || {}));
  });
}

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === "sentinelbit_autolock_check") {
    const local = await new Promise(r => chrome.storage.local.get(["auto_lock_minutes", "last_active_time"], r));
    const timeoutMin = parseInt(local.auto_lock_minutes || "15", 10);
    const lastActive = local.last_active_time || 0;

    if (timeoutMin > 0 && lastActive > 0) {
      const elapsedMin = (Date.now() - lastActive) / 60000;
      if (elapsedMin >= timeoutMin) {
        // Lock vault
        if (chrome.storage.session) {
          chrome.storage.session.clear();
        }
        chrome.storage.local.set({ last_active_time: 0 });
        chrome.action.setBadgeText({ text: "" });
        console.debug("sentinelbit: Auto-locked vault after inactivity");
      }
    }
  } else if (alarm.name === "sentinelbit_clipboard_clear") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) {
        chrome.tabs.sendMessage(tabs[0].id, { action: "CLEAR_CLIPBOARD" }, () => {});
      }
    });
  }
});

// Listen for broadcast messages from popup and content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "VAULT_UNLOCKED") {
    chrome.storage.local.set({ last_active_time: Date.now() });
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) updateBadgeForTab(tabs[0]);
    });
    sendResponse({ status: "ok" });
  } else if (request.action === "SET_SESSION_VAULT") {
    if (chrome.storage.session) {
      chrome.storage.session.set({
        vault_cache: request.items || [],
        vault_passkeys: request.passkeys || []
      });
    }
    chrome.storage.local.set({ last_active_time: Date.now() });
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) updateBadgeForTab(tabs[0]);
    });
    sendResponse({ status: "ok" });
  } else if (request.action === "VAULT_LOCKED") {
    if (chrome.storage.session) {
      chrome.storage.session.clear();
    }
    chrome.storage.local.set({ last_active_time: 0 });
    chrome.action.setBadgeText({ text: "" });
    sendResponse({ status: "ok" });
  } else if (request.action === "TOUCH_ACTIVITY") {
    chrome.storage.local.set({ last_active_time: Date.now() });
    sendResponse({ status: "ok" });
  } else if (request.action === "OPEN_SIDEPANEL") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id && chrome.sidePanel) {
        chrome.sidePanel.open({ tabId: tabs[0].id });
      }
    });
    sendResponse({ status: "ok" });
  } else if (request.action === "SCHEDULE_CLIPBOARD_CLEAR") {
    const sec = parseInt(request.seconds, 10) || 30;
    chrome.alarms.create("sentinelbit_clipboard_clear", { delayInMinutes: Math.max(0.1, sec / 60) });
    sendResponse({ status: "scheduled" });
  } else if (request.action === "GET_MATCHING_LOGINS") {
    const hostname = extractDomain(request.url || "");
    chrome.storage.local.get(["excluded_domains"], async (loc) => {
      const exclusions = (loc.excluded_domains || "").split("\n").map(s => s.trim().toLowerCase()).filter(Boolean);
      if (hostname && exclusions.some(ex => hostname === ex || hostname.endsWith("." + ex))) {
        sendResponse({ matches: [], passkeys: [], isExcluded: true });
        return;
      }
      const session = await getSessionData();
      const items = session.vault_cache || [];
      const passkeys = session.vault_passkeys || [];
      const matches = items.filter(it => matchesDomain(it, hostname));
      const matchingPasskeys = passkeys.filter(pk => matchesDomain({ url: pk.rp_id, title: pk.rp_name }, hostname));
      sendResponse({
        matches,
        passkeys: matchingPasskeys,
        totalItems: items.length,
        totalPasskeys: passkeys.length,
        isExcluded: false
      });
    });
    return true;
  } else if (request.action === "WEBAUTHN_GET_MATCHES") {
    const rpId = (request.rpId || "").toLowerCase();
    const allowCreds = request.allowCredentials || [];
    getSessionData().then((session) => {
      const passkeys = session.vault_passkeys || [];
      let matches = passkeys.filter(pk => {
        const pkRp = (pk.rp_id || "").toLowerCase();
        return pkRp === rpId || rpId.endsWith("." + pkRp) || pkRp.endsWith("." + rpId) || matchesDomain({ url: pk.rp_id, title: pk.rp_name }, rpId);
      });

      if (allowCreds.length > 0) {
        const credIdSet = new Set(allowCreds.map(c => c.id));
        const exactMatches = matches.filter(pk => credIdSet.has(pk.credential_id));
        if (exactMatches.length > 0) {
          matches = exactMatches;
        }
      }

      sendResponse({
        status: matches.length > 0 ? "ok" : "no_passkey",
        passkeys: matches
      });
    });
    return true;
  } else if (request.action === "WEBAUTHN_SAVE_PASSKEY") {
    const pk = request.passkey;
    chrome.storage.local.get(["server_url"], async (loc) => {
      const serverUrl = loc.server_url || "http://127.0.0.1:8000";
      const session = await getSessionData();
      const currentPks = session.vault_passkeys || [];
      currentPks.push(pk);
      if (chrome.storage.session) {
        await chrome.storage.session.set({ vault_passkeys: currentPks });
      }
      const token = session.vault_token || "";
      if (token) {
        try {
          await fetch(`${serverUrl}/api/passkeys`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${token}`
            },
            body: JSON.stringify(pk)
          });
        } catch (e) {
          console.warn("Could not sync new passkey to server:", e);
        }
      }
      sendResponse({ status: "ok" });
    });
    return true;
  }
  return true;
});
