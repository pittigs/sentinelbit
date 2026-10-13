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

const DOMAIN_EQUIVALENTS = [
  ["google.com", "accounts.google.com", "gmail.com", "googlemail.com", "google.de", "youtube.com"],
  ["microsoft.com", "live.com", "login.live.com", "office.com", "microsoftonline.com"],
  ["apple.com", "icloud.com", "appleid.apple.com"],
  ["amazon.com", "amazon.de", "amazon.co.uk"]
];

function areDomainsEquivalent(d1, d2) {
  if (!d1 || !d2) return false;
  const c1 = d1.toLowerCase().replace(/^www\./, "").trim();
  const c2 = d2.toLowerCase().replace(/^www\./, "").trim();
  if (c1 === c2) return true;
  for (const group of DOMAIN_EQUIVALENTS) {
    const inGroup1 = group.some(g => c1 === g || c1.endsWith("." + g) || g.endsWith("." + c1));
    const inGroup2 = group.some(g => c2 === g || c2.endsWith("." + g) || g.endsWith("." + c2));
    if (inGroup1 && inGroup2) return true;
  }
  return false;
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
    if (areDomainsEquivalent(itemDomain, currentClean)) return true;
  }

  if (item.title && currentName && currentName.length >= 3) {
    const cleanTitle = item.title.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (cleanTitle === currentName || cleanTitle.includes(currentName) || currentName.includes(cleanTitle)) {
      return true;
    }
    if ((cleanTitle.includes("google") || cleanTitle.includes("gmail")) && (currentName === "google" || currentName === "accounts" || currentClean.includes("google"))) {
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

// Crypto & Live-Sync Helpers
function hexToBuffer(hex) {
  if (!hex) return new ArrayBuffer(0);
  const bytes = new Uint8Array(Math.ceil(hex.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes.buffer;
}

function base64ToBuffer(b64) {
  if (!b64) return new ArrayBuffer(0);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function bufferToStr(buf) {
  return new TextDecoder().decode(buf);
}

async function decryptPayload(encryptedJsonStr, cryptoKey) {
  try {
    const parsed = typeof encryptedJsonStr === "string" ? JSON.parse(encryptedJsonStr) : encryptedJsonStr;
    const iv = hexToBuffer(parsed.iv);
    const ciphertext = hexToBuffer(parsed.data);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      cryptoKey,
      ciphertext
    );

    return JSON.parse(bufferToStr(decrypted));
  } catch (e) {
    return null;
  }
}

let isSyncing = false;
async function performBackgroundVaultSync() {
  if (isSyncing) return;
  isSyncing = true;
  try {
    const session = await getSessionData();
    const token = session.vault_token;
    const keyB64 = session.vault_key_b64;
    if (!token || !keyB64) {
      isSyncing = false;
      return;
    }

    const loc = await new Promise(r => chrome.storage.local.get(["server_url"], r));
    const serverUrl = loc.server_url || "http://127.0.0.1:8000";

    const keyBuf = base64ToBuffer(keyB64);
    const encKey = await crypto.subtle.importKey(
      "raw",
      keyBuf,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    const [itemsRes, pkRes] = await Promise.all([
      fetch(`${serverUrl}/api/vault/items`, { headers: { "Authorization": `Bearer ${token}` } }),
      fetch(`${serverUrl}/api/passkeys`, { headers: { "Authorization": `Bearer ${token}` } })
    ]);

    if (!itemsRes.ok) {
      isSyncing = false;
      return;
    }

    const rawItems = await itemsRes.json();
    let passkeys = pkRes.ok ? await pkRes.json() : [];

    for (const pk of passkeys) {
      if (pk.encrypted_private_key) {
        if (typeof pk.encrypted_private_key === "string" && pk.encrypted_private_key.startsWith("{") && pk.encrypted_private_key.includes('"iv"')) {
          try {
            const dec = await decryptPayload(pk.encrypted_private_key, encKey);
            if (dec) {
              pk.decrypted_private_key = dec.private_pem || dec.raw_key || (typeof dec === "string" ? dec : null);
            }
          } catch (_) {}
        } else {
          pk.decrypted_private_key = pk.encrypted_private_key;
        }
      }
    }

    const logins = [];
    for (const it of rawItems) {
      if (it.type === "login") {
        try {
          const payload = await decryptPayload(it.encrypted_payload, encKey);
          if (payload) {
            logins.push({
              id: it.id,
              title: it.title,
              username: payload.username || "",
              password: payload.password || "",
              url: payload.url || "",
              totp: payload.totp || "",
              favorite: it.favorite
            });
          }
        } catch (_) {}
      }
    }

    if (chrome.storage.session) {
      await chrome.storage.session.set({
        vault_cache: logins,
        vault_passkeys: passkeys
      });
    }

    await chrome.storage.local.set({ last_synced: Date.now() });
    console.log(`[sentinelbit-sse] Live-Sync update: ${logins.length} Logins, ${passkeys.length} Passkeys.`);

    chrome.runtime.sendMessage({
      action: "VAULT_SYNCED",
      loginsCount: logins.length,
      passkeysCount: passkeys.length
    }, () => {});

    chrome.tabs.query({}, (tabs) => {
      for (const t of tabs) {
        if (t.id) {
          chrome.tabs.sendMessage(t.id, { action: "VAULT_SYNCED" }, () => {});
        }
      }
    });

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) updateBadgeForTab(tabs[0]);
    });
  } catch (err) {
    console.warn("[sentinelbit-sse] Background sync error:", err);
  } finally {
    isSyncing = false;
  }
}

let liveSyncAbortController = null;
let liveSyncRunning = false;

async function startLiveSync() {
  if (liveSyncRunning) return;
  const session = await getSessionData();
  const token = session.vault_token;
  if (!token) return;

  const loc = await new Promise(r => chrome.storage.local.get(["server_url"], r));
  const serverUrl = loc.server_url || "http://127.0.0.1:8000";

  liveSyncRunning = true;
  if (liveSyncAbortController) {
    liveSyncAbortController.abort();
  }
  liveSyncAbortController = new AbortController();

  try {
    console.log("[sentinelbit-sse] Connecting to live-sync stream:", `${serverUrl}/api/sync/events`);
    const res = await fetch(`${serverUrl}/api/sync/events?token=${encodeURIComponent(token)}`, {
      headers: { "Accept": "text/event-stream" },
      signal: liveSyncAbortController.signal
    });

    if (!res.ok) {
      liveSyncRunning = false;
      return;
    }

    chrome.runtime.sendMessage({ action: "LIVE_SYNC_STATUS", connected: true }, () => {});

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop() || "";

      for (const block of parts) {
        if (block.includes("event: vault_sync")) {
          console.log("[sentinelbit-sse] vault_sync event received! Triggering background sync...");
          await performBackgroundVaultSync();
        }
      }
    }
  } catch (err) {
    if (err.name !== "AbortError") {
      console.debug("[sentinelbit-sse] Stream closed/disconnected:", err.message);
    }
  } finally {
    liveSyncRunning = false;
    chrome.runtime.sendMessage({ action: "LIVE_SYNC_STATUS", connected: false }, () => {});
    setTimeout(async () => {
      const currentSess = await getSessionData();
      if (currentSess && currentSess.vault_token) {
        startLiveSync();
      }
    }, 8000);
  }
}

function stopLiveSync() {
  if (liveSyncAbortController) {
    liveSyncAbortController.abort();
    liveSyncAbortController = null;
  }
  liveSyncRunning = false;
  chrome.runtime.sendMessage({ action: "LIVE_SYNC_STATUS", connected: false }, () => {});
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
        stopLiveSync();
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

// Active 2FA session tracking for multi-step logins & redirects
const active2FaSessions = new Map();
let latest2FaSession = null;

// Clean expired 2FA sessions periodically
setInterval(() => {
  const now = Date.now();
  for (const [tabId, sess] of active2FaSessions.entries()) {
    if (now - sess.timestamp > 120000) active2FaSessions.delete(tabId);
  }
  if (latest2FaSession && now - latest2FaSession.timestamp > 120000) {
    latest2FaSession = null;
  }
}, 30000);

// Listen for broadcast messages from popup and content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "VAULT_UNLOCKED") {
    chrome.storage.local.set({ last_active_time: Date.now() });
    startLiveSync();
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) updateBadgeForTab(tabs[0]);
    });
    sendResponse({ status: "ok" });
  } else if (request.action === "START_LIVE_SYNC") {
    startLiveSync();
    sendResponse({ status: "ok" });
  } else if (request.action === "GET_LIVE_SYNC_STATUS") {
    sendResponse({ connected: liveSyncRunning });
  } else if (request.action === "SET_SESSION_VAULT") {
    if (chrome.storage.session) {
      chrome.storage.session.set({
        vault_cache: request.items || [],
        vault_passkeys: request.passkeys || [],
        vault_token: request.token || undefined,
        vault_key_b64: request.key_b64 || undefined
      });
    }
    chrome.storage.local.set({ last_active_time: Date.now() });
    startLiveSync();
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) updateBadgeForTab(tabs[0]);
    });
    sendResponse({ status: "ok" });
  } else if (request.action === "VAULT_LOCKED") {
    stopLiveSync();
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
  } else if (request.action === "SET_ACTIVE_2FA_SESSION") {
    const { origin, secret, username } = request;
    const tabId = sender.tab ? sender.tab.id : null;
    const sessionData = {
      origin: origin ? origin.toLowerCase() : "",
      secret,
      username: username || "",
      timestamp: Date.now()
    };
    if (tabId) {
      active2FaSessions.set(tabId, sessionData);
    }
    latest2FaSession = sessionData;
    sendResponse({ status: "ok" });
  } else if (request.action === "GET_ACTIVE_2FA_SESSION") {
    const tabId = sender.tab ? sender.tab.id : null;
    const reqOrigin = (request.origin || "").toLowerCase();
    let session = tabId ? active2FaSessions.get(tabId) : null;
    if (!session && latest2FaSession) {
      if (Date.now() - latest2FaSession.timestamp < 120000) {
        const baseLatest = getBaseDomain(extractDomain(latest2FaSession.origin || ""));
        const baseReq = getBaseDomain(extractDomain(reqOrigin || ""));
        if (!reqOrigin || !latest2FaSession.origin || reqOrigin === latest2FaSession.origin || (baseLatest && baseLatest === baseReq)) {
          session = latest2FaSession;
        }
      }
    }
    if (session && (Date.now() - session.timestamp < 120000)) {
      sendResponse({ status: "ok", session });
    } else {
      sendResponse({ status: "none" });
    }
  } else if (request.action === "CLEAR_ACTIVE_2FA_SESSION") {
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId) active2FaSessions.delete(tabId);
    latest2FaSession = null;
    sendResponse({ status: "ok" });
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
    const rpId = (request.rpId || "").toLowerCase().trim();
    const allowCreds = request.allowCredentials || [];

    (async () => {
      let session = await getSessionData();
      let passkeys = session.vault_passkeys || [];
      let cache = session.vault_cache || [];

      // If session is empty, check if an open web vault tab can instantly hydrate it!
      if (passkeys.length === 0 && cache.length === 0) {
        await new Promise((resolve) => {
          chrome.tabs.query({}, (tabs) => {
            let pending = tabs ? tabs.length : 0;
            if (pending === 0) return resolve();
            for (const t of tabs) {
              if (t.id) {
                chrome.tabs.sendMessage(t.id, { action: "TRIGGER_VAULT_PAGE_SYNC" }, () => {
                  pending--;
                  if (pending <= 0) resolve();
                });
              } else {
                pending--;
                if (pending <= 0) resolve();
              }
            }
          });
          setTimeout(resolve, 350);
        });
        session = await getSessionData();
        passkeys = session.vault_passkeys || [];
        cache = session.vault_cache || [];
      }

      // Check if vault is locked
      if (passkeys.length === 0 && cache.length === 0) {
        chrome.storage.local.get(["vault_user"], (loc) => {
          if (loc && loc.vault_user) {
            sendResponse({ status: "locked", passkeys: [] });
          } else {
            sendResponse({ status: "no_passkey", passkeys: [] });
          }
        });
        return;
      }

      function normId(s) {
        if (!s) return "";
        if (s instanceof ArrayBuffer || s instanceof Uint8Array || ArrayBuffer.isView(s)) {
          let bytes = s instanceof Uint8Array ? s : new Uint8Array(s.buffer || s, s.byteOffset || 0, s.byteLength);
          let binary = "";
          for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
          return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        }
        const str = String(s).trim();
        const isUuid = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(str);
        const isPureHex = /^[0-9a-fA-F]{32,}$/.test(str) && str.length % 2 === 0;

        if (isUuid || isPureHex) {
          const cleanHex = str.replace(/-/g, "");
          try {
            let binary = "";
            for (let i = 0; i < cleanHex.length; i += 2) {
              binary += String.fromCharCode(parseInt(cleanHex.substr(i, 2), 16));
            }
            return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
          } catch (_) {}
        }
        return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      }

      let matches = passkeys.filter(pk => {
        const pkRp = (extractDomain(pk.rp_id || "") || (pk.rp_id || "")).toLowerCase().trim();
        return pkRp === rpId ||
          rpId.endsWith("." + pkRp) ||
          pkRp.endsWith("." + rpId) ||
          areDomainsEquivalent(pkRp, rpId) ||
          matchesDomain({ url: pk.rp_id, title: pk.rp_name }, rpId);
      });

      if (allowCreds.length > 0) {
        const credIdSet = new Set(allowCreds.map(c => normId(c.id)));
        const exactMatches = matches.filter(pk => credIdSet.has(normId(pk.credential_id)));
        if (exactMatches.length > 0) {
          matches = exactMatches;
        } else {
          console.warn("[sentinelbit-bg] allowCredentials did not match any stored passkey id in vault:", allowCreds.map(c => normId(c.id)));
        }
      }

      sendResponse({
        status: matches.length > 0 ? "ok" : "no_passkey",
        passkeys: matches
      });
    })();
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

// Resume Live-Sync on background worker initialization if vault session is active
getSessionData().then((sess) => {
  if (sess && sess.vault_token && sess.vault_key_b64) {
    startLiveSync();
  }
});
