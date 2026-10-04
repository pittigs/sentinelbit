/**
 * sentinelbit Browser Extension - Full Popup Controller
 * - Direct In-Extension Login & Zero-Knowledge AES-256 Decryption
 * - Two-Way Web Vault Tab Synchronization Bridge
 * - Smart Subdomain & Domain Matching
 * - Real 6-digit TOTP 2FA Code Generation & Clipboard Copy
 * - Password Generator with 1-Click Page Autofill
 */

const SERVER_URL = "http://127.0.0.1:8000";

let allVaultItems = [];
let activeHostname = "";
let showAllItemsMode = false;
let currentGeneratedPassword = "";

// =============================================================
// 1. CRYPTO HELPERS (Web Crypto API)
// =============================================================

function bufferToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBuffer(hex) {
  const bytes = new Uint8Array(Math.ceil(hex.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes.buffer;
}

function strToBuffer(str) {
  return new TextEncoder().encode(str);
}

function bufferToStr(buf) {
  return new TextDecoder().decode(buf);
}

async function deriveMasterEncryptionKey(masterPassword, encSalt) {
  const enc = new TextEncoder();
  const passwordKey = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(masterPassword),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode(encSalt),
      iterations: 100000,
      hash: "SHA-256"
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

async function deriveClientAuthKey(masterPassword, clientSalt) {
  const enc = new TextEncoder();
  const passwordKey = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(masterPassword),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const derivedBits = await window.crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: enc.encode(clientSalt),
      iterations: 100000,
      hash: "SHA-256"
    },
    passwordKey,
    256
  );

  return bufferToHex(derivedBits);
}

async function decryptPayload(encryptedJsonStr, cryptoKey) {
  try {
    const parsed = typeof encryptedJsonStr === "string" ? JSON.parse(encryptedJsonStr) : encryptedJsonStr;
    const iv = hexToBuffer(parsed.iv);
    const ciphertext = hexToBuffer(parsed.data);

    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      cryptoKey,
      ciphertext
    );

    return JSON.parse(bufferToStr(decrypted));
  } catch (e) {
    return null;
  }
}

// =============================================================
// 2. INITIALIZATION
// =============================================================

document.addEventListener("DOMContentLoaded", async () => {
  setupTabs();
  setupGenerator();
  setupHeaderButtons();
  setupLoginForm();

  await checkServerHealth();
  await detectActiveTab();
  loadCachedVault();
});

// =============================================================
// 3. SERVER STATUS CHECK
// =============================================================

async function checkServerHealth() {
  const statusEl = document.getElementById("server-status");
  try {
    const res = await fetch(`${SERVER_URL}/api/health`, { method: "GET", cache: "no-store" });
    if (res.ok) {
      statusEl.innerText = "Verbunden";
      statusEl.className = "status-badge";
    } else {
      statusEl.innerText = "Gesperrt";
      statusEl.className = "status-badge offline";
    }
  } catch (e) {
    statusEl.innerText = "Offline";
    statusEl.className = "status-badge offline";
  }
}

// =============================================================
// 4. TAB & DOMAIN DETECTION
// =============================================================

async function detectActiveTab() {
  const domainLabel = document.getElementById("domain-label");
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0] && tabs[0].url) {
      const url = new URL(tabs[0].url);
      activeHostname = url.hostname.toLowerCase().replace(/^www\./, "");

      if (activeHostname === "newtab" || activeHostname === "" || tabs[0].url.startsWith("chrome://") || tabs[0].url.startsWith("edge://")) {
        activeHostname = "";
        if (domainLabel) domainLabel.innerText = "Alle Zugänge:";
      } else {
        if (domainLabel) domainLabel.innerText = `Zugänge für ${activeHostname}:`;
      }
    }
  } catch (e) {
    console.debug("Could not read active tab:", e);
  }
}

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
    return urlStr.toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0].split(":")[0];
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

  // 1. Check item URL
  if (item.url) {
    const itemDomain = extractDomain(item.url);
    const itemBase = getBaseDomain(itemDomain);
    if (itemDomain === currentClean || itemBase === currentBase) return true;
    if (currentClean.endsWith("." + itemDomain) || itemDomain.endsWith("." + currentClean)) return true;
    if (itemDomain.includes(currentBase) || currentClean.includes(itemBase)) return true;
  }

  // 2. Check item Title
  if (item.title && currentName && currentName.length >= 3) {
    const cleanTitle = item.title.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (cleanTitle === currentName || cleanTitle.includes(currentName) || currentName.includes(cleanTitle)) {
      return true;
    }
  }

  return false;
}

// =============================================================
// 5. VAULT CACHE LOADING & RENDERING
// =============================================================

function loadCachedVault() {
  chrome.storage.local.get(["vault_cache", "last_synced", "vault_user"], (res) => {
    allVaultItems = res.vault_cache || [];
    const count = allVaultItems.length;
    const syncInfo = document.getElementById("sync-info");
    const lockBtn = document.getElementById("btn-lock");
    const viewUnlock = document.getElementById("view-unlock");
    const viewMain = document.getElementById("view-main");

    if (count > 0) {
      if (viewUnlock) viewUnlock.style.display = "none";
      if (viewMain) viewMain.style.display = "block";
      if (lockBtn) lockBtn.style.display = "flex";

      if (res.last_synced) {
        const minutesAgo = Math.floor((Date.now() - res.last_synced) / 60000);
        syncInfo.innerText = `${count} Logins (${minutesAgo === 0 ? "gerade" : `vor ${minutesAgo}m`})`;
      } else {
        syncInfo.innerText = `${count} Logins`;
      }
      renderItems();
    } else {
      // Locked or empty: show unlock view
      if (viewUnlock) viewUnlock.style.display = "block";
      if (viewMain) viewMain.style.display = "none";
      if (lockBtn) lockBtn.style.display = "none";
      syncInfo.innerText = "Nicht verbunden";

      if (res.vault_user) {
        const userInput = document.getElementById("popup-login-user");
        if (userInput && !userInput.value) userInput.value = res.vault_user;
      }
    }
  });

  const searchInput = document.getElementById("ext-search");
  if (searchInput) {
    searchInput.addEventListener("input", renderItems);
  }

  const toggleAllBtn = document.getElementById("btn-toggle-all");
  if (toggleAllBtn) {
    toggleAllBtn.addEventListener("click", (e) => {
      e.preventDefault();
      showAllItemsMode = !showAllItemsMode;
      toggleAllBtn.innerText = showAllItemsMode ? "Nur diese Seite" : "Alle anzeigen";
      renderItems();
    });
  }
}

function renderItems() {
  const listEl = document.getElementById("items-list");
  if (!listEl) return;

  const query = (document.getElementById("ext-search")?.value || "").toLowerCase().trim();
  listEl.innerHTML = "";

  if (allVaultItems.length === 0) {
    return;
  }

  // Filter items
  let filtered = allVaultItems.filter(it => {
    if (query) {
      const mTitle = it.title && it.title.toLowerCase().includes(query);
      const mUser = it.username && it.username.toLowerCase().includes(query);
      const mUrl = it.url && it.url.toLowerCase().includes(query);
      return mTitle || mUser || mUrl;
    }

    if (!showAllItemsMode && activeHostname) {
      return matchesDomain(it, activeHostname);
    }

    return true;
  });

  if (filtered.length === 0) {
    if (!showAllItemsMode && activeHostname) {
      listEl.innerHTML = `
        <div style="font-size: 0.8rem; color: #9ca3af; text-align: center; padding: 24px 0;">
          Kein Eintrag für <strong>${escapeHtml(activeHostname)}</strong> gefunden.<br>
          <button class="btn btn-secondary" style="margin-top: 10px; font-size: 0.75rem;" onclick="document.getElementById('btn-toggle-all').click()">
            Alle ${allVaultItems.length} Logins anzeigen
          </button>
        </div>
      `;
    } else {
      listEl.innerHTML = `
        <div style="font-size: 0.8rem; color: #9ca3af; text-align: center; padding: 24px 0;">
          Keine passenden Einträge für deine Suche gefunden.
        </div>
      `;
    }
    return;
  }

  for (const it of filtered) {
    const card = document.createElement("div");
    card.className = "item-card";

    card.innerHTML = `
      <div class="item-header">
        <div class="item-title" title="${escapeHtml(it.title)}">${escapeHtml(it.title)}</div>
        ${it.favorite ? '<span style="color: #fbbf24; font-size: 11px;">⭐</span>' : ''}
      </div>
      <div class="item-user" title="${escapeHtml(it.username || '')}">
        ${escapeHtml(it.username || 'Kein Benutzername')}
      </div>
      <div class="actions">
        <button class="btn btn-autofill">⚡ Ausfüllen</button>
        <button class="btn btn-secondary btn-copy-pwd" title="Passwort kopieren">🔑</button>
        ${it.totp ? '<button class="btn btn-secondary btn-totp" title="2FA Code kopieren">⏱️ 2FA</button>' : ''}
      </div>
    `;

    // Action handlers
    card.querySelector(".btn-autofill").onclick = () => executeAutofill(it.username, it.password);
    card.querySelector(".btn-copy-pwd").onclick = () => copyText(it.password, "Passwort kopiert! ✓");

    const totpBtn = card.querySelector(".btn-totp");
    if (totpBtn) {
      totpBtn.onclick = () => handleTotpCopy(it.totp);
    }

    listEl.appendChild(card);
  }
}

// =============================================================
// 6. DIRECT LOGIN & UNLOCK
// =============================================================

function setupLoginForm() {
  const form = document.getElementById("popup-login-form");
  const btnLogin = document.getElementById("btn-popup-login");
  const btnTabSync = document.getElementById("btn-popup-tab-sync");
  const btnOpenWeb = document.getElementById("btn-open-web-vault");

  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const user = document.getElementById("popup-login-user").value.trim();
      const pass = document.getElementById("popup-login-pass").value;
      const totp = document.getElementById("popup-login-totp").value.trim();

      if (!user || !pass) return;

      btnLogin.disabled = true;
      btnLogin.innerText = "⏳ Entschlüssele Tresor...";

      try {
        await loginAndSyncDirectly(user, pass, totp);
      } catch (err) {
        showToast(err.message, "error");
      } finally {
        btnLogin.disabled = false;
        btnLogin.innerText = "🔓 Anmelden & Synchronisieren";
      }
    });
  }

  if (btnTabSync) {
    btnTabSync.addEventListener("click", async () => {
      btnTabSync.disabled = true;
      btnTabSync.innerText = "⏳ Synchronisiere...";
      await triggerOpenAndSyncVault();
      setTimeout(() => {
        btnTabSync.disabled = false;
        btnTabSync.innerText = "🔄 Aus geöffnetem Web-Tab laden";
        loadCachedVault();
      }, 1000);
    });
  }

  if (btnOpenWeb) {
    btnOpenWeb.addEventListener("click", () => {
      chrome.tabs.create({ url: SERVER_URL });
    });
  }
}

async function loginAndSyncDirectly(username, password, totpCode) {
  // Step 1: Login Init
  const initRes = await fetch(`${SERVER_URL}/api/auth/login-init`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username })
  });
  const initData = await initRes.json();
  if (!initRes.ok) throw new Error(initData.detail || "Benutzer existiert nicht");

  // Show 2FA input immediately if enabled on this account to prevent rate limit penalties
  if (initData.totp_required && !totpCode) {
    const totpRow = document.getElementById("popup-login-totp-row");
    if (totpRow) totpRow.style.display = "block";
    const totpInput = document.getElementById("popup-login-totp");
    if (totpInput) totpInput.focus();
    throw new Error("2FA aktiv: Bitte 6-stelligen Code eingeben");
  }

  // Step 2: Derive Keys
  const salts = (initData.auth_salt || "").split(":");
  const clientSalt = salts[0];
  const clientAuthKey = await deriveClientAuthKey(password, clientSalt);
  const encKey = await deriveMasterEncryptionKey(password, initData.enc_salt);

  // Step 3: Login Verify
  const verifyRes = await fetch(`${SERVER_URL}/api/auth/login-verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username,
      client_auth_key: clientAuthKey,
      totp_code: totpCode || null
    })
  });
  const verifyData = await verifyRes.json();

  if (!verifyRes.ok) {
    if (verifyRes.status === 403 && verifyData.detail === "2FA_REQUIRED") {
      document.getElementById("popup-login-totp-row").style.display = "block";
      document.getElementById("popup-login-totp").focus();
      throw new Error("2FA aktiv: Bitte 6-stelligen Code eingeben");
    }
    throw new Error(verifyData.detail || "Falsches Master-Passwort");
  }

  // Step 4: Fetch Vault Items
  const itemsRes = await fetch(`${SERVER_URL}/api/vault/items`, {
    headers: { "Authorization": `Bearer ${verifyData.token}` }
  });
  const rawItems = await itemsRes.json();

  // Step 5: Decrypt Logins
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
      } catch (err) {
        console.error("Decrypt error on item", it.id, err);
      }
    }
  }

  // Step 6: Save in extension storage
  await chrome.storage.local.set({
    vault_cache: logins,
    vault_user: username,
    last_synced: Date.now()
  });

  allVaultItems = logins;
  loadCachedVault();
  showToast(`Erfolgreich! ${logins.length} Logins bereit.`);
}

function lockExtension() {
  chrome.storage.local.set({ vault_cache: [] }, () => {
    allVaultItems = [];
    loadCachedVault();
    showToast("Erweiterung gesperrt 🔒");
  });
}

// =============================================================
// 7. AUTOFILL TRIGGER
// =============================================================

async function executeAutofill(username, password) {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs[0] || !tabs[0].id) {
      showToast("Kein aktiver Tab gefunden", "error");
      return;
    }
    const tabId = tabs[0].id;
    const tabUrl = tabs[0].url || "";

    if (tabUrl.startsWith("chrome://") || tabUrl.startsWith("edge://") || tabUrl.startsWith("about:") || tabUrl.startsWith("chrome-extension://")) {
      showToast("Auf Browser-Systemseiten nicht möglich. Nutze '🔑 Kopieren'.", "error");
      return;
    }

    // Try messaging content script
    chrome.tabs.sendMessage(tabId, { action: "AUTOFILL", username, password }, async (res) => {
      if (chrome.runtime.lastError || !res) {
        // Content script was not present -> inject dynamically
        try {
          await chrome.scripting.executeScript({
            target: { tabId: tabId, allFrames: true },
            files: ["content.js"]
          });
          setTimeout(() => {
            chrome.tabs.sendMessage(tabId, { action: "AUTOFILL", username, password }, (retryRes) => {
              processAutofillResult(retryRes);
            });
          }, 150);
          return;
        } catch (injectErr) {
          showToast("Konnte Tab nicht ansteuern. Nutze '🔑 Kopieren'.", "error");
          return;
        }
      }
      processAutofillResult(res);
    });
  } catch (err) {
    showToast("Fehler beim Ausfüllen: " + err.message, "error");
  }
}

function processAutofillResult(res) {
  if (res && res.status === "ok") {
    showToast("✓ Zugangsdaten ausgefüllt!");
    setTimeout(() => {
      window.close();
    }, 450);
  } else {
    const msg = (res && res.message) ? res.message : "Kein Anmeldefeld auf der Seite gefunden.";
    showToast("⚠️ " + msg + " (Nutze '🔑')", "error");
  }
}

// =============================================================
// 8. TOTP (2FA) COMPUTATION & COPY
// =============================================================

function cleanTotpSecret(secret) {
  if (!secret) return "";
  let clean = secret.trim();
  if (clean.toLowerCase().startsWith("otpauth://")) {
    try {
      const u = new URL(clean);
      const s = u.searchParams.get("secret");
      if (s) clean = s;
    } catch (e) {
      const m = clean.match(/secret=([^&]+)/i);
      if (m) clean = m[1];
    }
  } else if (clean.includes("secret=")) {
    const m = clean.match(/secret=([^&]+)/i);
    if (m) clean = m[1];
  }
  return clean.replace(/[\s\-]/g, "").toUpperCase();
}

function base32ToBuffer(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let cleaned = base32.toUpperCase().replace(/=+$/, "").replace(/[\s\-]/g, "");
  let length = cleaned.length;
  let bits = 0;
  let value = 0;
  let index = 0;
  let output = new Uint8Array(Math.floor((length * 5) / 8));

  for (let i = 0; i < length; i++) {
    const char = cleaned[i];
    const val = alphabet.indexOf(char);
    if (val === -1) continue;
    value = (value << 5) | val;
    bits += 5;
    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }
  return output.buffer;
}

async function generateTotpInBrowser(secret) {
  const clean = cleanTotpSecret(secret);
  const keyBuffer = base32ToBuffer(clean);
  const epoch = Math.floor(Date.now() / 1000);
  const timeStep = Math.floor(epoch / 30);
  const rem = 30 - (epoch % 30);

  const timeBuffer = new ArrayBuffer(8);
  const timeView = new DataView(timeBuffer);
  timeView.setUint32(4, timeStep, false);

  const cryptoKey = await window.crypto.subtle.importKey(
    "raw",
    keyBuffer,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );

  const signature = await window.crypto.subtle.sign("HMAC", cryptoKey, timeBuffer);
  const sigBytes = new Uint8Array(signature);
  const offset = sigBytes[sigBytes.length - 1] & 0x0f;

  const binary =
    ((sigBytes[offset] & 0x7f) << 24) |
    ((sigBytes[offset + 1] & 0xff) << 16) |
    ((sigBytes[offset + 2] & 0xff) << 8) |
    (sigBytes[offset + 3] & 0xff);

  const otp = (binary % 1000000).toString().padStart(6, "0");
  return { code: otp, remaining_seconds: rem };
}

async function handleTotpCopy(secret) {
  if (!secret) return;

  const clean = cleanTotpSecret(secret);

  // 1. Try local backend server first
  try {
    const res = await fetch(`${SERVER_URL}/api/tools/totp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret: clean })
    });

    if (res.ok) {
      const data = await res.json();
      if (data.code) {
        copyText(data.code, `2FA: ${data.code} kopiert! (${data.remaining_seconds}s)`);
        return;
      }
    }
  } catch (e) {
    // Backend offline or error -> fallback below
  }

  // 2. Client-side WebCrypto HMAC-SHA1 fallback
  try {
    const localTotp = await generateTotpInBrowser(clean);
    if (localTotp && localTotp.code) {
      copyText(localTotp.code, `2FA: ${localTotp.code} kopiert! (${localTotp.remaining_seconds}s)`);
      return;
    }
  } catch (err) {
    console.error("Local TOTP error:", err);
  }

  // 3. Fallback: Copy secret string
  copyText(clean, "2FA Schlüssel kopiert!");
}

// =============================================================
// 9. HEADER BUTTONS & SYNC
// =============================================================

function setupHeaderButtons() {
  const syncBtn = document.getElementById("btn-sync");
  const lockBtn = document.getElementById("btn-lock");

  if (syncBtn) {
    syncBtn.addEventListener("click", async () => {
      syncBtn.classList.add("spinning");
      await triggerOpenAndSyncVault();
      setTimeout(() => {
        syncBtn.classList.remove("spinning");
        loadCachedVault();
        showToast("Sync abgeschlossen ✓");
      }, 1000);
    });
  }

  if (lockBtn) {
    lockBtn.addEventListener("click", lockExtension);
  }
}

async function triggerOpenAndSyncVault() {
  try {
    const tabs = await chrome.tabs.query({});
    const vaultTab = tabs.find(t => t.url && (t.url.includes("127.0.0.1:8000") || t.url.includes("localhost:8000")));

    if (vaultTab && vaultTab.id) {
      chrome.tabs.sendMessage(vaultTab.id, { action: "TRIGGER_VAULT_PAGE_SYNC" }, () => {});
    } else {
      chrome.tabs.create({ url: SERVER_URL });
    }
  } catch (e) {
    chrome.tabs.create({ url: SERVER_URL });
  }
}

// =============================================================
// 10. IN-POPUP PASSWORD GENERATOR
// =============================================================

function setupGenerator() {
  const slider = document.getElementById("gen-len-slider");
  const lenVal = document.getElementById("gen-len-val");
  const btnRefresh = document.getElementById("btn-gen-refresh");
  const btnCopy = document.getElementById("btn-gen-copy");
  const btnAutofill = document.getElementById("btn-gen-autofill");

  if (!slider) return;

  slider.addEventListener("input", () => {
    lenVal.innerText = slider.value;
    generateNewPassword();
  });

  ["gen-opt-upper", "gen-opt-lower", "gen-opt-numbers", "gen-opt-symbols"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("change", generateNewPassword);
  });

  if (btnRefresh) btnRefresh.onclick = generateNewPassword;
  if (btnCopy) btnCopy.onclick = () => copyText(currentGeneratedPassword, "Passwort kopiert! ✓");
  if (btnAutofill) {
    btnAutofill.onclick = () => {
      executeAutofill("", currentGeneratedPassword);
    };
  }

  generateNewPassword();
}

function generateNewPassword() {
  const len = parseInt(document.getElementById("gen-len-slider")?.value || "20", 10);
  const up = document.getElementById("gen-opt-upper")?.checked ?? true;
  const low = document.getElementById("gen-opt-lower")?.checked ?? true;
  const num = document.getElementById("gen-opt-numbers")?.checked ?? true;
  const sym = document.getElementById("gen-opt-symbols")?.checked ?? true;

  let chars = "";
  if (up) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (low) chars += "abcdefghijklmnopqrstuvwxyz";
  if (num) chars += "0123456789";
  if (sym) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";

  if (!chars) chars = "abcdefghijklmnopqrstuvwxyz";

  const randomValues = new Uint32Array(len);
  window.crypto.getRandomValues(randomValues);

  let pwd = "";
  for (let i = 0; i < len; i++) {
    pwd += chars[randomValues[i] % chars.length];
  }

  currentGeneratedPassword = pwd;
  const out = document.getElementById("gen-pwd-output");
  if (out) out.innerText = pwd;
}

// =============================================================
// 11. UI HELPERS
// =============================================================

function setupTabs() {
  const btnLogins = document.getElementById("tab-btn-logins");
  const btnGen = document.getElementById("tab-btn-generator");
  const viewLogins = document.getElementById("view-logins");
  const viewGen = document.getElementById("view-generator");

  if (!btnLogins || !btnGen) return;

  btnLogins.addEventListener("click", () => {
    btnLogins.classList.add("active");
    btnGen.classList.remove("active");
    viewLogins.style.display = "block";
    viewGen.style.display = "none";
  });

  btnGen.addEventListener("click", () => {
    btnGen.classList.add("active");
    btnLogins.classList.remove("active");
    viewLogins.style.display = "none";
    viewGen.style.display = "block";
    generateNewPassword();
  });
}

function copyText(txt, msg = "In Zwischenablage kopiert! ✓") {
  if (!txt) return;
  navigator.clipboard.writeText(txt).then(() => {
    showToast(msg);
  });
}

function showToast(msg) {
  const toast = document.getElementById("popup-toast");
  if (!toast) return;
  toast.innerText = msg;
  toast.classList.add("visible");
  setTimeout(() => {
    toast.classList.remove("visible");
  }, 1800);
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
