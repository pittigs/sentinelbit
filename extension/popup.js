/**
 * sentinelbit Browser Extension - Full Popup Controller
 * - Direct In-Extension Login & Zero-Knowledge AES-256 Decryption
 * - Two-Way Web Vault Tab Synchronization Bridge
 * - Smart Subdomain & Domain Matching
 * - Real 6-digit TOTP 2FA Code Generation & Clipboard Copy
 * - Password Generator with 1-Click Page Autofill
 */

let SERVER_URL = "http://127.0.0.1:8000";

async function loadServerUrl() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["server_url"], (res) => {
      if (res && res.server_url) {
        SERVER_URL = res.server_url;
      }
      const footerLink = document.getElementById("footer-vault-link");
      if (footerLink) footerLink.href = SERVER_URL;
      resolve(SERVER_URL);
    });
  });
}

let allVaultItems = [];
let allVaultPasskeys = [];
let activeHostname = "";
let showAllItemsMode = false;
let showAllPasskeysMode = false;
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
  await loadServerUrl();
  setupTabs();
  setupGenerator();
  setupHeaderButtons();
  setupLoginForm();
  setupPinUnlock();
  setupKeyboardNavigation();
  setupSettings();

  await checkServerHealth();
  await detectActiveTab();
  await loadCachedVault();
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

async function loadCachedVault() {
  chrome.runtime.sendMessage({ action: "TOUCH_ACTIVITY" }, () => {});

  let items = [];
  let passkeys = [];
  if (chrome.storage.session) {
    const sess = await new Promise(r => chrome.storage.session.get(["vault_cache", "vault_passkeys"], r));
    if (sess && sess.vault_cache) items = sess.vault_cache;
    if (sess && sess.vault_passkeys) passkeys = sess.vault_passkeys;
  }
  // Check if legacy fallback exists in local storage
  if (items.length === 0) {
    const local = await new Promise(r => chrome.storage.local.get(["vault_cache", "vault_passkeys"], r));
    if (local && local.vault_cache && local.vault_cache.length > 0) {
      items = local.vault_cache;
      if (chrome.storage.session) {
        await new Promise(r => chrome.storage.session.set({ vault_cache: items }, r));
        await new Promise(r => chrome.storage.local.remove(["vault_cache"], r));
      }
    }
    if (local && local.vault_passkeys && local.vault_passkeys.length > 0) {
      passkeys = local.vault_passkeys;
      if (chrome.storage.session) {
        await new Promise(r => chrome.storage.session.set({ vault_passkeys: passkeys }, r));
        await new Promise(r => chrome.storage.local.remove(["vault_passkeys"], r));
      }
    }
  }

  const meta = await new Promise(r => chrome.storage.local.get(["last_synced", "vault_user"], r));

  allVaultItems = items;
  allVaultPasskeys = passkeys;
  const count = allVaultItems.length;
  const pkCount = allVaultPasskeys.length;
  const syncInfo = document.getElementById("sync-info");
  const lockBtn = document.getElementById("btn-lock");
  const viewUnlock = document.getElementById("view-unlock");
  const viewMain = document.getElementById("view-main");
  const viewSettings = document.getElementById("view-settings");

  if (viewSettings) viewSettings.style.display = "none";

  if (count > 0 || pkCount > 0) {
    if (viewUnlock) viewUnlock.style.display = "none";
    if (viewMain) viewMain.style.display = "block";
    if (lockBtn) lockBtn.style.display = "flex";

    const pkBadge = pkCount > 0 ? ` · ${pkCount} ⚡ Passkeys` : '';
    if (meta.last_synced) {
      const minutesAgo = Math.floor((Date.now() - meta.last_synced) / 60000);
      syncInfo.innerText = `${count} Logins${pkBadge} (${minutesAgo === 0 ? "gerade" : `vor ${minutesAgo}m`})`;
    } else {
      syncInfo.innerText = `${count} Logins${pkBadge}`;
    }
    renderItems();
    renderPasskeys();
  } else {
    // Locked or empty: show unlock view
    if (viewUnlock) viewUnlock.style.display = "block";
    if (viewMain) viewMain.style.display = "none";
    if (lockBtn) lockBtn.style.display = "none";
    syncInfo.innerText = "Nicht verbunden / Gesperrt";

    const pinData = await new Promise(r => chrome.storage.local.get(["pin_hash", "pin_encrypted_vault"], r));
    const pinBox = document.getElementById("popup-pin-box");
    const loginForm = document.getElementById("popup-login-form");
    if (pinData && pinData.pin_hash && pinData.pin_encrypted_vault) {
      if (pinBox) pinBox.style.display = "block";
      if (loginForm) loginForm.style.display = "none";
      const pinInput = document.getElementById("popup-pin-input");
      if (pinInput) {
        pinInput.value = "";
        pinInput.focus();
      }
    } else {
      if (pinBox) pinBox.style.display = "none";
      if (loginForm) loginForm.style.display = "block";
    }

    if (meta.vault_user) {
      const userInput = document.getElementById("popup-login-user");
      if (userInput && !userInput.value) userInput.value = meta.vault_user;
    }
  }

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

  const pkSearchInput = document.getElementById("passkey-search");
  if (pkSearchInput) {
    pkSearchInput.addEventListener("input", renderPasskeys);
  }

  const toggleAllPkBtn = document.getElementById("btn-toggle-all-passkeys");
  if (toggleAllPkBtn) {
    toggleAllPkBtn.addEventListener("click", (e) => {
      e.preventDefault();
      showAllPasskeysMode = !showAllPasskeysMode;
      toggleAllPkBtn.innerText = showAllPasskeysMode ? "Nur diese Seite" : "Alle anzeigen";
      renderPasskeys();
    });
  }
}

function renderItems() {
  const listEl = document.getElementById("items-list");
  if (!listEl) return;

  const query = (document.getElementById("ext-search")?.value || "").toLowerCase().trim();
  listEl.innerHTML = "";

  // If there are matching passkeys for this domain, highlight them at the top
  if (!showAllItemsMode && activeHostname && allVaultPasskeys.length > 0 && !query) {
    const matchingPk = allVaultPasskeys.filter(pk => matchesDomain({ url: pk.rp_id, title: pk.rp_name }, activeHostname));
    if (matchingPk.length > 0) {
      const pkBanner = document.createElement("div");
      pkBanner.style.padding = "8px 10px";
      pkBanner.style.marginBottom = "8px";
      pkBanner.style.borderRadius = "6px";
      pkBanner.style.background = "rgba(139, 92, 246, 0.15)";
      pkBanner.style.border = "1px solid rgba(139, 92, 246, 0.35)";
      pkBanner.style.display = "flex";
      pkBanner.style.alignItems = "center";
      pkBanner.style.justifyContent = "space-between";
      pkBanner.innerHTML = `
        <span style="font-size: 0.76rem; color: #c4b5fd; font-weight: 600;">
          ⚡ ${matchingPk.length} FIDO2 Passkey aktiv
        </span>
        <button class="btn btn-secondary" id="btn-goto-pk-tab" style="padding: 2px 8px; font-size: 0.72rem;">
          Anzeigen
        </button>
      `;
      listEl.appendChild(pkBanner);
      pkBanner.querySelector("#btn-goto-pk-tab")?.addEventListener("click", () => {
        document.getElementById("tab-btn-passkeys")?.click();
      });
    }
  }

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
      listEl.innerHTML += `
        <div style="font-size: 0.8rem; color: #9ca3af; text-align: center; padding: 24px 0;">
          Kein Eintrag für <strong>${escapeHtml(activeHostname)}</strong> gefunden.<br>
          <button class="btn btn-secondary" id="btn-show-all-empty" style="margin-top: 10px; font-size: 0.75rem;">
            Alle ${allVaultItems.length} Logins anzeigen
          </button>
        </div>
      `;
      document.getElementById("btn-show-all-empty")?.addEventListener("click", () => {
        document.getElementById("btn-toggle-all")?.click();
      });
    } else {
      listEl.innerHTML += `
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

    if (it.type === "card") {
      const cardNum = it.cardNumber || (it.data && it.data.cardNumber) || "";
      const last4 = cardNum.replace(/\s+/g, "").slice(-4);
      card.innerHTML = `
        <div class="item-header">
          <div class="item-title" title="${escapeHtml(it.title)}">💳 ${escapeHtml(it.title)}</div>
          ${it.favorite ? '<span style="color: #fbbf24; font-size: 11px;">⭐</span>' : ''}
        </div>
        <div class="item-user" title="${escapeHtml(cardNum)}">
          •••• •••• •••• ${last4 || 'Karte'}
        </div>
        <div class="actions">
          <button class="btn btn-autofill btn-fill-card">💳 Ausfüllen</button>
          <button class="btn btn-secondary btn-copy-card" title="Kartennummer kopieren">📋</button>
          <button class="btn btn-secondary btn-copy-cvv" title="CVV kopieren">🔒</button>
        </div>
      `;
      card.querySelector(".btn-fill-card").onclick = () => executeCardAutofill(it.data || it);
      card.querySelector(".btn-copy-card").onclick = () => copyText(cardNum, "Kartennummer kopiert! ✓");
      card.querySelector(".btn-copy-cvv").onclick = () => copyText(it.cvv || (it.data && it.data.cvv) || "", "CVV kopiert! ✓", true);
    } else {
      card.innerHTML = `
        <div class="item-header">
          <div class="item-title" title="${escapeHtml(it.title)}">${escapeHtml(it.title)}</div>
          ${it.favorite ? '<span style="color: #fbbf24; font-size: 11px;">⭐</span>' : ''}
        </div>
        <div class="item-user" title="${escapeHtml(it.username || '')}">
          <span draggable="true" class="drag-badge" data-drag="${escapeHtml(it.username || '')}" title="Ziehen zum Einfügen" style="cursor: grab;">👤 ${escapeHtml(it.username || 'Kein Benutzername')}</span>
        </div>
        <div class="actions">
          <button class="btn btn-autofill">⚡ Ausfüllen</button>
          <button class="btn btn-secondary btn-copy-pwd" draggable="true" data-drag="${escapeHtml(it.password || '')}" title="Passwort kopieren oder direkt ins Feld ziehen" style="cursor: grab;">🔑</button>
          ${it.totp ? `<button class="btn btn-secondary btn-totp" draggable="true" data-drag="${escapeHtml(it.totp || '')}" title="2FA Code kopieren oder ziehen" style="cursor: grab;">⏱️ 2FA</button>` : ''}
        </div>
      `;

      card.querySelectorAll("[draggable='true']").forEach(el => {
        el.addEventListener("dragstart", (e) => {
          const val = el.getAttribute("data-drag");
          if (val) e.dataTransfer.setData("text/plain", val);
        });
      });

      // Action handlers: automatically include TOTP when autofilling
      card.querySelector(".btn-autofill").onclick = () => executeAutofill(it.username, it.password, it.totp);
      card.querySelector(".btn-copy-pwd").onclick = () => copyText(it.password, "Passwort kopiert! ✓");

      const totpBtn = card.querySelector(".btn-totp");
      if (totpBtn) {
        totpBtn.onclick = () => handleTotpCopy(it.totp);
      }
    }

    listEl.appendChild(card);
  }
}

function renderPasskeys() {
  const listEl = document.getElementById("passkeys-list");
  if (!listEl) return;

  const query = (document.getElementById("passkey-search")?.value || "").toLowerCase().trim();
  listEl.innerHTML = "";

  if (allVaultPasskeys.length === 0) {
    listEl.innerHTML = `
      <div style="font-size: 0.8rem; color: #9ca3af; text-align: center; padding: 24px 0;">
        Keine FIDO2 Passkeys hinterlegt.
      </div>
    `;
    return;
  }

  let filtered = allVaultPasskeys.filter(pk => {
    if (query) {
      const mRp = (pk.rp_name && pk.rp_name.toLowerCase().includes(query)) || (pk.rp_id && pk.rp_id.toLowerCase().includes(query));
      const mUser = pk.username && pk.username.toLowerCase().includes(query);
      return mRp || mUser;
    }

    if (!showAllPasskeysMode && activeHostname) {
      return matchesDomain({ url: pk.rp_id, title: pk.rp_name }, activeHostname);
    }

    return true;
  });

  if (filtered.length === 0) {
    if (!showAllPasskeysMode && activeHostname) {
      listEl.innerHTML = `
        <div style="font-size: 0.8rem; color: #9ca3af; text-align: center; padding: 24px 0;">
          Kein Passkey für <strong>${escapeHtml(activeHostname)}</strong> gefunden.<br>
          <button class="btn btn-secondary" id="btn-show-all-pk-empty" style="margin-top: 10px; font-size: 0.75rem;">
            Alle ${allVaultPasskeys.length} Passkeys anzeigen
          </button>
        </div>
      `;
      document.getElementById("btn-show-all-pk-empty")?.addEventListener("click", () => {
        document.getElementById("btn-toggle-all-passkeys")?.click();
      });
    } else {
      listEl.innerHTML = `
        <div style="font-size: 0.8rem; color: #9ca3af; text-align: center; padding: 24px 0;">
          Keine passenden Passkeys gefunden.
        </div>
      `;
    }
    return;
  }

  for (const pk of filtered) {
    const card = document.createElement("div");
    card.className = "item-card";
    card.style.border = "1px solid rgba(139, 92, 246, 0.4)";
    card.style.background = "rgba(139, 92, 246, 0.08)";

    card.innerHTML = `
      <div class="item-header">
        <div class="item-title" style="color: #c4b5fd;" title="${escapeHtml(pk.rp_name || pk.rp_id)}">⚡ ${escapeHtml(pk.rp_name || pk.rp_id)}</div>
        <span style="font-size: 10px; background: rgba(139, 92, 246, 0.25); color: #c4b5fd; padding: 2px 6px; border-radius: 999px; border: 1px solid rgba(139, 92, 246, 0.35); font-weight: 600;">FIDO2</span>
      </div>
      <div class="item-user" style="color: #cbd5e1;" title="${escapeHtml(pk.username || '')}">
        Benutzer: <strong>${escapeHtml(pk.username || 'Unbekannt')}</strong>
      </div>
      <div style="font-size: 0.72rem; color: #94a3b8; margin-bottom: 8px;">
        ID: <span style="font-family: monospace; color: #a5b4fc;">${escapeHtml((pk.credential_id || '').substring(0, 16))}...</span>
      </div>
      <div class="actions">
        <button class="btn btn-autofill btn-fill-pk" style="background: #7c3aed;">⚡ Ausfüllen</button>
        <button class="btn btn-secondary btn-copy-pk-user" title="Benutzername kopieren">👤</button>
        <button class="btn btn-secondary btn-copy-pk-id" title="Credential ID kopieren">🔑</button>
      </div>
    `;

    card.querySelector(".btn-fill-pk").onclick = () => executeAutofill(pk.username, "", "", pk);
    card.querySelector(".btn-copy-pk-user").onclick = () => copyText(pk.username, "Benutzername kopiert! ✓");
    card.querySelector(".btn-copy-pk-id").onclick = () => copyText(pk.credential_id, "Credential ID kopiert! ✓");

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

  // Step 4b: Fetch Passkeys
  let passkeys = [];
  try {
    const pkRes = await fetch(`${SERVER_URL}/api/passkeys`, {
      headers: { "Authorization": `Bearer ${verifyData.token}` }
    });
    if (pkRes.ok) {
      passkeys = await pkRes.json();
    }
  } catch (pkErr) {
    console.debug("Could not fetch passkeys:", pkErr);
  }

  // Step 4c: Decrypt Passkeys (support Sentinelbit AES-GCM envelope & Vaultwarden/Bitwarden raw keys)
  for (const pk of passkeys) {
    let privKey = null;
    if (pk.encrypted_private_key) {
      if (typeof pk.encrypted_private_key === "string" && pk.encrypted_private_key.startsWith("{") && pk.encrypted_private_key.includes('"iv"')) {
        try {
          const dec = await decryptPayload(pk.encrypted_private_key, encKey);
          if (dec) {
            privKey = dec.private_pem || dec.raw_key || (typeof dec === "string" ? dec : null);
          }
        } catch (e) {
          console.debug("Could not decrypt passkey envelope:", e);
        }
      } else {
        // Vaultwarden / Bitwarden raw key string
        privKey = pk.encrypted_private_key;
      }
    }
    pk.decrypted_private_key = privKey;
  }

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

  // Step 6: Save decrypted items and passkeys strictly in-memory (session storage)
  if (chrome.storage.session) {
    await chrome.storage.session.set({
      vault_cache: logins,
      vault_passkeys: passkeys,
      vault_token: verifyData.token
    });
  }
  // Store only non-sensitive metadata in persistent local storage
  await chrome.storage.local.set({
    vault_user: username,
    last_synced: Date.now()
  });
  // Purge any legacy plain passwords from persistent storage
  await new Promise(r => chrome.storage.local.remove(["vault_cache", "vault_passkeys"], r));

  allVaultItems = logins;
  allVaultPasskeys = passkeys;
  chrome.runtime.sendMessage({ action: "VAULT_UNLOCKED" }, () => {});
  await loadCachedVault();
  showToast(`Erfolgreich! ${logins.length} Logins & ${passkeys.length} Passkeys bereit.`);
}

async function lockExtension() {
  if (chrome.storage.session) {
    await chrome.storage.session.clear();
  }
  await new Promise(r => chrome.storage.local.remove(["vault_cache", "vault_passkeys"], r));
  allVaultItems = [];
  allVaultPasskeys = [];
  chrome.runtime.sendMessage({ action: "VAULT_LOCKED" }, () => {});
  await loadCachedVault();
  showToast("Erweiterung gesperrt 🔒");
}

// =============================================================
// 7. AUTOFILL TRIGGER
// =============================================================

async function executeAutofill(username, password, totp = "", passkey = null) {
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

    // If totp is present, immediately copy it to clipboard so it's ready for step 2!
    if (totp) {
      handleTotpCopy(totp);
    }

    // Try messaging content script
    chrome.tabs.sendMessage(tabId, { action: "AUTOFILL", username, password, totp, passkey }, async (res) => {
      if (chrome.runtime.lastError || !res) {
        // Content script was not present -> inject dynamically
        try {
          await chrome.scripting.executeScript({
            target: { tabId: tabId, allFrames: true },
            files: ["content.js"]
          });
          setTimeout(() => {
            chrome.tabs.sendMessage(tabId, { action: "AUTOFILL", username, password, totp, passkey }, (retryRes) => {
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

async function executeCardAutofill(cardData) {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs[0] || !tabs[0].id) {
      showToast("Kein aktiver Tab gefunden", "error");
      return;
    }
    const tabId = tabs[0].id;
    const tabUrl = tabs[0].url || "";

    if (tabUrl.startsWith("chrome://") || tabUrl.startsWith("edge://") || tabUrl.startsWith("about:") || tabUrl.startsWith("chrome-extension://")) {
      showToast("Auf Browser-Systemseiten nicht möglich.", "error");
      return;
    }

    chrome.tabs.sendMessage(tabId, { action: "AUTOFILL_CARD", card: cardData }, async (res) => {
      if (chrome.runtime.lastError || !res) {
        try {
          await chrome.scripting.executeScript({
            target: { tabId: tabId, allFrames: true },
            files: ["content.js"]
          });
          setTimeout(() => {
            chrome.tabs.sendMessage(tabId, { action: "AUTOFILL_CARD", card: cardData }, (retryRes) => {
              if (retryRes && retryRes.status === "ok") {
                showToast("✓ Kartendaten ausgefüllt!");
                setTimeout(() => window.close(), 450);
              } else {
                showToast("⚠️ " + (retryRes ? retryRes.message : "Keine Kreditkartenfelder gefunden"), "error");
              }
            });
          }, 150);
          return;
        } catch (e) {
          showToast("Konnte Tab nicht ansteuern.", "error");
          return;
        }
      }

      if (res && res.status === "ok") {
        showToast("✓ Kartendaten ausgefüllt!");
        setTimeout(() => window.close(), 450);
      } else {
        showToast("⚠️ " + (res ? res.message : "Keine Kreditkartenfelder gefunden"), "error");
      }
    });
  } catch (err) {
    showToast("Fehler beim Ausfüllen: " + err.message, "error");
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
  const settingsBtn = document.getElementById("btn-settings");
  const sidepanelBtn = document.getElementById("btn-sidepanel");

  if (sidepanelBtn) {
    sidepanelBtn.addEventListener("click", () => {
      chrome.runtime.sendMessage({ action: "OPEN_SIDEPANEL" }, () => {});
      window.close();
    });
  }

  if (syncBtn) {
    syncBtn.addEventListener("click", async () => {
      syncBtn.classList.add("spinning");
      await triggerOpenAndSyncVault();
      setTimeout(async () => {
        syncBtn.classList.remove("spinning");
        await loadCachedVault();
        showToast("Sync abgeschlossen ✓");
      }, 1000);
    });
  }

  if (lockBtn) {
    lockBtn.addEventListener("click", lockExtension);
  }

  if (settingsBtn) {
    settingsBtn.addEventListener("click", () => {
      const settingsView = document.getElementById("view-settings");
      if (!settingsView) return;
      const isOpen = settingsView.style.display === "block";
      settingsView.style.display = isOpen ? "none" : "block";
      if (!isOpen) {
        document.getElementById("setting-server-url").value = SERVER_URL;
        chrome.storage.local.get(["auto_lock_minutes", "clipboard_clear_seconds", "auto_submit", "excluded_domains", "pin_hash"], (res) => {
          if (res) {
            if (res.auto_lock_minutes !== undefined) document.getElementById("setting-autolock").value = String(res.auto_lock_minutes);
            if (res.clipboard_clear_seconds !== undefined) document.getElementById("setting-clipboard-clear").value = String(res.clipboard_clear_seconds);
            if (res.auto_submit !== undefined) document.getElementById("setting-auto-submit").checked = Boolean(res.auto_submit);
            if (res.excluded_domains) document.getElementById("setting-excluded-domains").value = res.excluded_domains;
            const pinInput = document.getElementById("setting-pin-code");
            if (pinInput) {
              pinInput.value = "";
              pinInput.placeholder = res.pin_hash ? "PIN aktiv (leer lassen = behalten)" : "PIN leer lassen zum Deaktivieren";
            }
          }
        });
      }
    });
  }
}

function setupSettings() {
  const btnClose = document.getElementById("btn-close-settings");
  const btnSave = document.getElementById("btn-save-settings");
  const btnTest = document.getElementById("btn-test-connection");
  const statusMsg = document.getElementById("settings-status-msg");

  if (btnClose) {
    btnClose.addEventListener("click", () => {
      const settingsView = document.getElementById("view-settings");
      if (settingsView) settingsView.style.display = "none";
    });
  }

  if (btnTest) {
    btnTest.addEventListener("click", async () => {
      const inputUrl = (document.getElementById("setting-server-url").value || "").trim().replace(/\/+$/, "");
      if (!inputUrl) {
        statusMsg.innerText = "Bitte eine gültige URL angeben";
        statusMsg.style.color = "#f87171";
        return;
      }
      statusMsg.innerText = "⏳ Prüfe Verbindung...";
      statusMsg.style.color = "#9ca3af";
      const start = performance.now();
      try {
        const res = await fetch(`${inputUrl}/api/health`, { method: "GET", cache: "no-store" });
        const latency = Math.round(performance.now() - start);
        if (res.ok) {
          const data = await res.json();
          statusMsg.innerText = `✓ Verbunden (${latency}ms, v${data.version || '3.0.0'})`;
          statusMsg.style.color = "#34d399";
        } else {
          statusMsg.innerText = `Fehler: HTTP ${res.status}`;
          statusMsg.style.color = "#f87171";
        }
      } catch (err) {
        statusMsg.innerText = "Keine Verbindung zum Server möglich";
        statusMsg.style.color = "#f87171";
      }
    });
  }

  if (btnSave) {
    btnSave.addEventListener("click", async () => {
      let inputUrl = (document.getElementById("setting-server-url").value || "").trim().replace(/\/+$/, "");
      if (!inputUrl) inputUrl = "http://127.0.0.1:8000";
      const autolockVal = parseInt(document.getElementById("setting-autolock").value || "15", 10);
      const clipClearVal = parseInt(document.getElementById("setting-clipboard-clear")?.value || "30", 10);
      const autoSubmitVal = document.getElementById("setting-auto-submit")?.checked || false;
      const excludedVal = document.getElementById("setting-excluded-domains")?.value || "";
      const pinCodeVal = (document.getElementById("setting-pin-code")?.value || "").trim();

      SERVER_URL = inputUrl;
      const toSave = {
        server_url: inputUrl,
        auto_lock_minutes: autolockVal,
        clipboard_clear_seconds: clipClearVal,
        auto_submit: autoSubmitVal,
        excluded_domains: excludedVal
      };

      if (pinCodeVal.length >= 4) {
        const pinH = await sha256Hex(pinCodeVal);
        toSave.pin_hash = pinH;
        if (allVaultItems.length > 0 || allVaultPasskeys.length > 0) {
          const pinKey = await deriveKeyFromPin(pinCodeVal);
          const encVault = await encryptPayload({ logins: allVaultItems, passkeys: allVaultPasskeys }, pinKey);
          toSave.pin_encrypted_vault = encVault;
        }
      }

      await new Promise(r => chrome.storage.local.set(toSave, r));

      const footerLink = document.getElementById("footer-vault-link");
      if (footerLink) footerLink.href = SERVER_URL;

      const settingsView = document.getElementById("view-settings");
      if (settingsView) settingsView.style.display = "none";

      await checkServerHealth();
      showToast("Einstellungen gespeichert ✓");
    });
  }
}

async function triggerOpenAndSyncVault() {
  try {
    const tabs = await chrome.tabs.query({});
    let serverOrigin = "http://127.0.0.1:8000";
    try {
      serverOrigin = new URL(SERVER_URL).origin;
    } catch (e) {}

    const vaultTab = tabs.find(t => t.url && (t.url.startsWith(serverOrigin) || t.url.includes("127.0.0.1:8000") || t.url.includes("localhost:8000")));

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
// 10. IN-POPUP PASSWORD & PASSPHRASE GENERATOR
// =============================================================

const DICEWARE_WORDS = [
  "alpen", "adler", "anker", "apfel", "atom", "bahn", "baum", "berg", "blitz", "blume",
  "boot", "bruecke", "burg", "campus", "chaos", "dachs", "diamant", "drache", "duene", "echo",
  "eule", "falke", "feuer", "fluss", "forst", "fuchs", "funke", "garten", "gipfel", "glanz",
  "gold", "hafen", "insel", "jagd", "juwel", "komet", "kristall", "kupfer", "laser", "licht",
  "loewe", "luchs", "magie", "matrix", "mond", "moos", "nacht", "nebel", "nord", "oase",
  "ozean", "palast", "panther", "perle", "pfeil", "planet", "prisma", "quelle", "quarz", "rakete",
  "regen", "ritter", "rubin", "smaragd", "sonne", "spiegel", "sturm", "tann", "tiger", "titan",
  "traum", "turm", "urwald", "vulkan", "wald", "welle", "wind", "wolf", "zenit", "aurora",
  "biber", "dynamik", "element", "galaxie", "horizont", "impuls", "jubel", "kosmos", "meteor",
  "nexus", "orbit", "pulsar", "quantum", "reaktor", "signal", "tempo", "uranus", "vektor", "wirbel",
  "xenon", "antrieb", "chronos", "pegasus", "sirius", "helena", "komet", "saturn", "polaris"
];

let generatorMode = "pwd";

function setupGenerator() {
  const slider = document.getElementById("gen-len-slider");
  const lenVal = document.getElementById("gen-len-val");
  const wordsSlider = document.getElementById("gen-words-slider");
  const wordsVal = document.getElementById("gen-words-val");
  const btnRefresh = document.getElementById("btn-gen-refresh");
  const btnCopy = document.getElementById("btn-gen-copy");
  const btnAutofill = document.getElementById("btn-gen-autofill");
  const btnModePwd = document.getElementById("btn-gen-mode-pwd");
  const btnModePass = document.getElementById("btn-gen-mode-passphrase");
  const rowLen = document.getElementById("row-gen-len");
  const rowWords = document.getElementById("row-gen-words");
  const charOptions = document.getElementById("gen-char-options");

  if (btnModePwd && btnModePass) {
    btnModePwd.onclick = () => {
      generatorMode = "pwd";
      btnModePwd.classList.add("active");
      btnModePass.classList.remove("active");
      if (rowLen) rowLen.style.display = "flex";
      if (rowWords) rowWords.style.display = "none";
      if (charOptions) charOptions.style.display = "grid";
      generateNewPassword();
    };
    btnModePass.onclick = () => {
      generatorMode = "passphrase";
      btnModePass.classList.add("active");
      btnModePwd.classList.remove("active");
      if (rowLen) rowLen.style.display = "none";
      if (rowWords) rowWords.style.display = "flex";
      if (charOptions) charOptions.style.display = "none";
      generateNewPassword();
    };
  }

  if (slider) {
    slider.addEventListener("input", () => {
      if (lenVal) lenVal.innerText = slider.value;
      generateNewPassword();
    });
  }

  if (wordsSlider) {
    wordsSlider.addEventListener("input", () => {
      if (wordsVal) wordsVal.innerText = wordsSlider.value;
      generateNewPassword();
    });
  }

  ["gen-opt-upper", "gen-opt-lower", "gen-opt-numbers", "gen-opt-symbols", "gen-opt-ambiguous"].forEach(id => {
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
  let pwd = "";
  let entropy = 0;

  if (generatorMode === "passphrase") {
    const wordCount = parseInt(document.getElementById("gen-words-slider")?.value || "4", 10);
    const randVals = new Uint32Array(wordCount);
    window.crypto.getRandomValues(randVals);
    const words = [];
    for (let i = 0; i < wordCount; i++) {
      let w = DICEWARE_WORDS[randVals[i] % DICEWARE_WORDS.length];
      if (i === 0) w = w.charAt(0).toUpperCase() + w.slice(1);
      words.push(w);
    }
    const randNum = (randVals[0] % 8) + 2;
    pwd = words.join("-") + "-" + randNum;
    entropy = Math.round(wordCount * Math.log2(DICEWARE_WORDS.length) + Math.log2(8));
  } else {
    const len = parseInt(document.getElementById("gen-len-slider")?.value || "20", 10);
    const up = document.getElementById("gen-opt-upper")?.checked ?? true;
    const low = document.getElementById("gen-opt-lower")?.checked ?? true;
    const num = document.getElementById("gen-opt-numbers")?.checked ?? true;
    const sym = document.getElementById("gen-opt-symbols")?.checked ?? true;
    const avoidAmbiguous = document.getElementById("gen-opt-ambiguous")?.checked ?? false;

    let chars = "";
    if (up) chars += avoidAmbiguous ? "ABCDEFGHJKLMNPQRSTUVWXYZ" : "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (low) chars += avoidAmbiguous ? "abcdefghijkmnopqrstuvwxyz" : "abcdefghijklmnopqrstuvwxyz";
    if (num) chars += avoidAmbiguous ? "23456789" : "0123456789";
    if (sym) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";

    if (!chars) chars = "abcdefghijkmnopqrstuvwxyz";

    const randomValues = new Uint32Array(len);
    window.crypto.getRandomValues(randomValues);

    for (let i = 0; i < len; i++) {
      pwd += chars[randomValues[i] % chars.length];
    }
    entropy = Math.round(len * Math.log2(chars.length));
  }

  currentGeneratedPassword = pwd;
  const out = document.getElementById("gen-pwd-output");
  if (out) out.innerText = pwd;

  // Update entropy UI
  const bar = document.getElementById("gen-entropy-bar");
  const text = document.getElementById("gen-entropy-text");
  if (bar && text) {
    let color = "#ef4444";
    let label = "Schwach 🔴";
    let pct = Math.min(100, Math.round((entropy / 128) * 100));

    if (entropy >= 100) {
      color = "#10b981";
      label = "Quantensicher / Exzellent 🟢";
    } else if (entropy >= 75) {
      color = "#3b82f6";
      label = "Sehr sicher 🔵";
    } else if (entropy >= 50) {
      color = "#f59e0b";
      label = "Solide 🟡";
    }

    bar.style.width = `${pct}%`;
    bar.style.background = color;
    text.innerText = `~${entropy} Bits Entropie (${label})`;
    text.style.color = color;
  }
}

// =============================================================
// 11. KEYBOARD NAVIGATION & PIN UNLOCK
// =============================================================

let selectedItemIndex = -1;

function setupKeyboardNavigation() {
  const searchInput = document.getElementById("ext-search");
  if (!searchInput) return;

  searchInput.addEventListener("keydown", (e) => {
    const listEl = document.getElementById("items-list");
    const cards = listEl ? Array.from(listEl.querySelectorAll(".item-card")) : [];
    if (cards.length === 0) return;

    if (e.key === "ArrowDown") {
      e.preventDefault();
      selectedItemIndex = (selectedItemIndex + 1) % cards.length;
      updateCardHighlight(cards);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      selectedItemIndex = (selectedItemIndex - 1 + cards.length) % cards.length;
      updateCardHighlight(cards);
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (selectedItemIndex >= 0 && selectedItemIndex < cards.length) {
        const fillBtn = cards[selectedItemIndex].querySelector(".btn-autofill");
        if (fillBtn) fillBtn.click();
      } else if (cards.length > 0) {
        const fillBtn = cards[0].querySelector(".btn-autofill");
        if (fillBtn) fillBtn.click();
      }
    }
  });
}

function updateCardHighlight(cards) {
  cards.forEach((c, idx) => {
    if (idx === selectedItemIndex) {
      c.style.borderColor = "#3b82f6";
      c.style.background = "#1e293b";
      c.style.boxShadow = "0 0 8px rgba(59, 130, 246, 0.4)";
      c.scrollIntoView({ block: "nearest", behavior: "smooth" });
    } else {
      c.style.borderColor = "";
      c.style.background = "";
      c.style.boxShadow = "";
    }
  });
}

function setupPinUnlock() {
  const pinBtn = document.getElementById("btn-popup-pin-unlock");
  const pinInput = document.getElementById("popup-pin-input");
  const linkFull = document.getElementById("link-show-full-login");

  if (pinBtn && pinInput) {
    const doPinUnlock = () => {
      const pin = pinInput.value.trim();
      if (pin) unlockWithPin(pin);
    };
    pinBtn.addEventListener("click", doPinUnlock);
    pinInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") doPinUnlock();
    });
  }

  const bioBtn = document.getElementById("btn-popup-bio-unlock");
  if (bioBtn) {
    bioBtn.addEventListener("click", async () => {
      try {
        const cred = await navigator.credentials.get({
          publicKey: {
            challenge: window.crypto.getRandomValues(new Uint8Array(32)),
            timeout: 60000,
            userVerification: "required"
          }
        });
        if (cred) {
          showToast("Biometrie verifiziert! 🔓", "success");
        }
      } catch (err) {
        showToast("Biometrische Prüfung abgebrochen oder nicht verfügbar.", "warning");
      }
    });
  }

  if (linkFull) {
    linkFull.addEventListener("click", (e) => {
      e.preventDefault();
      document.getElementById("popup-pin-box").style.display = "none";
      document.getElementById("popup-login-form").style.display = "block";
    });
  }
}

async function unlockWithPin(pin) {
  const pinData = await new Promise(r => chrome.storage.local.get(["pin_hash", "pin_encrypted_vault"], r));
  if (!pinData || !pinData.pin_hash || !pinData.pin_encrypted_vault) {
    showToast("Kein PIN eingerichtet", "error");
    return;
  }
  const enteredHash = await sha256Hex(pin);
  if (enteredHash !== pinData.pin_hash) {
    showToast("Falscher PIN-Code ❌", "error");
    return;
  }

  try {
    const pinKey = await deriveKeyFromPin(pin);
    const decrypted = await decryptPayload(pinData.pin_encrypted_vault, pinKey);
    if (!decrypted) throw new Error("Entschlüsselung fehlgeschlagen");

    const logins = decrypted.logins || [];
    const passkeys = decrypted.passkeys || [];

    if (chrome.storage.session) {
      await chrome.storage.session.set({
        vault_cache: logins,
        vault_passkeys: passkeys
      });
    }

    allVaultItems = logins;
    allVaultPasskeys = passkeys;
    chrome.runtime.sendMessage({ action: "VAULT_UNLOCKED" }, () => {});
    await loadCachedVault();
    showToast(`Mit PIN entsperrt! 🔓 (${logins.length} Logins)`);
  } catch (e) {
    showToast("Fehler beim Entsperren mit PIN", "error");
  }
}

async function sha256Hex(str) {
  const buf = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return bufferToHex(buf);
}

async function deriveKeyFromPin(pin) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(pin),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode("sentinelbit_pin_fixed_salt_v1"),
      iterations: 50000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptPayload(dataObj, cryptoKey) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(dataObj));
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    cryptoKey,
    encoded
  );
  return {
    iv: bufferToHex(iv),
    data: bufferToHex(ciphertext)
  };
}

// =============================================================
// 12. UI HELPERS
// =============================================================

function setupTabs() {
  const btnLogins = document.getElementById("tab-btn-logins");
  const btnPasskeys = document.getElementById("tab-btn-passkeys");
  const btnGen = document.getElementById("tab-btn-generator");
  const viewLogins = document.getElementById("view-logins");
  const viewPasskeys = document.getElementById("view-passkeys");
  const viewGen = document.getElementById("view-generator");

  if (!btnLogins || !btnGen) return;

  function switchTab(activeBtn, activeView) {
    [btnLogins, btnPasskeys, btnGen].forEach(b => b?.classList.remove("active"));
    [viewLogins, viewPasskeys, viewGen].forEach(v => { if (v) v.style.display = "none"; });
    activeBtn?.classList.add("active");
    if (activeView) activeView.style.display = "block";
  }

  btnLogins.addEventListener("click", () => {
    switchTab(btnLogins, viewLogins);
  });

  if (btnPasskeys) {
    btnPasskeys.addEventListener("click", () => {
      switchTab(btnPasskeys, viewPasskeys);
      renderPasskeys();
    });
  }

  btnGen.addEventListener("click", () => {
    switchTab(btnGen, viewGen);
    generateNewPassword();
  });
}

function copyText(txt, msg = "In Zwischenablage kopiert! ✓") {
  if (!txt) return;
  navigator.clipboard.writeText(txt).then(() => {
    showToast(msg);
    chrome.storage.local.get(["clipboard_clear_seconds"], (res) => {
      const sec = parseInt(res.clipboard_clear_seconds ?? "30", 10);
      if (sec > 0) {
        chrome.runtime.sendMessage({ action: "SCHEDULE_CLIPBOARD_CLEAR", seconds: sec }, () => {});
      }
    });
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

