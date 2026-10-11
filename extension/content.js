/**
 * sentinelbit Browser Extension - Content Script
 * - Bulletproof Autofill Engine for Vanilla HTML, React, Vue, Angular & Shadow DOM
 * - Intelligent Form & Field Pairing
 * - Two-Way Web App Sync Bridge
 */

// =============================================================
// 1. EXTENSION TO WEBPAGE SYNC BRIDGE (http://127.0.0.1:8000)
// =============================================================

const isSentinelBitVaultPage =
  window.location.origin === "http://127.0.0.1:8000" ||
  window.location.origin === "http://localhost:8000" ||
  !!document.querySelector('meta[name="sentinelbit-vault"]') ||
  document.title.toLowerCase().includes("sentinelbit");

if (isSentinelBitVaultPage) {
  // Store detected active server origin in extension storage
  chrome.storage.local.set({ server_url: window.location.origin });

  // Announce extension presence to the web vault securely
  window.postMessage({
    source: "SENTINELBIT_EXTENSION",
    action: "EXTENSION_READY",
    version: "3.0.0"
  }, window.location.origin);

  // Listen for sync messages from the web vault
  window.addEventListener("message", (event) => {
    if (event.source !== window || !event.data) return;

    if (event.data.source === "SENTINELBIT_WEB_APP") {
      if (event.data.action === "SYNC_VAULT") {
        const items = event.data.items || [];
        const passkeys = event.data.passkeys || [];
        const user = event.data.user || "";

        // Send items and passkeys securely to background service worker memory / session storage
        chrome.runtime.sendMessage({
          action: "SET_SESSION_VAULT",
          items: items,
          passkeys: passkeys
        }, () => {});

        // Store only safe metadata in persistent storage (no plain passwords)
        chrome.storage.local.set({
          vault_user: user,
          server_url: window.location.origin,
          last_synced: Date.now()
        }, () => {
          // Clean legacy plain passwords if any existed
          chrome.storage.local.remove(["vault_cache", "vault_passkeys"], () => {});

          window.postMessage({
            source: "SENTINELBIT_EXTENSION",
            action: "SYNC_ACK",
            count: items.length,
            passkeysCount: passkeys.length,
            timestamp: Date.now()
          }, window.location.origin);
        });
      } else if (event.data.action === "CHECK_EXTENSION") {
        window.postMessage({
          source: "SENTINELBIT_EXTENSION",
          action: "EXTENSION_READY",
          version: "3.0.0"
        }, window.location.origin);
      }
    }
  });
}

// =============================================================
// 2. RUNTIME MESSAGE LISTENER (from popup or background)
// =============================================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "AUTOFILL") {
    executeAutofill(request.username, request.password, request.totp, request.passkey).then(result => {
      sendResponse(result);
    });
    return true;
  } else if (request.action === "TRIGGER_VAULT_PAGE_SYNC") {
    if (isSentinelBitVaultPage) {
      window.postMessage({
        source: "SENTINELBIT_EXTENSION",
        action: "REQUEST_SYNC_NOW"
      }, "*");
      sendResponse({ status: "triggered" });
    } else {
      sendResponse({ status: "not_vault_page" });
    }
  } else if (request.action === "VAULT_CACHE_UPDATED") {
    initInPageAutofill();
    sendResponse({ status: "ok" });
  }
  return true;
});

// =============================================================
// 3. SHADOW DOM-AWARE ELEMENT QUERYING & VISIBILITY
// =============================================================

function getAllInputs(root = document) {
  let inputs = [];
  try {
    const directInputs = Array.from(root.querySelectorAll("input"));
    inputs.push(...directInputs);

    // Recursively traverse Shadow DOM roots
    const allElements = root.querySelectorAll("*");
    for (const el of allElements) {
      if (el.shadowRoot) {
        inputs.push(...getAllInputs(el.shadowRoot));
      }
    }
  } catch (e) {
    // Ignore query errors
  }
  return inputs;
}

function isElementFillable(el) {
  if (!el || el.disabled || el.readOnly) return false;
  const type = (el.type || "").toLowerCase();
  if (type === "hidden" || type === "submit" || type === "button" || type === "reset" || type === "checkbox" || type === "radio" || type === "file") {
    return false;
  }

  // Check CSS visibility
  try {
    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden" || parseFloat(style.opacity || "1") < 0.05) {
      return false;
    }
  } catch (e) {}

  // Check element rendering & anti-phishing trap detection (1px traps or offscreen traps)
  const rects = el.getClientRects();
  if (rects.length === 0 && !el.offsetParent) {
    return false;
  }
  const rect = el.getBoundingClientRect();
  if (rect.width > 0 && rect.height > 0 && (rect.width <= 2 || rect.height <= 2)) {
    return false; // 1px trap defense
  }
  if (rect.bottom < -100 || rect.right < -100) {
    return false; // Off-screen honeypot trap
  }

  return true;
}

// =============================================================
// 4. REACT / VUE / ANGULAR / VANILLA INPUT SETTER
// =============================================================

function setInputValue(el, value) {
  if (!el || value === undefined || value === null) return;

  try {
    el.focus();

    // 1. Reset React _valueTracker (React 16-19 synthetic event tracker)
    if (el._valueTracker) {
      el._valueTracker.setValue("");
    }

    // 2. Call native prototype setter to bypass framework wrappers
    const proto = window.HTMLInputElement.prototype;
    const nativeSetter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
    if (nativeSetter) {
      nativeSetter.call(el, value);
    } else {
      el.value = value;
    }

    // 3. Dispatch full event sequence
    el.dispatchEvent(new Event("input", { bubbles: true, cancelable: true }));
    el.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
    el.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, key: "Unidentified" }));
    el.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true, key: "Unidentified" }));

    // 4. Highlight
    highlightElement(el);
  } catch (err) {
    console.error("Error setting input value:", err);
  }
}

function highlightElement(el) {
  try {
    const prevOutline = el.style.outline;
    const prevBoxShadow = el.style.boxShadow;
    const prevTransition = el.style.transition;

    el.style.transition = "outline 0.15s ease, box-shadow 0.15s ease";
    el.style.outline = "2px solid #10b981";
    el.style.boxShadow = "0 0 10px rgba(16, 185, 129, 0.5)";

    setTimeout(() => {
      el.style.outline = prevOutline;
      el.style.boxShadow = prevBoxShadow;
      el.style.transition = prevTransition;
    }, 1200);
  } catch (e) {}
}

// =============================================================
// 5. TOTP (2FA RFC 6238) GENERATOR & CLIPBOARD HELPER
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
  try {
    const clean = cleanTotpSecret(secret);
    if (!clean) return null;
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
  } catch (err) {
    console.debug("TOTP generation error:", err);
    return null;
  }
}

async function copyToClipboard(text) {
  if (!text) return false;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (e) {}
  try {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    textarea.style.top = "-9999px";
    textarea.setAttribute("readonly", "");
    document.body.appendChild(textarea);
    textarea.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(textarea);
    return ok;
  } catch (e) {
    return false;
  }
}

function findOtpInputs(allInputs) {
  const candidates = [];
  for (const el of allInputs) {
    if (!isElementFillable(el)) continue;
    const t = (el.type || "").toLowerCase();
    if (t === "password") continue;
    const auto = (el.getAttribute("autocomplete") || "").toLowerCase();
    const name = (el.name || "").toLowerCase();
    const id = (el.id || "").toLowerCase();
    const ph = (el.placeholder || "").toLowerCase();
    const aria = (el.getAttribute("aria-label") || "").toLowerCase();
    const max = parseInt(el.getAttribute("maxlength") || "99", 10);
    const combined = `${name} ${id} ${ph} ${aria}`;

    if (auto === "one-time-code") {
      candidates.push({ el, score: 100 });
      continue;
    }
    if (combined.includes("otp") || combined.includes("totp") || combined.includes("2fa") || combined.includes("mfa") || combined.includes("authenticator") || combined.includes("auth-code") || combined.includes("authcode") || combined.includes("verificationcode") || combined.includes("securitycode")) {
      candidates.push({ el, score: 90 });
      continue;
    }
    if ((combined.includes("code") || combined.includes("token") || combined.includes("pin") || combined.includes("verify") || combined.includes("bestätigung") || combined.includes("sicherheit")) && (max <= 8 || t === "tel" || t === "number")) {
      candidates.push({ el, score: 80 });
      continue;
    }
  }
  candidates.sort((a, b) => b.score - a.score);
  return candidates.map(c => c.el);
}

function findSegmentedOtpInputs(allInputs) {
  const singleCharInputs = allInputs.filter(el => {
    if (!isElementFillable(el)) return false;
    const max = el.getAttribute("maxlength");
    const size = el.getAttribute("size");
    return max === "1" || size === "1";
  });
  if (singleCharInputs.length >= 6) {
    return singleCharInputs.slice(0, 6);
  }
  return [];
}

function fillOtpInputs(totpCode, allInputs) {
  if (!totpCode) return false;
  const single = findOtpInputs(allInputs);
  if (single.length > 0) {
    setInputValue(single[0], totpCode);
    return true;
  }
  const segmented = findSegmentedOtpInputs(allInputs);
  if (segmented.length === 6 && totpCode.length === 6) {
    for (let i = 0; i < 6; i++) {
      setInputValue(segmented[i], totpCode[i]);
    }
    return true;
  }
  return false;
}

let lastAutofilledSession = null;

// =============================================================
// 6. INTELLIGENT LOGIN & OTP FORM PAIRING & AUTOFILL
// =============================================================

async function executeAutofill(username, password, totp = "", passkey = null) {
  const allInputs = getAllInputs(document).filter(isElementFillable);

  // 1. If passkey provided:
  if (passkey) {
    if (username) {
      const candidateUser = findStandaloneUsernameInput(allInputs);
      if (candidateUser) setInputValue(candidateUser, username);
    }
    showInPageNotification(`⚡ Passkey (FIDO2) aktiv für ${passkey.username || passkey.rp_name || 'Account'}!`, "⚡");
    return {
      status: "ok",
      passkeyReady: true,
      message: `Passkey für ${passkey.username || passkey.rp_name} aktiv.`
    };
  }

  let currentTotpCode = "";
  if (totp) {
    const totpObj = await generateTotpInBrowser(totp);
    if (totpObj && totpObj.code) {
      currentTotpCode = totpObj.code;
      await copyToClipboard(currentTotpCode);
      lastAutofilledSession = {
        secret: totp,
        code: currentTotpCode,
        timestamp: Date.now()
      };
    }
  }

  // 2. Try filling OTP input if one is currently visible
  let otpFilled = false;
  if (currentTotpCode) {
    otpFilled = fillOtpInputs(currentTotpCode, allInputs);
  }

  if (allInputs.length === 0) {
    if (currentTotpCode) {
      showInPageNotification(`2FA-Code (${currentTotpCode}) in Zwischenablage kopiert! ✓`, "⏱️");
      return { status: "ok", otpCopied: true, message: `2FA-Code (${currentTotpCode}) kopiert.` };
    }
    return { status: "not_found", message: "Keine ausfüllbaren Eingabefelder gefunden." };
  }

  // 3. Locate password fields
  const passwordInputs = allInputs.filter(el => (el.type || "").toLowerCase() === "password");
  let usernameFilled = false;
  let passwordFilled = false;

  if (passwordInputs.length > 0) {
    const activeEl = document.activeElement;
    const pwdInput = (activeEl && (activeEl.type || "").toLowerCase() === "password")
      ? activeEl
      : passwordInputs[0];

    if (password) {
      setInputValue(pwdInput, password);
      passwordFilled = true;
    }

    if (username) {
      const usernameInput = findAssociatedUsernameInput(pwdInput, allInputs);
      if (usernameInput) {
        setInputValue(usernameInput, username);
        usernameFilled = true;
      }
    }

    if (otpFilled) {
      showInPageNotification(`✓ Zugangsdaten & 2FA (${currentTotpCode}) ausgefüllt!`, "✓");
    } else if (currentTotpCode) {
      showInPageNotification(`✓ Zugangsdaten ausgefüllt · 2FA (${currentTotpCode}) kopiert!`, "⏱️");
    } else {
      showInPageNotification("✓ Zugangsdaten erfolgreich ausgefüllt!", "✓");
    }

    return {
      status: "ok",
      usernameFilled,
      passwordFilled,
      otpFilled,
      otpCopied: !!currentTotpCode,
      message: "Zugangsdaten ausgefüllt."
    };
  }

  // 4. Standalone OTP field (Step 2 of login)
  if (otpFilled) {
    showInPageNotification(`✓ 2FA-Code (${currentTotpCode}) automatisch eingefügt!`, "⏱️");
    return {
      status: "ok",
      otpFilled: true,
      message: "2FA-Code eingefügt."
    };
  }

  // 5. Two-Step Login (Step 1: Only Username / Email present, no password input yet)
  if (username) {
    const candidateUserInput = findStandaloneUsernameInput(allInputs);
    if (candidateUserInput) {
      setInputValue(candidateUserInput, username);
      if (currentTotpCode) {
        showInPageNotification(`Benutzername ausgefüllt · 2FA (${currentTotpCode}) kopiert!`, "⏱️");
      } else {
        showInPageNotification("Benutzername / E-Mail ausgefüllt (Schritt 1).", "✓");
      }
      return {
        status: "ok",
        usernameFilled: true,
        passwordFilled: false,
        otpCopied: !!currentTotpCode,
        message: "Benutzername ausgefüllt."
      };
    }
  }

  if (currentTotpCode) {
    showInPageNotification(`2FA-Code (${currentTotpCode}) in Zwischenablage kopiert! ✓`, "⏱️");
    return {
      status: "ok",
      otpCopied: true,
      message: "2FA-Code kopiert."
    };
  }

  return {
    status: "not_found",
    usernameFilled: false,
    passwordFilled: false,
    message: "Kein passendes Anmeldefeld erkannt."
  };
}

/**
 * Finds the username input associated with a given password field
 */
function findAssociatedUsernameInput(pwdInput, allInputs) {
  // Check form or closest parent container
  const form = pwdInput.form || pwdInput.closest("form") || pwdInput.closest("[role='form']") || pwdInput.parentElement?.parentElement;
  let containerInputs = form ? Array.from(form.querySelectorAll("input")).filter(isElementFillable) : allInputs;

  // Filter out password inputs
  const nonPwdInputs = containerInputs.filter(el => (el.type || "").toLowerCase() !== "password");

  if (nonPwdInputs.length === 0) {
    // Fallback: search globally for preceding input
    const globalNonPwd = allInputs.filter(el => (el.type || "").toLowerCase() !== "password");
    return findBestUsernameCandidate(globalNonPwd, pwdInput);
  }

  return findBestUsernameCandidate(nonPwdInputs, pwdInput);
}

function findBestUsernameCandidate(candidates, pwdInput = null) {
  let best = null;
  let highestScore = -1;

  for (const el of candidates) {
    let score = 0;
    const auto = (el.getAttribute("autocomplete") || "").toLowerCase();
    const type = (el.type || "").toLowerCase();
    const name = (el.name || "").toLowerCase();
    const id = (el.id || "").toLowerCase();
    const placeholder = (el.placeholder || "").toLowerCase();
    const aria = (el.getAttribute("aria-label") || "").toLowerCase();
    const combined = `${name} ${id} ${placeholder} ${aria}`;

    // Negative penalties
    if (combined.includes("search") || combined.includes("suche") || combined.includes("find") || combined.includes("filter") || combined.includes("otp") || combined.includes("captcha")) {
      score -= 100;
    }

    // Positive indicators
    if (auto === "username" || auto === "email") score += 100;
    if (type === "email") score += 60;
    if (combined.includes("user") || combined.includes("benutzer")) score += 50;
    if (combined.includes("login") || combined.includes("email") || combined.includes("e-mail") || combined.includes("mail")) score += 40;
    if (combined.includes("account") || combined.includes("konto") || combined.includes("ident")) score += 30;

    // Proximity bonus: if element comes directly before the password field in document order
    if (pwdInput) {
      const pos = pwdInput.compareDocumentPosition(el);
      if (pos & Node.DOCUMENT_POSITION_PRECEDING) {
        score += 20;
      }
    }

    if (score > highestScore && score > 0) {
      highestScore = score;
      best = el;
    }
  }

  // Fallback: if no score > 0, return the last preceding text/email input before password
  if (!best && pwdInput) {
    const preceding = candidates.filter(el => {
      const pos = pwdInput.compareDocumentPosition(el);
      return (pos & Node.DOCUMENT_POSITION_PRECEDING) && (el.type === "text" || el.type === "email" || el.type === "tel");
    });
    if (preceding.length > 0) {
      return preceding[preceding.length - 1];
    }
  }

  return best;
}

function findStandaloneUsernameInput(allInputs) {
  const nonPwd = allInputs.filter(el => (el.type || "").toLowerCase() !== "password");
  return findBestUsernameCandidate(nonPwd, null);
}

// =============================================================
// 6. IN-PAGE HOVER & FOCUS AUTOFILL OVERLAY (Shadow DOM Isolated)
// =============================================================

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

let activeMatchingLogins = [];
let activeMatchingPasskeys = [];
let overlayHost = null;
let shadowRoot = null;
let activeTargetInput = null;
let hideTimer = null;

function initInPageAutofill() {
  if (isSentinelBitVaultPage) return;

  try {
    chrome.runtime.sendMessage(
      { action: "GET_MATCHING_LOGINS", url: window.location.href },
      (res) => {
        if (chrome.runtime.lastError || !res) return;
        activeMatchingLogins = res.matches || [];
        activeMatchingPasskeys = res.passkeys || [];
        if (activeMatchingLogins.length > 0 || activeMatchingPasskeys.length > 0) {
          ensureOverlayContainer();
          attachFieldListeners();
        } else {
          removeOverlayContainer();
        }
      }
    );
  } catch (e) {}
}

function ensureOverlayContainer() {
  if (overlayHost && document.body && document.body.contains(overlayHost)) return;
  if (!document.body) return;

  overlayHost = document.createElement("div");
  overlayHost.id = "sentinelbit-inpage-host";
  overlayHost.style.position = "absolute";
  overlayHost.style.top = "0";
  overlayHost.style.left = "0";
  overlayHost.style.width = "100%";
  overlayHost.style.height = "0";
  overlayHost.style.overflow = "visible";
  overlayHost.style.pointerEvents = "none";
  overlayHost.style.zIndex = "2147483647";

  shadowRoot = overlayHost.attachShadow({ mode: "open" });

  shadowRoot.innerHTML = `
    <style>
      * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
      
      .sb-trigger-btn {
        position: absolute;
        pointer-events: auto;
        width: 22px;
        height: 22px;
        border-radius: 5px;
        background: #0f172a;
        border: 1px solid rgba(59, 130, 246, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        opacity: 0;
        transform: scale(0.85);
        transition: opacity 0.2s cubic-bezier(0.16, 1, 0.3, 1), transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.15s, box-shadow 0.15s;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.4);
        z-index: 2147483647;
      }
      .sb-trigger-btn.visible {
        opacity: 1;
        transform: scale(1);
      }
      .sb-trigger-btn:hover {
        border-color: #3b82f6;
        box-shadow: 0 0 10px rgba(59, 130, 246, 0.6);
        background: #1e293b;
      }
      .sb-trigger-btn svg {
        width: 13px;
        height: 13px;
      }

      .sb-dropdown {
        position: absolute;
        pointer-events: auto;
        width: 280px;
        background: #0f172a;
        border: 1px solid #334155;
        border-radius: 10px;
        box-shadow: 0 16px 36px rgba(0, 0, 0, 0.6), 0 0 0 1px rgba(255, 255, 255, 0.05);
        padding: 8px;
        opacity: 0;
        visibility: hidden;
        transform: translateY(-6px);
        transition: opacity 0.18s ease, transform 0.18s ease, visibility 0.18s;
        z-index: 2147483647;
      }
      .sb-dropdown.open {
        opacity: 1;
        visibility: visible;
        transform: translateY(0);
      }

      .sb-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 4px 6px 8px 6px;
        border-bottom: 1px solid #1e293b;
        margin-bottom: 6px;
      }
      .sb-brand {
        display: flex;
        align-items: center;
        gap: 6px;
        font-weight: 700;
        font-size: 12px;
        color: #60a5fa;
        letter-spacing: 0.3px;
      }
      .sb-badge {
        font-size: 10px;
        padding: 2px 6px;
        border-radius: 999px;
        background: rgba(59, 130, 246, 0.15);
        color: #93c5fd;
        border: 1px solid rgba(59, 130, 246, 0.3);
      }

      .sb-items-list {
        max-height: 220px;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 4px;
      }
      .sb-items-list::-webkit-scrollbar {
        width: 4px;
      }
      .sb-items-list::-webkit-scrollbar-thumb {
        background: #334155;
        border-radius: 4px;
      }

      .sb-item-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 7px 8px;
        border-radius: 6px;
        cursor: pointer;
        transition: background 0.15s ease, border-color 0.15s ease;
        border: 1px solid transparent;
      }
      .sb-item-row:hover {
        background: #1e293b;
        border-color: #3b82f6;
      }
      .sb-item-info {
        display: flex;
        flex-direction: column;
        overflow: hidden;
        padding-right: 8px;
      }
      .sb-item-title {
        font-size: 12px;
        font-weight: 600;
        color: #f8fafc;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .sb-item-user {
        font-size: 11px;
        color: #94a3b8;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .sb-item-action {
        background: #2563eb;
        color: white;
        border: none;
        border-radius: 4px;
        padding: 4px 8px;
        font-size: 11px;
        font-weight: 600;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 3px;
        flex-shrink: 0;
        transition: background 0.15s;
      }
      .sb-item-action:hover {
        background: #1d4ed8;
      }

      .sb-footer {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 6px 4px 2px 4px;
        border-top: 1px solid #1e293b;
        margin-top: 6px;
        font-size: 10px;
        color: #64748b;
      }

      .sb-toast {
        position: fixed;
        bottom: 24px;
        right: 24px;
        background: #0f172a;
        border: 1px solid #3b82f6;
        color: #f8fafc;
        padding: 9px 14px;
        border-radius: 8px;
        font-size: 12px;
        font-weight: 500;
        display: flex;
        align-items: center;
        gap: 8px;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.6), 0 0 15px rgba(59, 130, 246, 0.4);
        opacity: 0;
        transform: translateY(12px) scale(0.96);
        transition: opacity 0.22s cubic-bezier(0.16, 1, 0.3, 1), transform 0.22s cubic-bezier(0.16, 1, 0.3, 1);
        pointer-events: none;
        z-index: 2147483647;
      }
      .sb-toast.visible {
        opacity: 1;
        transform: translateY(0) scale(1);
      }
      .sb-toast-icon {
        font-size: 14px;
      }
    </style>

    <div class="sb-trigger-btn" id="sb-btn" title="sentinelbit: Klick zum Ausfüllen">
      <svg viewBox="0 0 24 24" fill="#3b82f6" stroke="#93c5fd" stroke-width="1.5">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    </div>

    <div class="sb-dropdown" id="sb-menu">
      <div class="sb-header">
        <div class="sb-brand">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="#3b82f6">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          sentinelbit
        </div>
        <div class="sb-badge" id="sb-count-badge">1 Eintrag</div>
      </div>
      <div class="sb-items-list" id="sb-list"></div>
      <div class="sb-footer">
        <span>⚡ 1-Klick Login</span>
        <span>Strg+Shift+L</span>
      </div>
    </div>

    <div class="sb-toast" id="sb-toast">
      <span class="sb-toast-icon" id="sb-toast-icon">✓</span>
      <span class="sb-toast-text" id="sb-toast-text"></span>
    </div>
  `;

  document.body.appendChild(overlayHost);

  const btn = shadowRoot.getElementById("sb-btn");
  const menu = shadowRoot.getElementById("sb-menu");

  btn.addEventListener("mouseenter", () => {
    cancelHide();
    openDropdown();
  });
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    toggleDropdown();
  });

  menu.addEventListener("mouseenter", cancelHide);
  menu.addEventListener("mouseleave", scheduleHide);

  document.addEventListener("click", (e) => {
    if (overlayHost && !overlayHost.contains(e.target)) {
      closeDropdown();
    }
  });

  window.addEventListener("scroll", updatePositions, { passive: true });
  window.addEventListener("resize", updatePositions, { passive: true });
}

function showInPageNotification(message, icon = "✓", duration = 3200) {
  ensureOverlayContainer();
  if (!shadowRoot) return;

  const toast = shadowRoot.getElementById("sb-toast");
  const iconEl = shadowRoot.getElementById("sb-toast-icon");
  const textEl = shadowRoot.getElementById("sb-toast-text");
  if (!toast || !textEl) return;

  if (iconEl) iconEl.innerText = icon;
  textEl.innerText = message;

  toast.classList.add("visible");
  if (toast._timer) clearTimeout(toast._timer);
  toast._timer = setTimeout(() => {
    toast.classList.remove("visible");
  }, duration);
}

function removeOverlayContainer() {
  if (overlayHost && overlayHost.parentNode) {
    overlayHost.parentNode.removeChild(overlayHost);
    overlayHost = null;
    shadowRoot = null;
  }
}

function attachFieldListeners() {
  const allInputs = getAllInputs(document).filter(isElementFillable);
  const candidateInputs = allInputs.filter(el => {
    const t = (el.type || "").toLowerCase();
    const name = (el.name || "").toLowerCase();
    const id = (el.id || "").toLowerCase();
    const auto = (el.autocomplete || "").toLowerCase();
    const ph = (el.placeholder || "").toLowerCase();
    const aria = (el.getAttribute("aria-label") || "").toLowerCase();
    const combined = `${name} ${id} ${ph} ${aria}`;

    const isLoginField = t === "password" || t === "email" || name.includes("user") || name.includes("login") || id.includes("user") || id.includes("login") || (t === "text" && (auto === "username" || auto === "email" || auto.includes("webauthn")));
    const isOtpField = auto === "one-time-code" || combined.includes("otp") || combined.includes("totp") || combined.includes("2fa") || combined.includes("token") || combined.includes("code") || combined.includes("mfa");

    return isLoginField || isOtpField;
  });

  candidateInputs.forEach(input => {
    if (input._sbBound) return;
    input._sbBound = true;

    input.addEventListener("mouseenter", () => {
      cancelHide();
      positionTriggerOnInput(input);
    });

    input.addEventListener("focus", () => {
      cancelHide();
      positionTriggerOnInput(input);
      openDropdown();
    });

    input.addEventListener("mouseleave", () => {
      scheduleHide();
    });
  });
}

function positionTriggerOnInput(input) {
  if (!shadowRoot || !input) return;
  activeTargetInput = input;

  const rect = input.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) return;

  const btn = shadowRoot.getElementById("sb-btn");
  if (!btn) return;

  const scrollX = window.scrollX || window.pageXOffset;
  const scrollY = window.scrollY || window.pageYOffset;

  // Position button inside right edge of input
  const btnSize = 22;
  const top = scrollY + rect.top + (rect.height - btnSize) / 2;
  const left = scrollX + rect.right - btnSize - 6;

  btn.style.top = `${top}px`;
  btn.style.left = `${left}px`;
  btn.classList.add("visible");
}

function openDropdown() {
  if (!shadowRoot || !activeTargetInput) return;
  const menu = shadowRoot.getElementById("sb-menu");
  const listEl = shadowRoot.getElementById("sb-list");
  const badgeEl = shadowRoot.getElementById("sb-count-badge");
  if (!menu || !listEl) return;

  // Render matching logins and passkeys
  listEl.innerHTML = "";
  const totalCount = activeMatchingLogins.length + activeMatchingPasskeys.length;
  if (badgeEl) {
    badgeEl.innerText = `${totalCount} ${totalCount === 1 ? 'Eintrag' : 'Einträge'}`;
  }

  // 1. Render Passkeys
  if (activeMatchingPasskeys.length > 0) {
    activeMatchingPasskeys.forEach(pk => {
      const row = document.createElement("div");
      row.className = "sb-item-row";
      row.style.border = "1px solid rgba(139, 92, 246, 0.4)";
      row.style.background = "rgba(139, 92, 246, 0.1)";
      row.style.marginBottom = "4px";
      row.innerHTML = `
        <div class="sb-item-info">
          <div class="sb-item-title" style="color: #c4b5fd;">⚡ ${escapeHtml(pk.rp_name || pk.rp_id)} (FIDO2)</div>
          <div class="sb-item-user" style="color: #cbd5e1;">Benutzer: ${escapeHtml(pk.username || 'Passkey hinterlegt')}</div>
        </div>
        <button class="sb-item-action" style="background: #7c3aed;">⚡ Bereit</button>
      `;

      row.addEventListener("click", (e) => {
        e.stopPropagation();
        executeAutofill(pk.username, "", "", pk);
        closeDropdown();
        hideTrigger();
      });

      listEl.appendChild(row);
    });
  }

  // 2. Render Logins
  activeMatchingLogins.forEach(match => {
    const row = document.createElement("div");
    row.className = "sb-item-row";
    row.innerHTML = `
      <div class="sb-item-info">
        <div class="sb-item-title">${escapeHtml(match.title || match.url || 'Gespeicherter Account')}</div>
        <div class="sb-item-user">
          ${escapeHtml(match.username || 'Kein Benutzername')}
          ${match.totp ? ' · <span style="color: #34d399; font-weight: 600;">⏱️ 2FA</span>' : ''}
        </div>
      </div>
      <button class="sb-item-action">⚡ Ausfüllen</button>
    `;

    row.addEventListener("click", (e) => {
      e.stopPropagation();
      executeAutofill(match.username, match.password, match.totp);
      closeDropdown();
      hideTrigger();
    });

    listEl.appendChild(row);
  });

  // Position menu below input field
  const rect = activeTargetInput.getBoundingClientRect();
  const scrollX = window.scrollX || window.pageXOffset;
  const scrollY = window.scrollY || window.pageYOffset;

  const menuWidth = 280;
  let top = scrollY + rect.bottom + 6;
  let left = scrollX + rect.right - menuWidth;

  if (left < scrollX + 10) left = scrollX + rect.left;

  // If opening downwards would clip bottom of window, flip upwards
  const windowHeight = window.innerHeight;
  if (rect.bottom + 260 > windowHeight && rect.top - 260 > 0) {
    top = scrollY + rect.top - 260;
  }

  menu.style.top = `${top}px`;
  menu.style.left = `${left}px`;
  menu.classList.add("open");
}

function closeDropdown() {
  if (!shadowRoot) return;
  const menu = shadowRoot.getElementById("sb-menu");
  if (menu) menu.classList.remove("open");
}

function toggleDropdown() {
  if (!shadowRoot) return;
  const menu = shadowRoot.getElementById("sb-menu");
  if (menu && menu.classList.contains("open")) {
    closeDropdown();
  } else {
    openDropdown();
  }
}

function hideTrigger() {
  if (!shadowRoot) return;
  const btn = shadowRoot.getElementById("sb-btn");
  if (btn) btn.classList.remove("visible");
}

function scheduleHide() {
  cancelHide();
  hideTimer = setTimeout(() => {
    closeDropdown();
    hideTrigger();
    activeTargetInput = null;
  }, 400);
}

function cancelHide() {
  if (hideTimer) {
    clearTimeout(hideTimer);
    hideTimer = null;
  }
}

function updatePositions() {
  if (activeTargetInput && shadowRoot) {
    positionTriggerOnInput(activeTargetInput);
    const menu = shadowRoot.getElementById("sb-menu");
    if (menu && menu.classList.contains("open")) {
      openDropdown();
    }
  }
}

// 7. INITIALIZE IN-PAGE HOVER AUTOFILL ENGINE
if (!isSentinelBitVaultPage) {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      initInPageAutofill();
    });
  } else {
    initInPageAutofill();
  }

  // Observe dynamically loaded modal dialogs / forms & Step-2 2FA inputs
  let debounceTimer = null;
  const domObserver = new MutationObserver(() => {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(async () => {
      // Auto-fill Step 2 OTP if previous login occurred within 90 seconds
      if (lastAutofilledSession && (Date.now() - lastAutofilledSession.timestamp < 90000)) {
        const fillable = getAllInputs(document).filter(isElementFillable);
        const otpInputs = findOtpInputs(fillable);
        const segmented = findSegmentedOtpInputs(fillable);
        if (otpInputs.length > 0 || segmented.length === 6) {
          const freshTotp = await generateTotpInBrowser(lastAutofilledSession.secret);
          if (freshTotp && freshTotp.code) {
            const filled = fillOtpInputs(freshTotp.code, fillable);
            if (filled) {
              await copyToClipboard(freshTotp.code);
              showInPageNotification(`✓ 2FA-Code (${freshTotp.code}) automatisch erkannt & eingefügt!`, "⏱️");
              lastAutofilledSession = null;
            }
          }
        }
      }

      if (activeMatchingLogins.length > 0 || activeMatchingPasskeys.length > 0) {
        attachFieldListeners();
      } else {
        initInPageAutofill();
      }
    }, 400);
  });
  domObserver.observe(document.documentElement, { childList: true, subtree: true });
}

