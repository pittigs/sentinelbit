/**
 * sentinelbit Browser Extension - Content Script
 * - Bulletproof Autofill Engine for Vanilla HTML, React, Vue, Angular & Shadow DOM
 * - Intelligent Form & Field Pairing
 * - Two-Way Web App Sync Bridge
 */

// =============================================================
// 0. WEBAUTHN / FIDO2 ENGINE INJECTION & LISTENER
// =============================================================

try {
  const scriptTag = document.createElement("script");
  scriptTag.src = chrome.runtime.getURL("webauthn-page.js");
  scriptTag.onload = () => scriptTag.remove();
  (document.head || document.documentElement).appendChild(scriptTag);
} catch (e) {}

window.addEventListener("message", async (event) => {
  if (event.source !== window || !event.data || event.data.source !== "SENTINELBIT_PAGE_WEBAUTHN") return;
  const { type, requestId, options } = event.data;
  if (type === "GET_REQUEST") {
    handleWebAuthnGetRequest(requestId, options);
  } else if (type === "CREATE_REQUEST") {
    handleWebAuthnCreateRequest(requestId, options);
  }
});

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
    executeAutofill(request.username, request.password, request.totp, request.passkey, request.customFields).then(result => {
      sendResponse(result);
    });
    return true;
  } else if (request.action === "AUTOFILL_CARD") {
    executeCardAutofill(request.card).then(result => {
      sendResponse(result);
    });
    return true;
  } else if (request.action === "GENERATE_EMAIL_ALIAS") {
    const alias = generateEmailAlias(request.baseEmail, window.location.hostname);
    sendResponse({ alias });
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
  } else if (request.action === "CLEAR_CLIPBOARD") {
    try {
      navigator.clipboard.writeText("").catch(() => {});
    } catch (e) {}
    sendResponse({ status: "cleared" });
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

// Drag-and-Drop Autofill Fallback (#15)
document.addEventListener("drop", (e) => {
  const target = e.target;
  if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA")) {
    const text = e.dataTransfer ? e.dataTransfer.getData("text/plain") : "";
    if (text) {
      setInputValue(target, text);
      showInPageNotification("Eingefügt via Drag & Drop ✓", "🛡️");
    }
  }
}, true);

async function executeAutofill(username, password, totp = "", passkey = null, customFields = null) {
  // Anti-Phishing & Punycode Check
  const hostname = window.location.hostname.toLowerCase();
  if (hostname.startsWith("xn--") || /[^\u0000-\u007F]/.test(hostname)) {
    showInPageNotification("⚠️ Achtung: Internationalisierte Punycode-Domain erkannt. Mögliches Phishing!", "🛡️");
  }

  const allInputs = getAllInputs(document).filter(isElementFillable);

  // 1. If passkey provided:
  if (passkey) {
    if (username) {
      const candidateUser = findStandaloneUsernameInput(allInputs);
      if (candidateUser) setInputValue(candidateUser, username);
    }
    if (activeWebAuthnGetResolver) {
      const resolver = activeWebAuthnGetResolver;
      activeWebAuthnGetResolver = null;
      resolver(passkey);
      showInPageNotification(`⚡ Passkey (FIDO2) signiert für ${passkey.username || passkey.rp_name || 'Account'}!`, "⚡");
      return {
        status: "ok",
        passkeyReady: true,
        message: `Passkey für ${passkey.username || passkey.rp_name} signiert.`
      };
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

    // 5. Custom Field Autofill (#6)
    if (customFields && typeof customFields === "object") {
      for (const [key, val] of Object.entries(customFields)) {
        if (!val) continue;
        const keyLower = key.toLowerCase();
        const matched = allInputs.find(inp => {
          const n = (inp.name || "").toLowerCase();
          const id = (inp.id || "").toLowerCase();
          const ph = (inp.placeholder || "").toLowerCase();
          const customAttr = (inp.getAttribute("data-sentinelbit-field") || "").toLowerCase();
          return n.includes(keyLower) || id.includes(keyLower) || ph.includes(keyLower) || customAttr === keyLower;
        });
        if (matched) {
          setInputValue(matched, String(val));
        }
      }
    }

    // Auto-Submit if configured
    if (passwordFilled) {
      chrome.storage.local.get(["auto_submit"], (res) => {
        if (res && res.auto_submit) {
          setTimeout(() => {
            const form = pwdInput.form || pwdInput.closest("form");
            if (form) {
              try { form.requestSubmit(); } catch (e) { form.submit(); }
            }
          }, 350);
        }
      });
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
 * Autofill Credit Card / Payment form fields (#5)
 */
async function executeCardAutofill(card) {
  if (!card) return { status: "no_data", message: "Keine Kartendaten übergeben." };

  const allInputs = getAllInputs(document).filter(isElementFillable);
  let cardNumFilled = false;
  let cardHolderFilled = false;
  let expiryFilled = false;
  let cvvFilled = false;

  const cardNum = (card.cardNumber || card.number || "").replace(/\s+/g, "");
  const cardHolder = card.cardholderName || card.cardHolder || card.name || "";
  const expiry = card.expiry || card.cardExpiry || "";
  const cvv = card.cvv || card.cardCvv || card.securityCode || "";

  // 1. Credit Card Number field
  const numInput = allInputs.find(el => {
    const ac = (el.autocomplete || "").toLowerCase();
    const name = (el.name || "").toLowerCase();
    const id = (el.id || "").toLowerCase();
    const placeholder = (el.placeholder || "").toLowerCase();
    return ac === "cc-number" ||
      /(card.*number|cc.*num|pan|kreditkarte|kartennummer)/i.test(name) ||
      /(card.*number|cc.*num|pan|kreditkarte|kartennummer)/i.test(id) ||
      /(card.*number|kartennummer)/i.test(placeholder);
  });

  if (numInput && cardNum) {
    setInputValue(numInput, cardNum);
    cardNumFilled = true;
  }

  // 2. Cardholder Name field
  const holderInput = allInputs.find(el => {
    const ac = (el.autocomplete || "").toLowerCase();
    const name = (el.name || "").toLowerCase();
    const id = (el.id || "").toLowerCase();
    const placeholder = (el.placeholder || "").toLowerCase();
    return ac === "cc-name" ||
      /(card.*name|cardholder|karteninhaber|name.*on.*card)/i.test(name) ||
      /(card.*name|cardholder|karteninhaber)/i.test(id) ||
      /(cardholder|karteninhaber)/i.test(placeholder);
  });

  if (holderInput && cardHolder) {
    setInputValue(holderInput, cardHolder);
    cardHolderFilled = true;
  }

  // 3. Expiration Date field
  const expInput = allInputs.find(el => {
    const ac = (el.autocomplete || "").toLowerCase();
    const name = (el.name || "").toLowerCase();
    const id = (el.id || "").toLowerCase();
    const placeholder = (el.placeholder || "").toLowerCase();
    return ac === "cc-exp" ||
      /(cc.*exp|exp.*date|ablaufdatum|gueltig)/i.test(name) ||
      /(cc.*exp|exp.*date|ablaufdatum|gueltig)/i.test(id) ||
      /(mm\s*\/\s*yy|mm\s*\/\s*yyyy|ablauf)/i.test(placeholder);
  });

  if (expInput && expiry) {
    setInputValue(expInput, expiry);
    expiryFilled = true;
  }

  // 4. CVV / CVC field
  const cvvInput = allInputs.find(el => {
    const ac = (el.autocomplete || "").toLowerCase();
    const name = (el.name || "").toLowerCase();
    const id = (el.id || "").toLowerCase();
    const placeholder = (el.placeholder || "").toLowerCase();
    return ac === "cc-csc" ||
      /(cvv|cvc|csc|security.*code|pruefziffer|sicherheitscode)/i.test(name) ||
      /(cvv|cvc|csc|security.*code|pruefziffer)/i.test(id) ||
      /(cvv|cvc|csc|3.*digits)/i.test(placeholder);
  });

  if (cvvInput && cvv) {
    setInputValue(cvvInput, cvv);
    cvvFilled = true;
  }

  if (cardNumFilled || cardHolderFilled || expiryFilled || cvvFilled) {
    showInPageNotification("💳 Zahlungskarte erfolgreich ausgefüllt!", "✓");
    return {
      status: "ok",
      cardNumFilled,
      cardHolderFilled,
      expiryFilled,
      cvvFilled,
      message: "Kartendaten ausgefüllt."
    };
  }

  return { status: "not_found", message: "Keine passenden Kreditkartenfelder gefunden." };
}

/**
 * Generate a private randomized email mask / alias (#28)
 */
function generateEmailAlias(baseEmail, currentDomain) {
  const rnd = Math.random().toString(36).substring(2, 6);
  const cleanDomain = (currentDomain || window.location.hostname || "web")
    .replace(/^www\./, "")
    .split(".")[0]
    .replace(/[^a-z0-9]/gi, "");

  if (baseEmail && baseEmail.includes("@")) {
    const parts = baseEmail.split("@");
    return `${parts[0]}+${cleanDomain}.${rnd}@${parts[1]}`;
  }
  return `alias.${cleanDomain}.${rnd}@sentinelbit.vault`;
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
        if (res.isExcluded) {
          removeOverlayContainer();
          return;
        }
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

      /* WebAuthn Passkey Approval Modal */
      .sb-modal-overlay {
        position: fixed;
        top: 24px;
        right: 24px;
        pointer-events: auto;
        z-index: 2147483647;
        opacity: 0;
        visibility: hidden;
        transform: translateY(-12px) scale(0.96);
        transition: all 0.22s cubic-bezier(0.16, 1, 0.3, 1);
      }
      .sb-modal-overlay.open {
        opacity: 1;
        visibility: visible;
        transform: translateY(0) scale(1);
      }
      .sb-modal-box {
        width: 320px;
        background: #0f172a;
        border: 1px solid rgba(139, 92, 246, 0.55);
        border-radius: 12px;
        padding: 14px;
        box-shadow: 0 20px 45px rgba(0, 0, 0, 0.75), 0 0 15px rgba(139, 92, 246, 0.25);
        color: #f8fafc;
      }
      .sb-modal-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 10px;
        border-bottom: 1px solid #1e293b;
        padding-bottom: 8px;
      }
      .sb-modal-brand {
        display: flex;
        align-items: center;
        gap: 6px;
        font-weight: 700;
        font-size: 13px;
        color: #c4b5fd;
      }
      .sb-modal-badge {
        font-size: 10px;
        font-weight: 700;
        padding: 2px 6px;
        border-radius: 999px;
        background: rgba(139, 92, 246, 0.2);
        color: #c4b5fd;
        border: 1px solid rgba(139, 92, 246, 0.4);
      }
      .sb-modal-body {
        margin-bottom: 14px;
      }
      .sb-modal-text {
        font-size: 12px;
        color: #94a3b8;
        margin-bottom: 4px;
      }
      .sb-modal-user {
        font-size: 14px;
        font-weight: 600;
        color: #f1f5f9;
        word-break: break-all;
      }
      .sb-modal-rp {
        font-size: 11px;
        color: #818cf8;
        margin-top: 2px;
      }
      .sb-modal-actions {
        display: flex;
        gap: 8px;
      }
      .sb-modal-btn {
        flex: 1;
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
        border: none;
        transition: all 0.15s ease;
      }
      .sb-modal-btn-primary {
        background: linear-gradient(135deg, #7c3aed, #4f46e5);
        color: #ffffff;
        box-shadow: 0 2px 8px rgba(124, 58, 237, 0.35);
      }
      .sb-modal-btn-primary:hover {
        filter: brightness(1.1);
        box-shadow: 0 4px 12px rgba(124, 58, 237, 0.5);
      }
      .sb-modal-btn-secondary {
        background: #1e293b;
        color: #cbd5e1;
        border: 1px solid #334155;
      }
      .sb-modal-btn-secondary:hover {
        background: #334155;
        color: #ffffff;
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

    <!-- Passkey Prompt Modal -->
    <div class="sb-modal-overlay" id="sb-passkey-modal">
      <div class="sb-modal-box">
        <div class="sb-modal-header">
          <div class="sb-modal-brand">
            <svg viewBox="0 0 24 24" fill="none" stroke="#a78bfa" stroke-width="2" style="width: 18px; height: 18px;">
              <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
            </svg>
            <span id="sb-pk-modal-title">sentinelbit Passkey</span>
          </div>
          <span class="sb-modal-badge" id="sb-pk-modal-badge">FIDO2</span>
        </div>
        <div class="sb-modal-body">
          <div class="sb-modal-text" id="sb-pk-modal-text">Mit Passkey anmelden:</div>
          <div class="sb-modal-user" id="sb-pk-modal-user">user</div>
          <div class="sb-modal-rp" id="sb-pk-modal-rp">example.com</div>
        </div>
        <div class="sb-modal-actions">
          <button class="sb-modal-btn sb-modal-btn-primary" id="sb-pk-modal-confirm">⚡ Anmelden</button>
          <button class="sb-modal-btn sb-modal-btn-secondary" id="sb-pk-modal-cancel">Abbrechen</button>
        </div>
      </div>
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

function setupCredentialDetection() {
  document.addEventListener("submit", (e) => {
    try {
      const form = e.target;
      if (!form || !(form instanceof HTMLFormElement)) return;
      const pwdInputs = Array.from(form.querySelectorAll("input[type='password']")).filter(isElementFillable);
      if (pwdInputs.length === 0) return;

      const currentDomain = window.location.hostname.replace(/^www\./, "");

      // 1. Password change detection (e.g. 2 password fields with same value)
      if (pwdInputs.length >= 2) {
        const val1 = pwdInputs[0].value;
        const val2 = pwdInputs[1].value;
        if (val1 && val2 && val1 === val2 && val1.length >= 6) {
          showInPageNotification(`SentinelBit: Geändertes Passwort für ${currentDomain} erkannt! Bitte im Tresor aktualisieren.`, "🔑");
          return;
        }
      }

      // 2. New login detection (credentials entered on domain without saved logins)
      const pwdVal = pwdInputs[0].value;
      if (pwdVal && pwdVal.length >= 6 && activeMatchingLogins.length === 0) {
        showInPageNotification(`SentinelBit: Neue Anmeldedaten für ${currentDomain} eingegeben. Im Tresor speichern?`, "🛡️");
      }
    } catch (err) {}
  }, true);
}

// 7. INITIALIZE IN-PAGE HOVER AUTOFILL & CREDENTIAL DETECTION ENGINE
if (!isSentinelBitVaultPage) {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      initInPageAutofill();
      setupCredentialDetection();
    });
  } else {
    initInPageAutofill();
    setupCredentialDetection();
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

// =============================================================
// WEBAUTHN / PASSKEY CRYPTO ENGINE & INTERCEPTION LOGIC
// =============================================================

let activeWebAuthnGetResolver = null;

function promptPasskeyAssertion(passkey, rpId, callback) {
  ensureOverlayContainer();
  if (!shadowRoot) {
    callback(true);
    return;
  }

  const modal = shadowRoot.getElementById("sb-passkey-modal");
  const title = shadowRoot.getElementById("sb-pk-modal-title");
  const badge = shadowRoot.getElementById("sb-pk-modal-badge");
  const text = shadowRoot.getElementById("sb-pk-modal-text");
  const user = shadowRoot.getElementById("sb-pk-modal-user");
  const rp = shadowRoot.getElementById("sb-pk-modal-rp");
  const btnConfirm = shadowRoot.getElementById("sb-pk-modal-confirm");
  const btnCancel = shadowRoot.getElementById("sb-pk-modal-cancel");

  if (!modal || !btnConfirm || !btnCancel) {
    callback(true);
    return;
  }

  title.innerText = "sentinelbit Passkey";
  badge.innerText = "FIDO2";
  text.innerText = "Mit Passkey anmelden:";
  user.innerText = passkey.username || "Hinterlegter Benutzer";
  rp.innerText = rpId;
  btnConfirm.innerText = "⚡ Anmelden";

  modal.classList.add("open");

  const cleanup = () => {
    modal.classList.remove("open");
    btnConfirm.onclick = null;
    btnCancel.onclick = null;
  };

  btnConfirm.onclick = () => {
    cleanup();
    callback(true);
  };

  btnCancel.onclick = () => {
    cleanup();
    callback(false);
  };
}

function promptPasskeyCreation(rpName, rpId, username, callback) {
  ensureOverlayContainer();
  if (!shadowRoot) {
    callback(true);
    return;
  }

  const modal = shadowRoot.getElementById("sb-passkey-modal");
  const title = shadowRoot.getElementById("sb-pk-modal-title");
  const badge = shadowRoot.getElementById("sb-pk-modal-badge");
  const text = shadowRoot.getElementById("sb-pk-modal-text");
  const user = shadowRoot.getElementById("sb-pk-modal-user");
  const rp = shadowRoot.getElementById("sb-pk-modal-rp");
  const btnConfirm = shadowRoot.getElementById("sb-pk-modal-confirm");
  const btnCancel = shadowRoot.getElementById("sb-pk-modal-cancel");

  if (!modal || !btnConfirm || !btnCancel) {
    callback(true);
    return;
  }

  title.innerText = "Passkey erstellen";
  badge.innerText = "NEU";
  text.innerText = `Neuen Passkey für ${rpName} in Sentinelbit speichern?`;
  user.innerText = username || "Account";
  rp.innerText = rpId;
  btnConfirm.innerText = "🔑 Im Tresor speichern";

  modal.classList.add("open");

  const cleanup = () => {
    modal.classList.remove("open");
    btnConfirm.onclick = null;
    btnCancel.onclick = null;
  };

  btnConfirm.onclick = () => {
    cleanup();
    callback(true);
  };

  btnCancel.onclick = () => {
    cleanup();
    callback(false);
  };
}

async function handleWebAuthnGetRequest(requestId, options) {
  const { rpId, challenge, allowCredentials, mediation } = options;
  console.log("[sentinelbit-content] handleWebAuthnGetRequest for rpId:", rpId, "allowCredentials:", allowCredentials);

  chrome.runtime.sendMessage({
    action: "WEBAUTHN_GET_MATCHES",
    rpId: rpId,
    allowCredentials: allowCredentials
  }, async (response) => {
    console.log("[sentinelbit-content] WEBAUTHN_GET_MATCHES response:", response);

    if (response && response.status === "locked") {
      showInPageNotification("🔒 Sentinelbit ist gesperrt: Bitte Erweiterung entsperren", "🔒", 4000);
    }

    if (chrome.runtime.lastError || !response || response.status !== "ok" || !response.passkeys || response.passkeys.length === 0) {
      console.log("[sentinelbit-content] No passkeys matched or error, falling back to native WebAuthn");
      window.postMessage({
        source: "SENTINELBIT_CONTENT_WEBAUTHN",
        requestId,
        status: "fallback"
      }, "*");
      return;
    }

    const passkey = response.passkeys[0];

    // Conditional UI (autofill mediation)
    if (mediation === "conditional") {
      activeWebAuthnGetResolver = async (selectedPk) => {
        try {
          const assertion = await signWebAuthnAssertion(selectedPk || passkey, rpId, challenge);
          window.postMessage({
            source: "SENTINELBIT_CONTENT_WEBAUTHN",
            requestId,
            status: "success",
            data: assertion
          }, "*");
        } catch (e) {
          window.postMessage({
            source: "SENTINELBIT_CONTENT_WEBAUTHN",
            requestId,
            status: "fallback"
          }, "*");
        }
      };
      return;
    }

    promptPasskeyAssertion(passkey, rpId, async (approved) => {
      if (!approved) {
        window.postMessage({
          source: "SENTINELBIT_CONTENT_WEBAUTHN",
          requestId,
          status: "fallback"
        }, "*");
        return;
      }

      try {
        console.log("[sentinelbit] User approved passkey assertion for rpId:", rpId, passkey);
        const assertion = await signWebAuthnAssertion(passkey, rpId, challenge);
        console.log("[sentinelbit] Successfully generated assertion:", assertion);
        showInPageNotification(`✓ Mit Passkey (${passkey.username || rpId}) angemeldet!`, "⚡");
        window.postMessage({
          source: "SENTINELBIT_CONTENT_WEBAUTHN",
          requestId,
          status: "success",
          data: assertion
        }, "*");
      } catch (err) {
        console.error("[sentinelbit] Passkey signing error:", err);
        showInPageNotification("Passkey-Signierung fehlgeschlagen: " + (err.message || err), "⚠️", 5000);
        window.postMessage({
          source: "SENTINELBIT_CONTENT_WEBAUTHN",
          requestId,
          status: "fallback"
        }, "*");
      }
    });
  });
}

async function handleWebAuthnCreateRequest(requestId, options) {
  const { rp, user, challenge } = options;
  const rpId = rp.id || window.location.hostname;
  const rpName = rp.name || rpId;
  const username = user.name || user.displayName || "Account";

  promptPasskeyCreation(rpName, rpId, username, async (approved) => {
    if (!approved) {
      window.postMessage({
        source: "SENTINELBIT_CONTENT_WEBAUTHN",
        requestId,
        status: "fallback"
      }, "*");
      return;
    }

    try {
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );

      const privDer = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
      const privB64 = bufferToBase64Url(privDer);

      const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      const xBytes = base64UrlToBuffer(jwk.x);
      const yBytes = base64UrlToBuffer(jwk.y);

      const spkiDer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
      const spkiB64 = bufferToBase64Url(spkiDer);

      const credIdBytes = new Uint8Array(32);
      crypto.getRandomValues(credIdBytes);
      const credentialId = bufferToBase64Url(credIdBytes);

      const { attObj, authData } = await buildCborAttestationObject(rpId, credIdBytes, xBytes, yBytes, 0);

      const clientData = {
        type: "webauthn.create",
        challenge: challenge,
        origin: window.location.origin,
        crossOrigin: false
      };
      const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));

      const newPasskey = {
        rp_id: rpId,
        rp_name: rpName,
        username: username,
        user_handle: user.id || "",
        credential_id: credentialId,
        encrypted_private_key: privB64,
        decrypted_private_key: privB64,
        public_key_cose: JSON.stringify({ kty: 2, alg: -7, crv: 1, x: jwk.x, y: jwk.y }),
        public_key_pem: "",
        sign_count: 0
      };

      chrome.runtime.sendMessage({
        action: "WEBAUTHN_SAVE_PASSKEY",
        passkey: newPasskey
      });

      showInPageNotification(`✓ Neuer Passkey für ${rpName} in Sentinelbit gespeichert!`, "⚡");

      window.postMessage({
        source: "SENTINELBIT_CONTENT_WEBAUTHN",
        requestId,
        status: "success",
        data: {
          id: credentialId,
          rawIdB64: credentialId,
          clientDataB64: bufferToBase64Url(clientDataJSON),
          attestationObjectB64: bufferToBase64Url(attObj),
          authDataB64: bufferToBase64Url(authData),
          spkiB64: spkiB64
        }
      }, "*");
    } catch (err) {
      console.warn("[sentinelbit] Passkey registration error:", err);
      showInPageNotification("Passkey-Erstellung fehlgeschlagen", "⚠️");
      window.postMessage({
        source: "SENTINELBIT_CONTENT_WEBAUTHN",
        requestId,
        status: "fallback"
      }, "*");
    }
  });
}

function bufferToBase64Url(buffer) {
  if (!buffer) return "";
  let bytes;
  if (buffer instanceof Uint8Array) bytes = buffer;
  else if (buffer instanceof ArrayBuffer) bytes = new Uint8Array(buffer);
  else if (ArrayBuffer.isView(buffer)) bytes = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  else return "";
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBuffer(str) {
  if (!str) return new Uint8Array(0);
  if (str instanceof Uint8Array) return str;
  if (str instanceof ArrayBuffer) return new Uint8Array(str);
  let clean = String(str).trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  clean = clean.replace(/=+$/, "");
  const rem = clean.length % 4;
  if (rem === 2) clean += "==";
  else if (rem === 3) clean += "=";
  else if (rem === 1) clean += "===";
  try {
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch (e) {
    console.warn("[sentinelbit] base64 decode error for:", str, e);
    return new Uint8Array(0);
  }
}

function base64ToBuffer(b64) {
  return base64UrlToBuffer(b64);
}

function wrapSec1ToPkcs8(sec1Bytes) {
  const algId = new Uint8Array([
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
  ]);
  const version = new Uint8Array([0x02, 0x01, 0x00]);

  let octetHeader;
  if (sec1Bytes.length < 128) {
    octetHeader = new Uint8Array([0x04, sec1Bytes.length]);
  } else if (sec1Bytes.length < 256) {
    octetHeader = new Uint8Array([0x04, 0x81, sec1Bytes.length]);
  } else {
    octetHeader = new Uint8Array([0x04, 0x82, (sec1Bytes.length >> 8) & 0xff, sec1Bytes.length & 0xff]);
  }

  const contentLen = version.length + algId.length + octetHeader.length + sec1Bytes.length;
  let seqHeader;
  if (contentLen < 128) {
    seqHeader = new Uint8Array([0x30, contentLen]);
  } else if (contentLen < 256) {
    seqHeader = new Uint8Array([0x30, 0x81, contentLen]);
  } else {
    seqHeader = new Uint8Array([0x30, 0x82, (contentLen >> 8) & 0xff, contentLen & 0xff]);
  }

  const result = new Uint8Array(seqHeader.length + contentLen);
  let offset = 0;
  result.set(seqHeader, offset); offset += seqHeader.length;
  result.set(version, offset); offset += version.length;
  result.set(algId, offset); offset += algId.length;
  result.set(octetHeader, offset); offset += octetHeader.length;
  result.set(sec1Bytes, offset);
  return result;
}

async function importSec1OrPkcs8(derBytes) {
  if (!derBytes || derBytes.length === 0) {
    throw new Error("Leere Schlüsseldaten");
  }

  // Raw 32-byte private key scalar (d)
  if (derBytes.length === 32) {
    const pkcs8Prefix = new Uint8Array([
      0x30, 0x51, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
      0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
      0x01, 0x07, 0x04, 0x37, 0x30, 0x35, 0x02, 0x01, 0x01, 0x04, 0x20
    ]);
    const fullPkcs8 = new Uint8Array(pkcs8Prefix.length + 32);
    fullPkcs8.set(pkcs8Prefix, 0);
    fullPkcs8.set(derBytes, pkcs8Prefix.length);
    return await crypto.subtle.importKey(
      "pkcs8",
      fullPkcs8.buffer,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
  }

  // Try direct PKCS#8 import first
  try {
    const buf = derBytes.buffer.slice(derBytes.byteOffset, derBytes.byteOffset + derBytes.byteLength);
    return await crypto.subtle.importKey(
      "pkcs8",
      buf,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
  } catch (ePkcs8) {
    // If not standard PKCS#8, it might be SEC1 (ECPrivateKey) DER: wrap into PKCS#8
    try {
      const wrapped = wrapSec1ToPkcs8(derBytes);
      return await crypto.subtle.importKey(
        "pkcs8",
        wrapped.buffer,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"]
      );
    } catch (eSec1) {
      console.error("[sentinelbit] Failed to import key as PKCS#8 and SEC1:", ePkcs8, eSec1);
      throw ePkcs8;
    }
  }
}

function rawEcdsaToDer(signatureBytes) {
  const r = signatureBytes.slice(0, 32);
  const s = signatureBytes.slice(32, 64);
  function formatInteger(buf) {
    let i = 0;
    while (i < buf.length - 1 && buf[i] === 0) i++;
    const trimmed = buf.slice(i);
    if (trimmed[0] & 0x80) {
      const res = new Uint8Array(trimmed.length + 1);
      res[0] = 0x00;
      res.set(trimmed, 1);
      return res;
    }
    return trimmed;
  }
  const rDer = formatInteger(r);
  const sDer = formatInteger(s);
  const totalLen = 2 + rDer.length + 2 + sDer.length;
  const der = new Uint8Array(2 + totalLen);
  der[0] = 0x30;
  der[1] = totalLen;
  der[2] = 0x02;
  der[3] = rDer.length;
  der.set(rDer, 4);
  const sOffset = 4 + rDer.length;
  der[sOffset] = 0x02;
  der[sOffset + 1] = sDer.length;
  der.set(sDer, sOffset + 2);
  return der;
}

async function importEcdsaPrivateKey(keyMaterial) {
  if (!keyMaterial) throw new Error("Private key material missing");

  // 1. JSON string or object envelope
  if (typeof keyMaterial === "string" && keyMaterial.trim().startsWith("{")) {
    try {
      const parsed = JSON.parse(keyMaterial);
      if (parsed.private_pem || parsed.raw_key) {
        return await importEcdsaPrivateKey(parsed.private_pem || parsed.raw_key);
      }
      if (parsed.kty === "EC" || parsed.d) {
        return await crypto.subtle.importKey("jwk", parsed, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
      }
    } catch (_) {}
  } else if (typeof keyMaterial === "object" && !(keyMaterial instanceof ArrayBuffer) && !(keyMaterial instanceof Uint8Array)) {
    if (keyMaterial.private_pem || keyMaterial.raw_key) {
      return await importEcdsaPrivateKey(keyMaterial.private_pem || keyMaterial.raw_key);
    }
    if (keyMaterial.kty === "EC" || keyMaterial.d) {
      return await crypto.subtle.importKey("jwk", keyMaterial, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    }
  }

  // 2. PEM format
  if (typeof keyMaterial === "string" && keyMaterial.includes("-----BEGIN")) {
    const b64 = keyMaterial.replace(/-----BEGIN[^-]+-----/g, "").replace(/-----END[^-]+-----/g, "").replace(/\s+/g, "");
    const der = base64UrlToBuffer(b64);
    return await importSec1OrPkcs8(der);
  }

  // 3. String base64 / base64url or raw key
  if (typeof keyMaterial === "string") {
    const derBytes = base64UrlToBuffer(keyMaterial);
    return await importSec1OrPkcs8(derBytes);
  }

  // 4. ArrayBuffer or Uint8Array
  if (keyMaterial instanceof ArrayBuffer || keyMaterial instanceof Uint8Array) {
    const bytes = keyMaterial instanceof Uint8Array ? keyMaterial : new Uint8Array(keyMaterial);
    return await importSec1OrPkcs8(bytes);
  }

  throw new Error("Unsupported private key format");
}

async function signWebAuthnAssertion(passkey, rpId, challengeB64) {
  const privateKeyMaterial = passkey.decrypted_private_key || passkey.encrypted_private_key;
  if (!privateKeyMaterial) throw new Error("Kein privater Schlüssel für Passkey vorhanden");

  const privateKey = await importEcdsaPrivateKey(privateKeyMaterial);

  // Derive canonical Relying Party ID:
  // Prefer passkey.rp_id from vault, or strip www. prefix from origin hostname
  let targetRpId = (passkey.rp_id || rpId || window.location.hostname || "").toLowerCase().trim();
  if (targetRpId.startsWith("www.")) {
    targetRpId = targetRpId.replace(/^www\./, "");
  }
  if (passkey.rp_id) {
    const pkRp = passkey.rp_id.toLowerCase().trim().replace(/^www\./, "");
    if (targetRpId === pkRp || targetRpId.endsWith("." + pkRp)) {
      targetRpId = pkRp;
    }
  }

  console.log("[sentinelbit] signWebAuthnAssertion using canonical rpId:", targetRpId);

  const clientData = {
    type: "webauthn.get",
    challenge: challengeB64,
    origin: window.location.origin,
    crossOrigin: false
  };
  const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));
  const clientDataHash = await crypto.subtle.digest("SHA-256", clientDataJSON);

  const rpIdHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(targetRpId));
  const authData = new Uint8Array(37);
  authData.set(new Uint8Array(rpIdHash), 0);
  // Set flags: UP (0x01) | UV (0x04) | BE (0x08) | BS (0x10) = 0x1d (Multi-Device Synced Passkey)
  authData[32] = 0x1d;
  // According to FIDO2 / W3C WebAuthn L3 specification, multi-device synced passkeys MUST
  // set signature counter to 0 so Relying Parties skip cloned authenticator counter checks
  authData[33] = 0;
  authData[34] = 0;
  authData[35] = 0;
  authData[36] = 0;

  const dataToSign = new Uint8Array(authData.length + 32);
  dataToSign.set(authData, 0);
  dataToSign.set(new Uint8Array(clientDataHash), authData.length);

  const rawSig = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    privateKey,
    dataToSign
  );

  const derSig = rawEcdsaToDer(new Uint8Array(rawSig));

  return {
    id: passkey.credential_id,
    rawIdB64: passkey.credential_id,
    clientDataB64: bufferToBase64Url(clientDataJSON),
    authDataB64: bufferToBase64Url(authData),
    signatureB64: bufferToBase64Url(derSig),
    userHandleB64: passkey.user_handle || ""
  };
}

async function buildCborAttestationObject(rpId, credIdBytes, xBytes, yBytes, signCount = 0) {
  const rpIdHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId));
  const flags = new Uint8Array([0x45]); // UP (0x01) | UV (0x04) | AT (0x40)
  const countBytes = new Uint8Array(4);
  countBytes[0] = (signCount >> 24) & 0xff;
  countBytes[1] = (signCount >> 16) & 0xff;
  countBytes[2] = (signCount >> 8) & 0xff;
  countBytes[3] = signCount & 0xff;
  const aaguid = new Uint8Array(16);
  const credIdLen = new Uint8Array([(credIdBytes.length >> 8) & 0xff, credIdBytes.length & 0xff]);

  const coseHeader = new Uint8Array([
    0xa5,
    0x01, 0x02,
    0x03, 0x26,
    0x20, 0x01,
    0x21, 0x58, 0x20
  ]);
  const coseMid = new Uint8Array([
    0x22, 0x58, 0x20
  ]);

  const coseKey = new Uint8Array(coseHeader.length + 32 + coseMid.length + 32);
  coseKey.set(coseHeader, 0);
  coseKey.set(xBytes, coseHeader.length);
  coseKey.set(coseMid, coseHeader.length + 32);
  coseKey.set(yBytes, coseHeader.length + 32 + coseMid.length);

  const authDataTotalLen = 32 + 1 + 4 + 16 + 2 + credIdBytes.length + coseKey.length;
  const authData = new Uint8Array(authDataTotalLen);
  let offset = 0;
  authData.set(new Uint8Array(rpIdHash), offset); offset += 32;
  authData.set(flags, offset); offset += 1;
  authData.set(countBytes, offset); offset += 4;
  authData.set(aaguid, offset); offset += 16;
  authData.set(credIdLen, offset); offset += 2;
  authData.set(credIdBytes, offset); offset += credIdBytes.length;
  authData.set(coseKey, offset);

  const cborPrefix = new Uint8Array([
    0xa3,
    0x63, 0x66, 0x6d, 0x74,
    0x64, 0x6e, 0x6f, 0x6e, 0x65,
    0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74,
    0xa0,
    0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61
  ]);

  let authDataHeader;
  if (authData.length < 256) {
    authDataHeader = new Uint8Array([0x58, authData.length]);
  } else {
    authDataHeader = new Uint8Array([0x59, (authData.length >> 8) & 0xff, authData.length & 0xff]);
  }

  const attObj = new Uint8Array(cborPrefix.length + authDataHeader.length + authData.length);
  attObj.set(cborPrefix, 0);
  attObj.set(authDataHeader, cborPrefix.length);
  attObj.set(authData, cborPrefix.length + authDataHeader.length);

  return { attObj, authData };
}

