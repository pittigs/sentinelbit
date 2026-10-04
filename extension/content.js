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
  window.location.origin === "http://localhost:8000";

if (isSentinelBitVaultPage) {
  // Announce extension presence to the web vault
  window.postMessage({
    source: "SENTINELBIT_EXTENSION",
    action: "EXTENSION_READY",
    version: "1.2.0"
  }, "*");

  // Listen for sync messages from the web vault
  window.addEventListener("message", (event) => {
    if (event.source !== window || !event.data) return;

    if (event.data.source === "SENTINELBIT_WEB_APP") {
      if (event.data.action === "SYNC_VAULT") {
        const items = event.data.items || [];
        const user = event.data.user || "";

        chrome.storage.local.set({
          vault_cache: items,
          vault_user: user,
          last_synced: Date.now()
        }, () => {
          window.postMessage({
            source: "SENTINELBIT_EXTENSION",
            action: "SYNC_ACK",
            count: items.length,
            timestamp: Date.now()
          }, "*");
        });
      } else if (event.data.action === "CHECK_EXTENSION") {
        window.postMessage({
          source: "SENTINELBIT_EXTENSION",
          action: "EXTENSION_READY",
          version: "1.2.0"
        }, "*");
      }
    }
  });
}

// =============================================================
// 2. RUNTIME MESSAGE LISTENER (from popup)
// =============================================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "AUTOFILL") {
    const result = executeAutofill(request.username, request.password);
    sendResponse(result);
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

  // Check element rendering
  const rects = el.getClientRects();
  if (rects.length === 0 && !el.offsetParent) {
    return false;
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
// 5. INTELLIGENT LOGIN FORM PAIRING & AUTOFILL
// =============================================================

function executeAutofill(username, password) {
  const allInputs = getAllInputs(document).filter(isElementFillable);

  if (allInputs.length === 0) {
    return { status: "not_found", message: "Keine ausfüllbaren Eingabefelder auf dieser Seite gefunden." };
  }

  // 1. Locate password fields
  const passwordInputs = allInputs.filter(el => (el.type || "").toLowerCase() === "password");

  let usernameFilled = false;
  let passwordFilled = false;

  if (passwordInputs.length > 0) {
    // Choose primary password input (if multiple, e.g. login vs registration confirm, prefer first or focused)
    const activeEl = document.activeElement;
    const pwdInput = (activeEl && (activeEl.type || "").toLowerCase() === "password")
      ? activeEl
      : passwordInputs[0];

    // Fill Password
    if (password) {
      setInputValue(pwdInput, password);
      passwordFilled = true;
    }

    // Locate matching username input for this password input
    if (username) {
      const usernameInput = findAssociatedUsernameInput(pwdInput, allInputs);
      if (usernameInput) {
        setInputValue(usernameInput, username);
        usernameFilled = true;
      }
    }

    return {
      status: "ok",
      usernameFilled,
      passwordFilled,
      message: "Zugangsdaten erfolgreich ausgefüllt."
    };
  }

  // 2. Two-Step Login (Step 1: Only Username / Email present, no password input yet)
  if (username) {
    const candidateUserInput = findStandaloneUsernameInput(allInputs);
    if (candidateUserInput) {
      setInputValue(candidateUserInput, username);
      return {
        status: "ok",
        usernameFilled: true,
        passwordFilled: false,
        message: "Benutzername / E-Mail ausgefüllt (Schritt 1)."
      };
    }
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
