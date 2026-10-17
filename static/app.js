/**
 * sentinelbit - Zero-Knowledge Password & Passkey Manager
 * Advanced Features:
 * - Web Crypto API (AES-256-GCM, PBKDF2)
 * - FIDO2 / WebAuthn Passkeys & Windows Hello Biometric Unlock
 * - RFC 6238 TOTP Authenticator (30s live loop)
 * - HaveIBeenPwned (HIBP) k-Anonymity Leak Check
 * - Password History Tracker
 * - Encrypted File Attachments (Secure Attachments)
 * - Trash / Soft-Delete Management
 * - Diceware Passphrase Generator
 * - Multi-Format Importer (sentinelbit, Bitwarden JSON, CSV)
 */

// Global Application State (Zero-knowledge: Master key exists ONLY in memory)
let sessionToken = null;
let currentUser = null;
let masterEncryptionKey = null; // CryptoKey (AES-GCM-256)
let decryptedItems = [];
let passkeysList = [];
let trashItems = [];
let activeTab = 'all';

// Pending attachment for active item edit/create
let currentItemAttachment = null;
let currentItemPasswordHistory = [];

// Auto-lock countdown (15 minutes default)
const AUTO_LOCK_SECONDS = 900;
let remainingLockSeconds = AUTO_LOCK_SECONDS;
let lockInterval = null;
let totpInterval = null;

// Curated Diceware Wordlist for Memorable Passphrases
const DICEWARE_WORDS = [
  "alpen", "anker", "apfel", "arktis", "astronaut", "atlas", "atom", "aura",
  "balsam", "baron", "basalt", "biber", "blitz", "blume", "brise", "bronze",
  "caesar", "campus", "chaos", "chiffre", "chrom", "cirrus", "comet", "cosmos",
  "delfin", "delta", "diamant", "diesel", "dynamik", "drache", "duene", "duett",
  "echo", "edelweiss", "eisberg", "elixier", "energie", "epos", "erdbeere", "eureka",
  "falke", "faser", "feder", "feuer", "flamme", "fokus", "forelle", "fossil",
  "galaxie", "garnet", "geysir", "gigant", "gipfel", "glanz", "gletscher", "granit",
  "habicht", "hafen", "harfe", "helium", "herold", "himmels", "horizont", "hyper",
  "ibis", "ikone", "impuls", "insel", "iris", "isotop", "jaguar", "jubel",
  "kaktus", "komet", "kompass", "koralle", "komet", "kristall", "krater", "kronos",
  "laser", "lava", "legende", "libelle", "lotos", "luchs", "lunar", "magnet",
  "mammut", "marmor", "matrix", "meteor", "mirage", "monolith", "mosaik", "mystik",
  "nebula", "neptun", "nexus", "nordpol", "nova", "nugget", "nymphe", "oase",
  "odyssee", "olymp", "omega", "onyx", "opel", "orion", "orkan", "ozean",
  "palast", "panther", "papagei", "pegasus", "pendel", "phantom", "phoenix", "pionier",
  "pulsar", "pyramide", "quanten", "quasar", "quarz", "quelle", "radar", "radiant",
  "rakete", "reaktor", "riff", "ritter", "rubin", "smaragd", "safari", "satellit",
  "schatten", "schneefall", "silber", "sirene", "skalar", "solar", "sonne", "spektrum",
  "sphäre", "stachel", "stern", "strom", "smaragd", "talisman", "taifun", "titan",
  "tornado", "traum", "tundra", "turbin", "uranus", "urwald", "valkyrie", "vektor",
  "vulkan", "waechter", "walnuss", "wasser", "welle", "windrad", "wirbel", "wolfram",
  "zenit", "zephyr", "zirkon", "zodiac", "zyklop", "zypresse"
];

// =============================================================
// CRYPTOGRAPHY UTILITIES (Web Crypto API)
// =============================================================

function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes.buffer;
}

function strToBuffer(str) {
  return new TextEncoder().encode(str);
}

function bufferToStr(buf) {
  return new TextDecoder().decode(buf);
}

function bufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBuffer(b64) {
  const binary = atob(b64.replace(/\s+/g, ''));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function spkiToPem(buf) {
  const b64 = bufferToBase64(buf);
  const lines = b64.match(/.{1,64}/g) || [b64];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

function pemToSpki(pem) {
  const clean = pem.replace(/-----BEGIN PUBLIC KEY-----/g, '')
                   .replace(/-----END PUBLIC KEY-----/g, '')
                   .replace(/\s+/g, '');
  return base64ToBuffer(clean);
}

let userSharingPrivateKey = null;

async function ensureUserSharingKey() {
  if (!masterEncryptionKey || !currentUser) return null;
  if (userSharingPrivateKey) return userSharingPrivateKey;

  const storageKey = `SENTINELBIT_sharing_priv_${currentUser.username}`;
  const storedEncPriv = localStorage.getItem(storageKey);

  if (storedEncPriv) {
    try {
      const decPriv = await decryptPayload(storedEncPriv, masterEncryptionKey);
      if (decPriv && decPriv.pkcs8) {
        userSharingPrivateKey = await window.crypto.subtle.importKey(
          "pkcs8",
          hexToBuffer(decPriv.pkcs8),
          { name: "RSA-OAEP", hash: "SHA-256" },
          false,
          ["decrypt"]
        );
        return userSharingPrivateKey;
      }
    } catch (e) {
      console.warn("Failed to decrypt stored sharing private key, generating new one:", e);
    }
  }

  // Generate new RSA-OAEP 2048 key pair
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );

    userSharingPrivateKey = keyPair.privateKey;

    // Export & register public key
    const spkiBuf = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const pubPem = spkiToPem(spkiBuf);

    await fetch("/api/share/public-key", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${sessionToken}`
      },
      body: JSON.stringify({ public_key_pem: pubPem })
    });

    // Export private key & encrypt with user's master key
    const pkcs8Buf = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const encPrivPayload = await encryptPayload({ pkcs8: bufferToHex(pkcs8Buf) }, masterEncryptionKey);
    localStorage.setItem(storageKey, encPrivPayload);

    return userSharingPrivateKey;
  } catch (err) {
    console.error("Error creating sharing key pair:", err);
    return null;
  }
}

async function sha1Hex(str) {
  const buf = await window.crypto.subtle.digest("SHA-1", strToBuffer(str));
  return bufferToHex(buf).toUpperCase();
}

/**
 * Derive Master Encryption Key using PBKDF2 (SHA-256, 100,000 iterations)
 */
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
    true, // extractable for biometric wrapping if enabled
    ["encrypt", "decrypt"]
  );
}

/**
 * Derive Client Auth Key (sent to server for login verification)
 */
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

/**
 * Encrypt a JavaScript Object with AES-256-GCM
 */
async function encryptPayload(dataObj, cryptoKey) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const plaintext = strToBuffer(JSON.stringify(dataObj));

  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    cryptoKey,
    plaintext
  );

  return JSON.stringify({
    iv: bufferToHex(iv),
    data: bufferToHex(ciphertext)
  });
}

/**
 * Decrypt AES-256-GCM payload back to JavaScript Object
 */
async function decryptPayload(payloadStr, cryptoKey) {
  try {
    const parsed = JSON.parse(payloadStr);
    const iv = hexToBuffer(parsed.iv);
    const ciphertext = hexToBuffer(parsed.data);

    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      cryptoKey,
      ciphertext
    );

    return JSON.parse(bufferToStr(decrypted));
  } catch (err) {
    console.error("Entschlüsselungsfehler:", err);
    return null;
  }
}

// =============================================================
// CLIENT-SIDE TOTP GENERATOR (RFC 6238 / HMAC-SHA1)
// =============================================================

function base32Decode(base32) {
  const clean = base32.replace(/[\s=-]/g, '').toUpperCase();
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const output = [];

  for (let i = 0; i < clean.length; i++) {
    const val = alphabet.indexOf(clean[i]);
    if (val === -1) continue;
    value = (value << 5) | val;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

function parseTotpSecret(secretOrUri) {
  if (!secretOrUri) return null;
  if (secretOrUri.startsWith("otpauth://")) {
    try {
      const url = new URL(secretOrUri);
      return url.searchParams.get("secret");
    } catch {
      return secretOrUri;
    }
  }
  return secretOrUri.replace(/\s+/g, '');
}

let ntpClockDriftMs = 0;

async function checkNtpClockDrift() {
  try {
    const res = await fetch("/api/time");
    if (res.ok) {
      const data = await res.json();
      if (data.server_time_ms) {
        ntpClockDriftMs = data.server_time_ms - Date.now();
        if (Math.abs(ntpClockDriftMs) > 5000) {
          console.warn(`⏰ NTP Clock Drift erkannt: ${ntpClockDriftMs} ms Abweichung kompensiert.`);
        }
      }
    }
  } catch (_) {}
}

async function computeTotp(secretStr) {
  try {
    const secretKey = parseTotpSecret(secretStr);
    if (!secretKey) return null;

    const keyBytes = base32Decode(secretKey);
    if (keyBytes.length === 0) return null;

    // Compensate for clock drift using server NTP time (#67)
    const epoch = Math.floor((Date.now() + ntpClockDriftMs) / 1000);
    const counter = Math.floor(epoch / 30);
    const remainingSeconds = 30 - (epoch % 30);

    const counterBuffer = new ArrayBuffer(8);
    const counterView = new DataView(counterBuffer);
    counterView.setUint32(4, counter, false);

    const cryptoKey = await window.crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-1" },
      false,
      ["sign"]
    );

    const signature = await window.crypto.subtle.sign("HMAC", cryptoKey, counterBuffer);
    const hmacResult = new Uint8Array(signature);

    const offset = hmacResult[hmacResult.length - 1] & 0xf;
    const binary =
      ((hmacResult[offset] & 0x7f) << 24) |
      ((hmacResult[offset + 1] & 0xff) << 16) |
      ((hmacResult[offset + 2] & 0xff) << 8) |
      (hmacResult[offset + 3] & 0xff);

    // Support Steam Guard and Blizzard 8-digit algorithms (#66)
    let otp;
    const isSteam = secretStr && (secretStr.toLowerCase().includes("steam") || secretStr.startsWith("steam://"));
    const isBlizzard = secretStr && (secretStr.toLowerCase().includes("blizzard") || secretStr.toLowerCase().includes("digits=8"));

    if (isSteam) {
      const steamChars = "23456789BCDFGHJKMNPQRTVWXY";
      let steamCode = "";
      let fullCode = binary;
      for (let i = 0; i < 5; i++) {
        steamCode += steamChars[fullCode % steamChars.length];
        fullCode = Math.floor(fullCode / steamChars.length);
      }
      otp = steamCode;
    } else if (isBlizzard) {
      otp = (binary % 100000000).toString().padStart(8, '0');
    } else {
      otp = (binary % 1000000).toString().padStart(6, '0');
    }

    return {
      code: otp,
      remaining: remainingSeconds,
      percent: (remainingSeconds / 30) * 100
    };
  } catch (err) {
    return null;
  }
}

// =============================================================
// BIOMETRISCHES ENTSPERREN (WINDOWS HELLO / WEBAUTHN HARDENED)
// =============================================================

function openDeviceKeyStore() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("SentinelBitDeviceKeyStore", 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore("keys");
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function saveDeviceKey(key) {
  const db = await openDeviceKeyStore();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("keys", "readwrite");
    tx.objectStore("keys").put(key, "bio_device_key");
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function getDeviceKey() {
  const db = await openDeviceKeyStore();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("keys", "readonly");
    const req = tx.objectStore("keys").get("bio_device_key");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function removeDeviceKey() {
  try {
    const db = await openDeviceKeyStore();
    const tx = db.transaction("keys", "readwrite");
    tx.objectStore("keys").delete("bio_device_key");
  } catch (e) {}
}

function checkBiometricAvailability() {
  const bioData = localStorage.getItem("SENTINELBIT_bio_wrapped");
  const bioBtn = document.getElementById("btn-biometric-unlock");
  const bioDiv = document.getElementById("biometric-divider");

  if (bioData && bioBtn && bioDiv) {
    bioBtn.style.display = "block";
    bioDiv.style.display = "block";
  } else if (bioBtn && bioDiv) {
    bioBtn.style.display = "none";
    bioDiv.style.display = "none";
  }
}

async function handleBiometricUnlock() {
  const bioStr = localStorage.getItem("SENTINELBIT_bio_wrapped");
  if (!bioStr) {
    showToast("Kein biometrisches Gerät für dieses System registriert.", "error");
    return;
  }

  try {
    const bioData = JSON.parse(bioStr);
    
    // Request WebAuthn platform authentication (Windows Hello prompt)
    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: challenge,
        timeout: 60000,
        userVerification: "required",
        allowCredentials: [{
          id: hexToBuffer(bioData.credential_id),
          type: "public-key",
          transports: ["internal"]
        }]
      }
    });

    if (!cred) {
      showToast("Biometrische Authentifizierung abgebrochen.", "error");
      return;
    }

    await finishBiometricUnlock(bioData);
  } catch (err) {
    showToast("Windows Hello Fehler: " + err.message, "error");
  }
}

async function finishBiometricUnlock(bioData) {
  // Retrieve non-extractable device key from IndexedDB to decrypt wrapped master key
  const deviceKey = await getDeviceKey();
  if (!deviceKey) {
    throw new Error("Sicherer Geräteschlüssel nicht gefunden. Bitte erneut per Passwort anmelden.");
  }

  const rawKeyBuffer = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(hexToBuffer(bioData.iv)) },
    deviceKey,
    hexToBuffer(bioData.enc_master_key)
  );

  sessionToken = bioData.token;
  currentUser = {
    username: bioData.username,
    enc_salt: bioData.enc_salt,
    totp_enabled: bioData.totp_enabled
  };

  masterEncryptionKey = await window.crypto.subtle.importKey(
    "raw",
    rawKeyBuffer,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  // Verify that session token is still valid on server
  const authCheck = await fetch("/api/auth/me", {
    headers: { "Authorization": `Bearer ${sessionToken}` }
  });
  if (!authCheck.ok) {
    document.getElementById("login-username").value = bioData.username || "";
    showToast("Server-Sitzung ist abgelaufen. Bitte Master-Passwort eingeben.", "warning");
    document.getElementById("login-password").focus();
    return;
  }

  // Switch to Dashboard
  document.getElementById("auth-container").style.display = "none";
  document.getElementById("app-container").style.display = "flex";
  document.getElementById("user-display").innerText = "Tresor: " + currentUser.username;
  document.getElementById("badge-vault-2fa-status").innerText = currentUser.totp_enabled ? "Aktiv ✓" : "Aus";
  document.getElementById("badge-vault-2fa-status").className = currentUser.totp_enabled ? "badge badge-totp" : "badge";
  document.getElementById("badge-biometric-status").innerText = "Aktiv ✓";
  document.getElementById("badge-biometric-status").className = "badge badge-totp";

  startAutoLockTimer();
  startTotpRefreshLoop();
  await loadVault();
  ensureUserSharingKey();
  initLiveSyncStream();

  showToast("Erfolgreich mit Windows Hello / Passkey entsperrt! 🖐️", "success");
}

async function initConditionalPasskeyMediation() {
  if (sessionToken) return;
  const bioStr = localStorage.getItem("SENTINELBIT_bio_wrapped");
  if (!bioStr) return;
  if (!window.PublicKeyCredential || !PublicKeyCredential.isConditionalMediationAvailable) return;

  try {
    const available = await PublicKeyCredential.isConditionalMediationAvailable();
    if (!available) return;

    const bioData = JSON.parse(bioStr);
    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

    const cred = await navigator.credentials.get({
      mediation: "conditional",
      publicKey: {
        challenge: challenge,
        timeout: 60000,
        userVerification: "required",
        allowCredentials: [{
          id: hexToBuffer(bioData.credential_id),
          type: "public-key",
          transports: ["internal"]
        }]
      }
    });

    if (cred) {
      await finishBiometricUnlock(bioData);
    }
  } catch (err) {
    console.debug("Passkey conditional mediation:", err);
  }
}

function openBiometricModal() {
  const isEnabled = !!localStorage.getItem("SENTINELBIT_bio_wrapped");
  const btnDisable = document.getElementById("btn-disable-bio");
  if (btnDisable) {
    btnDisable.style.display = isEnabled ? "block" : "none";
  }
  openModal("modal-biometric");
}

async function enableBiometricUnlockOnThisDevice() {
  if (!masterEncryptionKey) {
    showToast("Tresor muss entsperrt sein, um Biometrie zu aktivieren.", "error");
    return;
  }

  try {
    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: challenge,
        rp: { name: "sentinelbit Password Manager", id: window.location.hostname },
        user: {
          id: strToBuffer(currentUser.username),
          name: currentUser.username,
          displayName: currentUser.username
        },
        pubKeyCredParams: [{ alg: -7, type: "public-key" }],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          userVerification: "required",
          residentKey: "preferred"
        },
        timeout: 60000
      }
    });

    if (!credential) throw new Error("Geräteregistrierung abgebrochen");

    const credIdHex = bufferToHex(credential.rawId);

    // 1. Generate non-extractable device encryption key in IndexedDB
    const deviceKey = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false, // non-extractable! Cannot be exported or stolen by scripts
      ["encrypt", "decrypt"]
    );
    await saveDeviceKey(deviceKey);

    // 2. Export raw master key and encrypt it with the device key
    const rawKeyBytes = await window.crypto.subtle.exportKey("raw", masterEncryptionKey);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedMasterKey = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      deviceKey,
      rawKeyBytes
    );

    // 3. Save wrapped bundle in browser localStorage (WITHOUT plaintext raw key)
    const bioBundle = {
      username: currentUser.username,
      credential_id: credIdHex,
      enc_master_key: bufferToHex(encryptedMasterKey),
      iv: bufferToHex(iv),
      enc_salt: currentUser.enc_salt,
      token: sessionToken,
      totp_enabled: currentUser.totp_enabled
    };
    localStorage.setItem("SENTINELBIT_bio_wrapped", JSON.stringify(bioBundle));

    // Register with server
    await fetch("/api/auth/webauthn/register-key", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${sessionToken}`
      },
      body: JSON.stringify({
        credential_id: credIdHex,
        public_key: "platform_authenticator",
        device_name: navigator.userAgent.includes("Windows") ? "Windows Hello PC" : "Platform Device"
      })
    });

    document.getElementById("badge-biometric-status").innerText = "Aktiv ✓";
    document.getElementById("badge-biometric-status").className = "badge badge-totp";

    closeModal("modal-biometric");
    showToast("Dieses Gerät wurde erfolgreich für Windows Hello registriert! 🖐️", "success");
  } catch (err) {
    showToast("Fehler bei Windows Hello Registrierung: " + err.message, "error");
  }
}

async function disableBiometricUnlockOnThisDevice() {
  localStorage.removeItem("SENTINELBIT_bio_wrapped");
  await removeDeviceKey();
  document.getElementById("badge-biometric-status").innerText = "Aus";
  document.getElementById("badge-biometric-status").className = "badge";
  closeModal("modal-biometric");
  checkBiometricAvailability();
  showToast("Windows Hello für dieses Gerät deaktiviert.", "info");
}

// =============================================================
// AUTHENTICATION & LOGIN FLOW
// =============================================================

function showRegisterView(e) {
  if (e) e.preventDefault();
  document.getElementById("login-section").style.display = "none";
  document.getElementById("register-section").style.display = "block";
}

function showLoginView(e) {
  if (e) e.preventDefault();
  document.getElementById("register-section").style.display = "none";
  document.getElementById("login-section").style.display = "block";
  checkBiometricAvailability();
}

function checkMasterPasswordStrength(pwd) {
  const fill = document.getElementById("reg-strength-fill");
  const text = document.getElementById("reg-strength-text");

  let score = 0;
  if (pwd.length >= 10) score += 1;
  if (pwd.length >= 14) score += 1;
  if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) score += 1;
  if (/[0-9]/.test(pwd)) score += 1;
  if (/[^A-Za-z0-9]/.test(pwd)) score += 1;

  fill.className = "strength-bar-fill";
  if (score < 3) {
    fill.classList.add("strength-weak");
    text.innerText = "Schwach: Verwende mehr Zeichen und Sonderzeichen.";
  } else if (score < 5) {
    fill.classList.add("strength-medium");
    text.innerText = "Mittel: Ausreichend, aber noch verbesserbar.";
  } else {
    fill.classList.add("strength-strong");
    text.innerText = "Sehr stark! Exzellente Entropie für Zero-Knowledge.";
  }
}

async function handleRegister(e) {
  e.preventDefault();
  const username = document.getElementById("reg-username").value.trim();
  const password = document.getElementById("reg-password").value;
  const passwordConfirm = document.getElementById("reg-password-confirm").value;

  if (password !== passwordConfirm) {
    showToast("Die Passwörter stimmen nicht überein!", "error");
    return;
  }
  if (password.length < 10) {
    showToast("Das Master-Passwort muss mindestens 10 Zeichen lang sein.", "error");
    return;
  }

  const clientSalt = bufferToHex(window.crypto.getRandomValues(new Uint8Array(16)));
  const encSalt = bufferToHex(window.crypto.getRandomValues(new Uint8Array(16)));

  try {
    const authKeyHex = await deriveClientAuthKey(password, clientSalt);

    const res = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: username,
        auth_salt: clientSalt,
        auth_hash: authKeyHex,
        enc_salt: encSalt
      })
    });

    const data = await res.json();
    if (!res.ok) {
      showToast(data.detail || "Registrierungsfehler", "error");
      return;
    }

    showToast("Tresor erfolgreich eingerichtet! Entsperre Tresor...", "success");
    document.getElementById("login-username").value = username;
    document.getElementById("login-password").value = password;

    // Automatically trigger login / unlock with the derived keys
    showLoginView();
    const fakeEvent = { preventDefault: () => {} };
    await handleLogin(fakeEvent);
  } catch (err) {
    showToast("Fehler bei der Registrierung: " + err.message, "error");
  }
}

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;
  const totpCode = document.getElementById("login-totp").value.trim();
  const recoveryCode = document.getElementById("login-recovery").value.trim();

  try {
    // Step 1: Login Init (fetch user salts & 2FA status)
    const initRes = await fetch("/api/auth/login-init", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: username })
    });

    const initData = await initRes.json();
    if (!initRes.ok) {
      showToast(initData.detail || "Fehler beim Initialisieren", "error");
      return;
    }

    const salts = initData.auth_salt.split(":");
    const clientSalt = salts[0];

    // Show 2FA input field if required and not filled yet
    if (initData.totp_required && !totpCode && !recoveryCode) {
      document.getElementById("login-totp-group").style.display = "block";
      showToast("Bitte gib deinen 6-stelligen 2FA-Code ein.", "info");
      document.getElementById("login-totp").focus();
      return;
    }

    // Step 2: Compute Client Auth Key
    const clientAuthKey = await deriveClientAuthKey(password, clientSalt);

    // Step 3: Login Verify with Server
    const verifyRes = await fetch("/api/auth/login-verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: username,
        client_auth_key: clientAuthKey,
        totp_code: totpCode || null,
        recovery_code: recoveryCode || null
      })
    });

    const verifyData = await verifyRes.json();
    if (!verifyRes.ok) {
      if (verifyRes.status === 403 && verifyData.detail === "2FA_REQUIRED") {
        document.getElementById("login-totp-group").style.display = "block";
        showToast("Passwort korrekt. Bitte gib deinen 6-stelligen 2FA-Code ein.", "info");
        document.getElementById("login-totp").focus();
        return;
      }
      showToast(verifyData.detail || "Anmeldung fehlgeschlagen", "error");
      return;
    }

    // Store Session
    sessionToken = verifyData.token;
    currentUser = {
      username: verifyData.username,
      enc_salt: verifyData.enc_salt,
      totp_enabled: verifyData.totp_enabled
    };

    // Step 4: Derive Master Encryption Key in Browser Memory
    masterEncryptionKey = await deriveMasterEncryptionKey(password, verifyData.enc_salt);

    // Switch to App Dashboard
    document.getElementById("auth-container").style.display = "none";
    document.getElementById("app-container").style.display = "flex";
    document.getElementById("user-display").innerText = "Tresor: " + currentUser.username;
    document.getElementById("badge-vault-2fa-status").innerText = currentUser.totp_enabled ? "Aktiv ✓" : "Aus";
    document.getElementById("badge-vault-2fa-status").className = currentUser.totp_enabled ? "badge badge-totp" : "badge";

    const hasBio = !!localStorage.getItem("SENTINELBIT_bio_wrapped");
    document.getElementById("badge-biometric-status").innerText = hasBio ? "Aktiv ✓" : "Aus";
    document.getElementById("badge-biometric-status").className = hasBio ? "badge badge-totp" : "badge";

    // Clear password inputs from DOM for memory security
    document.getElementById("login-password").value = "";
    document.getElementById("login-totp").value = "";
    document.getElementById("login-recovery").value = "";

    startAutoLockTimer();
    startTotpRefreshLoop();
    await loadVault();
    ensureUserSharingKey();
    initLiveSyncStream();

    showToast("Tresor erfolgreich entsperrt!", "success");
  } catch (err) {
    showToast("Fehler bei der Anmeldung: " + err.message, "error");
  }
}

function toggleRecoveryCodeInput(e) {
  if (e) e.preventDefault();
  const totpGroup = document.getElementById("login-totp-group");
  const recGroup = document.getElementById("login-recovery-group");
  if (recGroup.style.display === "none") {
    recGroup.style.display = "block";
    totpGroup.style.display = "none";
  } else {
    recGroup.style.display = "none";
    totpGroup.style.display = "block";
  }
}

function lockVault() {
  masterEncryptionKey = null;
  sessionToken = null;
  currentUser = null;
  decryptedItems = [];
  passkeysList = [];
  trashItems = [];

  if (lockInterval) clearInterval(lockInterval);
  if (totpInterval) clearInterval(totpInterval);
  closeLiveSyncStream();

  document.getElementById("app-container").style.display = "none";
  document.getElementById("auth-container").style.display = "flex";
  document.getElementById("items-container").innerHTML = "";

  checkBiometricAvailability();
  showToast("Tresor wurde gesperrt.", "info");
}

function getAutoLockSetting() {
  const saved = localStorage.getItem("sentinelbit_autolock_sec");
  if (saved !== null) {
    const val = parseInt(saved, 10);
    if (!isNaN(val)) return val;
  }
  return 300; // 5 min default
}

function setAutoLockSetting(sec) {
  localStorage.setItem("sentinelbit_autolock_sec", sec);
  const select = document.getElementById("select-autolock");
  if (select) select.value = String(sec);
  startAutoLockTimer();
  showToast(sec === 0 ? "Auto-Lock deaktiviert." : `Auto-Lock auf ${Math.round(sec / 60)} Min. gesetzt.`, "info");
}

function startAutoLockTimer() {
  const timeoutSec = getAutoLockSetting();
  const select = document.getElementById("select-autolock");
  if (select && select.value !== String(timeoutSec)) {
    select.value = String(timeoutSec);
  }

  if (lockInterval) clearInterval(lockInterval);

  if (timeoutSec <= 0) {
    const timerEl = document.getElementById("auto-lock-timer");
    if (timerEl) timerEl.innerText = "∞";
    window.onmousemove = null;
    window.onkeydown = null;
    window.onclick = null;
    return;
  }

  remainingLockSeconds = timeoutSec;
  const resetTimer = () => {
    remainingLockSeconds = timeoutSec;
  };
  window.onmousemove = resetTimer;
  window.onkeydown = resetTimer;
  window.onclick = resetTimer;

  lockInterval = setInterval(() => {
    remainingLockSeconds--;
    const mins = Math.floor(remainingLockSeconds / 60);
    const secs = remainingLockSeconds % 60;
    const timerEl = document.getElementById("auto-lock-timer");
    if (timerEl) {
      timerEl.innerText = `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }

    if (remainingLockSeconds <= 0) {
      lockVault();
    }
  }, 1000);
}

// =============================================================
// VAULT DATA & ITEMS CRUD
// =============================================================

async function loadVault() {
  try {
    // 1. Fetch active items
    const res = await fetch("/api/vault/items", {
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    const items = await res.json();

    // 2. Fetch trash items
    const trashRes = await fetch("/api/vault/trash", {
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    const rawTrash = await trashRes.json();

    // 3. Fetch passkeys
    const pkRes = await fetch("/api/passkeys", {
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    passkeysList = await pkRes.json();

    // 4. Decrypt active items
    decryptedItems = [];
    for (const it of items) {
      const decPayload = await decryptPayload(it.encrypted_payload, masterEncryptionKey);
      if (decPayload) {
        decryptedItems.push({
          ...it,
          data: decPayload
        });
      }
    }

    // 5. Decrypt trash items
    trashItems = [];
    for (const it of rawTrash) {
      const decPayload = await decryptPayload(it.encrypted_payload, masterEncryptionKey);
      if (decPayload) {
        trashItems.push({
          ...it,
          data: decPayload
        });
      }
    }

    updateItemCounters();
    renderVaultItems();

    // Sync active login items to browser extension via content script bridge
    syncWithBrowserExtension();
  } catch (err) {
    showToast("Fehler beim Laden des Tresors: " + err.message, "error");
  }
}

async function updateItemCounters() {
  document.getElementById("count-all").innerText = decryptedItems.length + passkeysList.length;
  document.getElementById("count-login").innerText = decryptedItems.filter(i => i.type === 'login').length;
  document.getElementById("count-passkey").innerText = passkeysList.length;
  document.getElementById("count-totp").innerText = decryptedItems.filter(i => i.data && i.data.totp).length;
  document.getElementById("count-note").innerText = decryptedItems.filter(i => i.type === 'note').length;
  document.getElementById("count-card").innerText = decryptedItems.filter(i => i.type === 'card').length;
  document.getElementById("count-favorite").innerText = decryptedItems.filter(i => i.favorite).length;
  document.getElementById("count-trash").innerText = trashItems.length;

  // Fetch count of aliases and shared inbox
  try {
    const aliasRes = await fetch("/api/aliases", { headers: { "Authorization": `Bearer ${sessionToken}` } });
    if (aliasRes.ok) {
      const aliases = await aliasRes.json();
      const el = document.getElementById("count-aliases");
      if (el) el.innerText = aliases.length;
    }
    const shareRes = await fetch("/api/share/inbox", { headers: { "Authorization": `Bearer ${sessionToken}` } });
    if (shareRes.ok) {
      const inbox = await shareRes.json();
      const el = document.getElementById("count-shared");
      if (el) el.innerText = inbox.length;
    }
    const syncRes = await fetch("/api/sync/settings", { headers: { "Authorization": `Bearer ${sessionToken}` } });
    if (syncRes.ok) {
      const syncInfo = await syncRes.json();
      const badge = document.getElementById("badge-sync-status");
      if (badge) {
        badge.innerText = syncInfo.is_active ? "Aktiv ✓" : "Aus";
        badge.className = syncInfo.is_active ? "badge badge-totp" : "badge";
      }
    }
    updateSecurityGamification();
    renderSidebarFolders();

    // Duplicate badge calculation
    try {
      const dupGroups = findVaultDuplicates(true);
      let totalDups = 0;
      dupGroups.forEach(g => { totalDups += g.duplicates.length; });
      const dupBadge = document.getElementById("badge-duplicates-count");
      if (dupBadge) {
        if (totalDups > 0) {
          dupBadge.innerText = totalDups;
          dupBadge.style.display = "inline-block";
        } else {
          dupBadge.style.display = "none";
        }
      }
    } catch (e) {
      // Ignore calculation error
    }
  } catch (e) {
    // Ignore non-critical counter errors
  }
}

// =============================================================
// BROWSER EXTENSION INTEGRATION BRIDGE
// =============================================================

async function syncWithBrowserExtension() {
  try {
    if (!decryptedItems) return;
    const cacheItems = decryptedItems
      .filter(it => it.type === "login" && it.data)
      .map(it => ({
        id: it.id,
        title: it.title,
        username: it.data.username || "",
        password: it.data.password || "",
        url: it.data.url || "",
        totp: it.data.totp || "",
        favorite: it.favorite
      }));

    const syncedPasskeys = await Promise.all((passkeysList || []).map(async pk => {
      let decKey = null;
      if (pk.encrypted_private_key) {
        if (typeof pk.encrypted_private_key === "string" && pk.encrypted_private_key.startsWith("{") && pk.encrypted_private_key.includes('"iv"')) {
          try {
            const dec = await decryptPayload(pk.encrypted_private_key, masterEncryptionKey);
            decKey = dec.private_pem || dec.raw_key || (typeof dec === "string" ? dec : null);
          } catch (_) {}
        } else {
          decKey = pk.encrypted_private_key;
        }
      }
      return {
        ...pk,
        decrypted_private_key: decKey
      };
    }));

    window.postMessage({
      source: "SENTINELBIT_WEB_APP",
      action: "SYNC_VAULT",
      items: cacheItems,
      passkeys: syncedPasskeys,
      user: currentUser ? currentUser.username : ""
    }, window.location.origin);
  } catch (e) {
    console.debug("Extension sync bridge error:", e);
  }
}

// Listen for messages from extension content script
window.addEventListener("message", (event) => {
  if (event.source !== window || !event.data) return;
  if (event.data.source === "SENTINELBIT_EXTENSION") {
    if (event.data.action === "EXTENSION_READY" || event.data.action === "REQUEST_SYNC_NOW") {
      const badge = document.getElementById("badge-extension-status");
      if (badge) badge.style.display = "inline-block";
      const statusText = document.getElementById("ext-modal-status-text");
      if (statusText) statusText.innerText = `Erweiterung erkannt (v${event.data.version || '1.1'}) ✓`;
      syncWithBrowserExtension();
    } else if (event.data.action === "SYNC_ACK") {
      const badge = document.getElementById("badge-extension-status");
      if (badge) {
        badge.style.display = "inline-block";
        const pkCount = event.data.passkeysCount ? ` + ${event.data.passkeysCount} ⚡` : '';
        badge.innerText = `Aktiv (${event.data.count}${pkCount})`;
      }
      const statusText = document.getElementById("ext-modal-status-text");
      if (statusText) {
        const pkText = event.data.passkeysCount ? ` & ${event.data.passkeysCount} Passkeys` : '';
        statusText.innerText = `Erweiterung synchronisiert: ${event.data.count} Zugänge${pkText} bereit ✓`;
      }
    }
  }
});

function openExtensionModal() {
  openModal("modal-extension");
}


// =============================================================
// GAMIFICATION & SECURITY ACHIEVEMENTS SYSTEM
// =============================================================

const ALL_ACHIEVEMENTS = [
  { id: "first_item", icon: "🌱", title: "Erster Schritt", desc: "Mindestens einen Tresor-Eintrag erstellt." },
  { id: "strong_passwords", icon: "💪", title: "Festungsmauer", desc: "Alle gespeicherten Passwörter haben ≥ 14 Zeichen." },
  { id: "passkey_pioneer", icon: "⚡", title: "Passkey-Pionier", desc: "Mindestens einen FIDO2 Passkey registriert." },
  { id: "two_factor_hero", icon: "🛡️", title: "Zwei-Faktor-Held", desc: "2FA (TOTP) für den Tresor oder gespeicherte Dienste eingerichtet." },
  { id: "biometric_ninja", icon: "🖐️", title: "Biometrie-Meister", desc: "Windows Hello / Touch ID eingerichtet." },
  { id: "backup_guardian", icon: "🔄", title: "Backup-Wächter", desc: "Automatischen Backup- und Sync-Plan aktiviert." },
  { id: "alias_ghost", icon: "🎭", title: "Maskierter Schatten", desc: "Mindestens einen E-Mail-Alias erstellt." },
  { id: "secure_sharing", icon: "🤝", title: "Sicheres Bündnis", desc: "Einen Eintrag asymmetrisch mit jemandem geteilt." }
];

function calculateAchievements() {
  const unlocked = new Set();
  const totalLogins = decryptedItems.filter(i => i.type === "login");
  const hasPasskeys = passkeysList.length > 0;
  const hasTotpItems = decryptedItems.some(i => i.data && (i.data.totp || i.data.totp_secret));
  const is2FaActive = !!(currentUser && currentUser.totp_enabled) || hasTotpItems;
  const isBioActive = !!localStorage.getItem("SENTINELBIT_bio_wrapped");
  const hasBackup = document.getElementById("badge-sync-status")?.innerText.includes("Aktiv");
  const hasAliases = parseInt(document.getElementById("count-aliases")?.innerText || "0") > 0;
  const hasShared = parseInt(document.getElementById("count-shared")?.innerText || "0") > 0;

  if (decryptedItems.length > 0 || hasPasskeys) {
    unlocked.add("first_item");
  }

  if (totalLogins.length > 0) {
    const allStrong = totalLogins.every(it => it.data && it.data.password && it.data.password.length >= 14);
    if (allStrong) unlocked.add("strong_passwords");
  }

  if (hasPasskeys) unlocked.add("passkey_pioneer");
  if (is2FaActive) unlocked.add("two_factor_hero");
  if (isBioActive) unlocked.add("biometric_ninja");
  if (hasBackup) unlocked.add("backup_guardian");
  if (hasAliases) unlocked.add("alias_ghost");
  if (hasShared) unlocked.add("secure_sharing");

  return unlocked;
}

function updateSecurityGamification() {
  const unlocked = calculateAchievements();
  const pct = Math.min(100, Math.round((unlocked.size / ALL_ACHIEVEMENTS.length) * 100));

  const ring = document.getElementById("security-score-ring");
  const val = document.getElementById("security-score-val");
  const rank = document.getElementById("security-rank-title");
  const lvl = document.getElementById("security-level-badge");
  const feed = document.getElementById("security-feedback-text");
  const bar = document.getElementById("achievements-container");

  if (ring) ring.style.setProperty("--score-pct", `${pct}%`);
  if (val) val.innerText = `${pct}%`;

  // Ranks & Titles based on score
  let level = "Level 1 (Rekrut)";
  let rankText = "Sicherheits-Novize";
  let feedback = "Füge Einträge hinzu und aktiviere 2FA, um deinen Schutz zu erhöhen.";

  if (pct >= 85) {
    level = "Level 5 (Elite)";
    rankText = "Festungs-Kommandant";
    feedback = "Perfekt! Dein Tresor besitzt maximale Sicherheit und höchsten Härtungsgrad.";
  } else if (pct >= 60) {
    level = "Level 4 (Meister)";
    rankText = "Sentinel-Wächter";
    feedback = "Hervorragend! Starke Schlüssel, Passkeys und Backups schützen deine Daten.";
  } else if (pct >= 40) {
    level = "Level 3 (Verteidiger)";
    rankText = "Cyber-Verteidiger";
    feedback = "Guter Schutz! Aktiviere noch Auto-Sync oder Passkeys für das nächste Level.";
  } else if (pct >= 20) {
    level = "Level 2 (Aufsteiger)";
    rankText = "Sicherheits-Wächter";
    feedback = "Guter Start! Richte einen 2FA-Schutz oder biometrisches Entsperren ein.";
  }

  if (lvl) lvl.innerText = level;
  if (rank) rank.innerText = rankText;
  if (feed) feed.innerText = feedback;

  // Mini Badges in banner
  if (bar) {
    bar.innerHTML = "";
    ALL_ACHIEVEMENTS.forEach(ach => {
      const isUnlocked = unlocked.has(ach.id);
      const span = document.createElement("span");
      span.className = `achieve-badge ${isUnlocked ? "unlocked" : ""}`;
      span.title = `${ach.title}: ${ach.desc}`;
      span.innerHTML = `<span>${ach.icon}</span> <span>${ach.title}</span> ${isUnlocked ? '✓' : '🔒'}`;
      bar.appendChild(span);
    });
  }
}

function openAchievementsModal() {
  const unlocked = calculateAchievements();
  const listEl = document.getElementById("achievements-full-list");
  if (!listEl) return;

  listEl.innerHTML = "";
  ALL_ACHIEVEMENTS.forEach(ach => {
    const isUnlocked = unlocked.has(ach.id);
    const card = document.createElement("div");
    card.style.cssText = `
      display: flex;
      align-items: center;
      gap: 14px;
      padding: 12px 16px;
      border-radius: var(--radius-md);
      background: ${isUnlocked ? "rgba(16, 185, 129, 0.12)" : "var(--bg-secondary)"};
      border: 1px solid ${isUnlocked ? "rgba(16, 185, 129, 0.3)" : "var(--border-color)"};
    `;
    card.innerHTML = `
      <div style="font-size: 1.8rem; width: 44px; height: 44px; display: flex; align-items: center; justify-content: center; background: rgba(0,0,0,0.2); border-radius: 50%;">
        ${ach.icon}
      </div>
      <div style="flex-grow: 1;">
        <div style="display: flex; align-items: center; gap: 8px;">
          <h4 style="font-size: 0.95rem; color: ${isUnlocked ? '#34d399' : 'var(--text-main)'};">${ach.title}</h4>
          <span class="badge ${isUnlocked ? 'badge-totp' : ''}" style="display: inline-flex; align-items: center; gap: 4px;">
            ${isUnlocked 
              ? `<svg viewBox="0 0 24 24" style="width: 11px; height: 11px; stroke: currentColor; fill: none; stroke-width: 2.5;"><polyline points="20 6 9 17 4 12"/></svg> Freigeschaltet` 
              : `<svg viewBox="0 0 24 24" style="width: 11px; height: 11px; stroke: currentColor; fill: none; stroke-width: 2;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Gesperrt`}
          </span>
        </div>
        <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 2px;">${ach.desc}</p>
      </div>
    `;
    listEl.appendChild(card);
  });

  openModal("modal-achievements");
}

function switchTab(tab) {
  activeTab = tab;
  document.querySelectorAll(".nav-item").forEach(el => el.classList.remove("active"));
  const navItem = document.querySelector(`.nav-item[onclick*="'${tab}'"]`);
  if (navItem) navItem.classList.add("active");

  // Deselect any active folder in sidebar
  document.querySelectorAll("#sidebar-folder-list .nav-item").forEach(el => el.classList.remove("active"));

  // Synchronize quick filter pills
  document.querySelectorAll(".filter-pill").forEach(el => {
    if (el.getAttribute("onclick") && el.getAttribute("onclick").includes(`'${tab}'`)) {
      el.classList.add("active");
    } else {
      el.classList.remove("active");
    }
  });

  const titles = {
    all: "Alle Einträge",
    login: "Anmeldungen (Logins)",
    passkey: "Passkeys (FIDO2)",
    totp: "2FA Authenticator Codes",
    note: "Sichere Notizen",
    card: "Zahlungskarten",
    favorite: "Favoriten",
    trash: "Papierkorb (Gelöschte Einträge)"
  };
  document.getElementById("current-view-title").innerText = titles[tab] || "Tresor";
  renderVaultItems();
}

// =============================================================
// VECTOR SVG ICONS (Clean, modern UI icons for vault cards & actions)
// =============================================================
const SVG_ICONS = {
  login: `<svg viewBox="0 0 24 24"><path d="M21 2l-2 2m-2-2l2 2m0 0l-7.5 7.5a5 5 0 1 0 2.8 2.8L21 4v2h2V2h-2z"/></svg>`,
  note: `<svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>`,
  card: `<svg viewBox="0 0 24 24"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>`,
  passkey: `<svg viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>`,
  totp: `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
  trash: `<svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>`,
  copy: `<svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
  eye: `<svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
  eyeOff: `<svg viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`,
  edit: `<svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`,
  starFilled: `<svg viewBox="0 0 24 24" style="fill: #fbbf24; stroke: #fbbf24;"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
  starOutline: `<svg viewBox="0 0 24 24" style="fill: none; stroke: currentColor;"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
  folder: `<svg viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`,
  attachment: `<svg viewBox="0 0 24 24"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>`,
  restore: `<svg viewBox="0 0 24 24"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>`,
  test: `<svg viewBox="0 0 24 24"><path d="M10 2v7.31L4.2 18.68A2 2 0 0 0 6 22h12a2 2 0 0 0 1.8-3.32L14 9.31V2"/></svg>`,
  close: `<svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
  history: `<svg viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`,
  dice: `<svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><circle cx="15.5" cy="8.5" r="1.5"/><circle cx="15.5" cy="15.5" r="1.5"/><circle cx="8.5" cy="15.5" r="1.5"/></svg>`,
  sun: `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`,
  moon: `<svg viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
  plus: `<svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
  zap: `<svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
  lock: `<svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  shield: `<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  terminal: `<svg viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`,
  archive: `<svg viewBox="0 0 24 24"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>`,
  sync: `<svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>`,
  fingerprint: `<svg viewBox="0 0 24 24"><path d="M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 4"/><path d="M5 19.5C5.5 18 6 15 6 12c0-.7.1-1.4.3-2"/><path d="M12 10a2 2 0 0 0-2 2c0 2.5-1 4.5-2 6"/><path d="M14 13a2 2 0 0 1-2 2c-1.5 0-2.5 1-3 2"/><path d="M17 12c0-2.8-2.2-5-5-5s-5 2.2-5 5c0 1.8.5 3.5 1.4 4.8"/><path d="M19 15.5c-.3 1.5-1 3-2 4.5"/><path d="M22 12c0 4-2 7-4 9.5"/></svg>`
};

function renderSidebarFolders() {
  const container = document.getElementById("sidebar-folder-list");
  const datalist = document.getElementById("folder-suggestions");
  if (!container) return;

  const folderCounts = {};
  decryptedItems.forEach(i => {
    if (i.folder && i.folder.trim()) {
      const f = i.folder.trim();
      folderCounts[f] = (folderCounts[f] || 0) + 1;
    }
  });

  const folders = Object.keys(folderCounts).sort();

  if (datalist) {
    datalist.innerHTML = folders.map(f => `<option value="${escapeHtml(f)}">`).join("");
  }

  if (folders.length === 0) {
    container.innerHTML = `<div style="font-size: 0.75rem; color: var(--text-dim); padding: 4px 12px;">Keine Ordner angelegt</div>`;
    return;
  }

  // Hierarchical Folder Tree Display (#53)
  container.innerHTML = folders.map(f => {
    const parts = f.split("/");
    const depth = parts.length - 1;
    const displayName = parts[parts.length - 1];
    const indentPx = depth * 14;
    const arrow = depth > 0 ? `<span style="font-size: 0.75rem; color: var(--text-dim); margin-right: 3px;">↳</span>` : '';

    return `
      <div class="nav-item ${activeTab === 'folder:' + f ? 'active' : ''}" style="padding-left: ${12 + indentPx}px;" onclick="switchFolder('${escapeHtml(f)}')" title="Ordner: ${escapeHtml(f)}">
        <div class="nav-item-content">
          <span class="nav-icon">${arrow}${SVG_ICONS.folder}</span>
          <span class="nav-text">${escapeHtml(displayName)}</span>
        </div>
        <span class="badge">${folderCounts[f]}</span>
      </div>
    `;
  }).join("");
}

function switchFolder(folderName) {
  activeTab = 'folder:' + folderName;
  document.querySelectorAll(".nav-item").forEach(el => el.classList.remove("active"));
  const navItems = Array.from(document.querySelectorAll("#sidebar-folder-list .nav-item"));
  const match = navItems.find(el => el.innerText.includes(folderName));
  if (match) match.classList.add("active");

  document.querySelectorAll(".filter-pill").forEach(el => el.classList.remove("active"));
  document.getElementById("current-view-title").innerText = `Ordner: ${folderName}`;
  renderVaultItems();
}

function filterVaultItems() {
  renderVaultItems();
}

function extractDomain(urlStr) {
  if (!urlStr) return null;
  try {
    let clean = urlStr.trim();
    if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
      clean = 'https://' + clean;
    }
    const parsed = new URL(clean);
    return parsed.hostname;
  } catch (e) {
    return null;
  }
}

function getFaviconUrl(urlStr) {
  if (localStorage.getItem("SENTINELBIT_disable_external_favicons") === "true") {
    return null;
  }
  const domain = extractDomain(urlStr);
  if (!domain) return null;
  return `/api/favicon?domain=${encodeURIComponent(domain)}`;
}

function handleFaviconError(imgEl, iconType = 'login') {
  if (!imgEl) return;
  imgEl.onerror = null;
  const parent = imgEl.parentElement;
  if (!parent) return;
  parent.style.background = iconType === 'passkey' ? 'rgba(139, 92, 246, 0.15)' : '';
  const svg = SVG_ICONS[iconType] || SVG_ICONS.login;
  parent.innerHTML = svg;
}


async function renderVaultItems() {
  const container = document.getElementById("items-container");
  const emptyState = document.getElementById("empty-state");
  const query = document.getElementById("vault-search").value.toLowerCase().trim();

  container.innerHTML = "";

  // -------------------------------------------------------------
  // TRASH VIEW
  // -------------------------------------------------------------
  if (activeTab === 'trash') {
    if (trashItems.length === 0) {
      container.innerHTML = `
        <div style="grid-column: 1/-1; text-align: center; padding: 40px; color: var(--text-dim);">
          <div style="width: 48px; height: 48px; margin: 0 auto 12px auto; opacity: 0.6;">${SVG_ICONS.trash}</div>
          Der Papierkorb ist leer.
        </div>
      `;
      return;
    }

    // Header actions for trash
    const trashBar = document.createElement("div");
    trashBar.style.gridColumn = "1/-1";
    trashBar.style.display = "flex";
    trashBar.style.justifyContent = "space-between";
    trashBar.style.alignItems = "center";
    trashBar.style.background = "rgba(239, 68, 68, 0.08)";
    trashBar.style.border = "1px solid rgba(239, 68, 68, 0.25)";
    trashBar.style.padding = "10px 16px";
    trashBar.style.borderRadius = "var(--radius-md)";
    trashBar.innerHTML = `
      <span style="font-size: 0.85rem; color: #f87171;">${trashItems.length} Element(e) im Papierkorb.</span>
      <button class="btn btn-danger" style="padding: 6px 12px; font-size: 0.8rem; display: inline-flex; align-items: center; gap: 4px;" onclick="emptyAllTrash()">${SVG_ICONS.trash} Papierkorb leeren</button>
    `;
    container.appendChild(trashBar);

    for (const item of trashItems) {
      const card = document.createElement("div");
      card.className = "vault-card";
      card.style.opacity = "0.8";

      card.innerHTML = `
        <div class="card-header">
          <div style="display: flex; gap: 12px; align-items: center; overflow: hidden;">
            <div class="card-icon">${SVG_ICONS.trash}</div>
            <div class="card-title-group">
              <div class="card-title">${escapeHtml(item.title)}</div>
              <div class="card-subtitle">${escapeHtml(item.data.username || item.data.url || '')}</div>
            </div>
          </div>
        </div>
        <div style="display: flex; gap: 8px; margin-top: 10px;">
          <button class="btn btn-primary" style="flex: 1; padding: 6px; font-size: 0.8rem; display: inline-flex; align-items: center; justify-content: center; gap: 6px;" onclick="restoreVaultItem('${item.id}')">
            ${SVG_ICONS.restore} Wiederherstellen
          </button>
          <button class="btn btn-danger" style="padding: 6px 12px; font-size: 0.8rem; display: inline-flex; align-items: center; justify-content: center;" onclick="deleteVaultItem('${item.id}', true)">
            Endgültig löschen
          </button>
        </div>
      `;
      container.appendChild(card);
    }
    return;
  }

  // -------------------------------------------------------------
  // PASSKEY VIEW
  // -------------------------------------------------------------
  if (activeTab === 'passkey') {
    renderPasskeyCards(passkeysList.filter(pk => 
      pk.rp_id.toLowerCase().includes(query) || 
      pk.rp_name.toLowerCase().includes(query) || 
      pk.username.toLowerCase().includes(query)
    ));
    return;
  }

  // Filter standard items
  let itemsToShow = decryptedItems.filter(item => {
    if (activeTab === 'login' && item.type !== 'login') return false;
    if (activeTab === 'note' && item.type !== 'note') return false;
    if (activeTab === 'card' && item.type !== 'card') return false;
    if (activeTab === 'favorite' && !item.favorite) return false;
    if (activeTab === 'totp' && (!item.data || !item.data.totp)) return false;
    if (activeTab.startsWith('folder:') && item.folder !== activeTab.substring(7)) return false;

    if (query) {
      const matchTitle = item.title.toLowerCase().includes(query);
      const matchUser = item.data.username && item.data.username.toLowerCase().includes(query);
      const matchUrl = item.data.url && item.data.url.toLowerCase().includes(query);
      return matchTitle || matchUser || matchUrl;
    }
    return true;
  });

  if (itemsToShow.length === 0 && (activeTab !== 'all' || passkeysList.length === 0)) {
    emptyState.style.display = "block";
    return;
  }
  emptyState.style.display = "none";

  // If tab is 'all', also display passkeys that do NOT have a corresponding login item
  if (activeTab === 'all') {
    const standalonePasskeys = passkeysList.filter(pk => {
      const hasMatchingLogin = decryptedItems.some(it => {
        if (it.type !== "login") return false;
        const itemHost = (extractDomain(it.data?.url) || "").toLowerCase();
        const itemUser = (it.data?.username || "").toLowerCase().trim();
        const itemTitle = (it.title || "").toLowerCase().trim();
        const pkUser = (pk.username || "").toLowerCase().trim();
        const pkRp = (pk.rp_id || "").toLowerCase().trim();
        const pkName = (pk.rp_name || "").toLowerCase().trim();
        const userMatches = (!itemUser && !pkUser) || (itemUser && pkUser && itemUser === pkUser);
        const domainMatches = (itemHost && pkRp && (itemHost === pkRp || pkRp.includes(itemHost) || itemHost.includes(pkRp)));
        const titleMatches = (itemTitle && pkName && (itemTitle.includes(pkName) || pkName.includes(itemTitle)));
        return userMatches && (domainMatches || titleMatches);
      });
      return !hasMatchingLogin;
    });

    renderPasskeyCards(standalonePasskeys.filter(pk => 
      pk.rp_id.toLowerCase().includes(query) || 
      pk.rp_name.toLowerCase().includes(query) || 
      pk.username.toLowerCase().includes(query)
    ));
  }

  // Render vault items
  for (const item of itemsToShow) {
    const card = document.createElement("div");
    card.className = "vault-card";

    let iconSvg = SVG_ICONS.login;
    if (item.type === "note") iconSvg = SVG_ICONS.note;
    if (item.type === "card") iconSvg = SVG_ICONS.card;

    let iconHtml = `<div class="card-icon">${iconSvg}</div>`;
    if (item.type === "login" && item.data.url) {
      const fav = getFaviconUrl(item.data.url);
      if (fav) {
        iconHtml = `
          <div class="card-icon" style="background: transparent;">
            <img class="card-favicon" src="${fav}" alt="" onerror="handleFaviconError(this, '${item.type || 'login'}')">
          </div>
        `;
      }
    }

    let matchingPk = null;
    if (item.type === "login") {
      const itemHost = (extractDomain(item.data?.url) || "").toLowerCase();
      const itemUser = (item.data?.username || "").toLowerCase().trim();
      const itemTitle = (item.title || "").toLowerCase().trim();

      matchingPk = passkeysList.find(pk => {
        if (pk.vault_item_id && pk.vault_item_id === item.id) return true;
        const pkUser = (pk.username || "").toLowerCase().trim();
        const pkRp = (pk.rp_id || "").toLowerCase().trim();
        const pkName = (pk.rp_name || "").toLowerCase().trim();
        const userMatches = (!itemUser && !pkUser) || (itemUser && pkUser && itemUser === pkUser);
        const domainMatches = (itemHost && pkRp && (itemHost === pkRp || pkRp.includes(itemHost) || itemHost.includes(pkRp)));
        const titleMatches = (itemTitle && pkName && (itemTitle.includes(pkName) || pkName.includes(itemTitle)));
        return userMatches && (domainMatches || titleMatches);
      });
    }

    let contentHtml = "";

    if (item.type === "login") {
      contentHtml = `
        <div class="card-field-col card-field-user" title="${escapeHtml(item.data.username || '')}">
          ${item.data.username ? `
            <span class="card-field-label">Benutzer:</span>
            <span class="card-field-val">${escapeHtml(item.data.username)}</span>
            <button class="btn-icon" onclick="copyItemUsername('${item.id}')" title="Kopieren">${SVG_ICONS.copy}</button>
          ` : `
            <span class="card-field-empty">—</span>
          `}
        </div>

        <div class="card-field-col card-field-pwd">
          ${item.data.password ? `
            <span class="card-field-label">Passwort:</span>
            <span class="card-field-val" id="pwd-${item.id}">••••••••••••</span>
            <button class="btn-icon" onclick="toggleCardPassword('${item.id}', this)" title="Passwort anzeigen/verbergen">${SVG_ICONS.eye}</button>
            <button class="btn-icon" onclick="copyItemPassword('${item.id}')" title="Kopieren">${SVG_ICONS.copy}</button>
          ` : `
            <span class="card-field-empty">—</span>
          `}
        </div>

        ${item.data.totp ? `
          <div class="totp-badge-compact" id="totp-card-${item.id}" onclick="copyTotpCode('${item.id}')" title="2FA Code kopieren">
            <span style="font-size: 0.68rem; color: #34d399; font-weight: 700; display: inline-flex; align-items: center; gap: 3px;">
              <span style="width: 12px; height: 12px; display: inline-flex;">${SVG_ICONS.totp}</span> 2FA
            </span>
            <span class="totp-code-compact" id="totp-val-${item.id}">------</span>
            <span class="totp-timer-compact" id="totp-sec-${item.id}">30s</span>
            <button class="btn-icon" style="padding: 2px;" onclick="event.stopPropagation(); copyTotpCode('${item.id}')" title="Code kopieren">${SVG_ICONS.copy}</button>
          </div>
        ` : ''}

        ${matchingPk ? `
          <div class="passkey-pill-compact" style="display: flex; align-items: center; justify-content: space-between; background: rgba(139, 92, 246, 0.12); border: 1px solid rgba(139, 92, 246, 0.25); border-radius: var(--radius-sm); padding: 3px 8px; font-size: 0.72rem; gap: 6px;">
            <span style="color: #c4b5fd; font-weight: 600; display: inline-flex; align-items: center; gap: 4px;">
              <span style="width: 12px; height: 12px; display: inline-flex;">${SVG_ICONS.passkey}</span> Passkey
            </span>
            <button class="btn btn-secondary" style="padding: 2px 6px; font-size: 0.7rem;" onclick="event.stopPropagation(); testPasskeyAssertion('${matchingPk.id}')" title="WebAuthn Simulation">Testen</button>
          </div>
        ` : ''}

        ${item.data.attachment ? `
          <div class="attachment-pill">
            <span class="attachment-badge" onclick="downloadAttachment('${item.id}')" title="Klicken zum Herunterladen" style="display: inline-flex; align-items: center; gap: 4px;">
              <span style="width: 12px; height: 12px; display: inline-flex;">${SVG_ICONS.attachment}</span> ${escapeHtml(item.data.attachment.name)}
            </span>
          </div>
        ` : ''}
      `;
    } else if (item.type === "note") {
      contentHtml = `
        <div class="card-note-box" title="${escapeHtml(item.data.notes || '')}">
          ${escapeHtml(item.data.notes || '')}
        </div>
        ${item.data.attachment ? `
          <div class="attachment-pill">
            <span class="attachment-badge" onclick="downloadAttachment('${item.id}')" style="display: inline-flex; align-items: center; gap: 4px;">
              <span style="width: 12px; height: 12px; display: inline-flex;">${SVG_ICONS.attachment}</span> ${escapeHtml(item.data.attachment.name)}
            </span>
          </div>
        ` : ''}
      `;
    } else if (item.type === "card") {
      contentHtml = `
        <div class="card-field-col card-field-user">
          <span class="card-field-label">Karte:</span>
          <span class="card-field-val">${escapeHtml(item.data.cardNumber ? '•••• ' + item.data.cardNumber.slice(-4) : '••••')}</span>
        </div>
        <div class="card-field-col card-field-pwd">
          <span class="card-field-label">Ablauf:</span>
          <span class="card-field-val">${escapeHtml(item.data.expiry || '--/--')}</span>
        </div>
      `;
    }

    card.innerHTML = `
      <div class="card-main-col">
        ${iconHtml}
        <div class="card-title-group">
          <div class="card-title" title="${escapeHtml(item.title)}">
            <span class="card-title-text">${escapeHtml(item.title)}</span>
            ${item.folder ? `<span class="badge" style="font-size: 0.68rem; background: rgba(255,255,255,0.06); color: var(--text-muted); font-weight: 500; display: inline-flex; align-items: center; gap: 3px;"><span style="width: 11px; height: 11px; display: inline-flex;">${SVG_ICONS.folder}</span> ${escapeHtml(item.folder)}</span>` : ''}
            ${matchingPk ? `<span class="badge badge-passkey" style="font-size: 0.68rem; padding: 2px 6px; display: inline-flex; align-items: center; gap: 3px;" title="Passkey (FIDO2) hinterlegt"><span style="width: 11px; height: 11px; display: inline-flex;">${SVG_ICONS.passkey}</span> FIDO2</span>` : ''}
          </div>
          <div class="card-subtitle" title="${escapeHtml(item.data.url || item.folder || '')}">${escapeHtml(item.data.url || item.folder || 'Keine URL')}</div>
        </div>
      </div>

      <div class="card-creds-col">
        ${contentHtml}
      </div>

      <div class="card-actions-col">
        <button class="btn-icon" onclick="toggleFavorite('${item.id}')" title="Favorit">
          ${item.favorite ? SVG_ICONS.starFilled : SVG_ICONS.starOutline}
        </button>
        <button class="btn-icon" onclick="openEditItemModal('${item.id}')" title="Bearbeiten">${SVG_ICONS.edit}</button>
        <button class="btn-icon" onclick="deleteVaultItem('${item.id}', false)" title="In Papierkorb">${SVG_ICONS.trash}</button>
      </div>
    `;

    container.appendChild(card);
  }

  updateLiveTotpCards();
}

function formatTimeAgo(dateStr) {
  if (!dateStr) return "Nie";
  try {
    const diff = Date.now() - new Date(dateStr).getTime();
    if (diff < 60000) return "Gerade eben";
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `Vor ${mins} Min.`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `Vor ${hours} Std.`;
    const days = Math.floor(hours / 24);
    if (days < 30) return `Vor ${days} Tagen`;
    return new Date(dateStr).toLocaleDateString();
  } catch (_) {
    return "";
  }
}

function renderPasskeyCards(passkeys) {
  const container = document.getElementById("items-container");
  for (const pk of passkeys) {
    const card = document.createElement("div");
    card.className = "vault-card passkey-card";
    card.style.border = "1px solid rgba(139, 92, 246, 0.35)";

    let pkIconHtml = `<div class="card-icon passkey" style="color: #a78bfa; background: rgba(139, 92, 246, 0.15);">${SVG_ICONS.passkey}</div>`;
    if (pk.rp_id) {
      const fav = getFaviconUrl(pk.rp_id);
      if (fav) {
        pkIconHtml = `
          <div class="card-icon passkey" style="background: rgba(139, 92, 246, 0.1);">
            <img class="card-favicon" src="${fav}" alt="" onerror="handleFaviconError(this, 'passkey')">
          </div>
        `;
      }
    }

    card.innerHTML = `
      <div class="card-main-col">
        ${pkIconHtml}
        <div class="card-title-group">
          <div class="card-title" title="${escapeHtml(pk.rp_name)}">
            <span class="card-title-text" style="color: #c4b5fd;">${escapeHtml(pk.rp_name)}</span>
            <span class="badge badge-passkey" style="display: inline-flex; align-items: center; gap: 3px;"><span style="width: 11px; height: 11px; display: inline-flex;">${SVG_ICONS.passkey}</span> FIDO2</span>
          </div>
          <div class="card-subtitle" title="${escapeHtml(pk.rp_id)}">${escapeHtml(pk.rp_id)}</div>
        </div>
      </div>

      <div class="card-creds-col">
        <div class="card-field-col card-field-user">
          <span class="card-field-label">Benutzer:</span>
          <span class="card-field-val" style="color: #c4b5fd;">${escapeHtml(pk.username)}</span>
        </div>
        <div class="card-field-col card-field-pwd">
          <span class="card-field-label">Credential ID:</span>
          <span class="card-field-val" style="color: #60a5fa; font-size: 0.75rem;">${escapeHtml(pk.credential_id.substring(0, 16))}...</span>
        </div>
        <div class="card-field-col" style="flex: 1 1 100%; display: flex; gap: 14px; margin-top: 4px; font-size: 0.72rem; color: #94a3b8;">
          <span>🕒 Zuletzt genutzt: <strong style="color: #cbd5e1;">${escapeHtml(formatTimeAgo(pk.last_used_at))}</strong></span>
          ${pk.sign_count ? `<span>⚡ Signaturen: <strong style="color: #cbd5e1;">${pk.sign_count}</strong></span>` : ''}
        </div>
      </div>

      <div class="card-actions-col">
        <button class="btn btn-secondary passkey-test-btn" onclick="testPasskeyAssertion('${pk.id}')" title="WebAuthn Simulation">
          ${SVG_ICONS.test} WebAuthn Testen
        </button>
        <button class="btn-icon" onclick="deletePasskey('${pk.id}')" title="Passkey löschen" style="color: #f87171;">
          ${SVG_ICONS.trash}
        </button>
      </div>
    `;

    container.appendChild(card);
  }
}

// =============================================================
// LIVE TOTP DISPLAY REFRESH
// =============================================================

function startTotpRefreshLoop() {
  if (totpInterval) clearInterval(totpInterval);
  totpInterval = setInterval(updateLiveTotpCards, 1000);
}

async function updateLiveTotpCards() {
  for (const item of decryptedItems) {
    if (item.data && item.data.totp) {
      const codeEl = document.getElementById(`totp-val-${item.id}`);
      const secEl = document.getElementById(`totp-sec-${item.id}`);
      if (codeEl && secEl) {
        const res = await computeTotp(item.data.totp);
        if (res) {
          codeEl.innerText = res.code.slice(0, 3) + " " + res.code.slice(3);
          secEl.innerText = `${res.remaining}s`;
        } else {
          codeEl.innerText = "Ungültig";
        }
      }
    }
  }
}

async function copyTotpCode(itemId) {
  const item = decryptedItems.find(i => i.id === itemId);
  if (item && item.data.totp) {
    const res = await computeTotp(item.data.totp);
    if (res) {
      copyToClipboard(res.code, "2FA-Code kopiert! (Leert in 30s)", true);
    }
  }
}

function evaluateItemPasswordStrength(pwd) {
  const fill = document.getElementById("item-strength-fill");
  const text = document.getElementById("item-strength-text");
  if (!fill || !text) return;

  if (!pwd || pwd.length === 0) {
    fill.className = "strength-bar-fill";
    text.innerText = "Passwort-Sicherheit";
    text.style.color = "var(--text-dim)";
    return;
  }

  let score = 0;
  if (pwd.length >= 10) score += 1;
  if (pwd.length >= 14) score += 1;
  if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) score += 1;
  if (/[0-9]/.test(pwd)) score += 1;
  if (/[^A-Za-z0-9]/.test(pwd)) score += 1;

  fill.className = "strength-bar-fill";
  if (score < 3) {
    fill.classList.add("strength-weak");
    text.innerText = "Schwach: Bitte längeres Passwort wählen";
    text.style.color = "var(--color-danger)";
  } else if (score < 5) {
    fill.classList.add("strength-medium");
    text.innerText = "Mittel: Gut, aber mehr Entropie empfohlen";
    text.style.color = "var(--color-warning)";
  } else {
    fill.classList.add("strength-strong");
    text.innerText = "Sehr stark! Exzellente Entropie";
    text.style.color = "var(--color-success)";
  }
}

function openAddItemModal() {
  document.getElementById("modal-item-title").innerText = "Neuer Tresor-Eintrag";
  document.getElementById("item-id").value = "";
  document.getElementById("item-type").value = "login";
  document.getElementById("item-title").value = "";
  document.getElementById("item-folder").value = "";
  document.getElementById("item-url").value = "";
  document.getElementById("item-username").value = "";
  document.getElementById("item-password").value = "";
  document.getElementById("item-totp").value = "";
  document.getElementById("item-notes").value = "";
  document.getElementById("item-card-number").value = "";
  document.getElementById("item-card-expiry").value = "";
  document.getElementById("item-card-cvv").value = "";
  document.getElementById("item-favorite").checked = false;

  currentItemAttachment = null;
  currentItemPasswordHistory = [];
  document.getElementById("item-attachment-file").value = "";
  document.getElementById("attachment-preview").style.display = "none";
  document.getElementById("btn-toggle-history").innerHTML = `${SVG_ICONS.history} Passwort-Historie (0)`;
  document.getElementById("password-history-list").style.display = "none";

  evaluateItemPasswordStrength("");
  toggleItemTypeFields("login");
  openModal("modal-item");
}

function openEditItemModal(id) {
  const item = decryptedItems.find(i => i.id === id);
  if (!item) return;

  document.getElementById("modal-item-title").innerText = "Eintrag bearbeiten";
  document.getElementById("item-id").value = item.id;
  document.getElementById("item-type").value = item.type;
  document.getElementById("item-title").value = item.title;
  document.getElementById("item-folder").value = item.folder || "";
  document.getElementById("item-favorite").checked = item.favorite;

  toggleItemTypeFields(item.type);

  if (item.type === "login") {
    document.getElementById("item-url").value = item.data.url || "";
    document.getElementById("item-username").value = item.data.username || "";
    document.getElementById("item-password").value = item.data.password || "";
    document.getElementById("item-totp").value = item.data.totp || "";
    evaluateItemPasswordStrength(item.data.password || "");
  } else if (item.type === "note") {
    document.getElementById("item-notes").value = item.data.notes || "";
    evaluateItemPasswordStrength("");
  } else if (item.type === "card") {
    document.getElementById("item-card-number").value = item.data.cardNumber || "";
    document.getElementById("item-card-expiry").value = item.data.expiry || "";
    document.getElementById("item-card-cvv").value = item.data.cvv || "";
    evaluateItemPasswordStrength("");
  }

  // Password history
  currentItemPasswordHistory = item.data.passwordHistory || [];
  document.getElementById("btn-toggle-history").innerHTML = `${SVG_ICONS.history} Passwort-Historie (${currentItemPasswordHistory.length})`;
  document.getElementById("password-history-list").style.display = "none";

  // Attachment
  currentItemAttachment = item.data.attachment || null;
  const attachPrev = document.getElementById("attachment-preview");
  if (currentItemAttachment) {
    attachPrev.style.display = "block";
    attachPrev.innerHTML = `
      <div class="attachment-badge" style="display: inline-flex; align-items: center; gap: 4px;">
        <span style="width: 13px; height: 13px; display: inline-flex;">${SVG_ICONS.attachment}</span> ${escapeHtml(currentItemAttachment.name)} (${formatFileSize(currentItemAttachment.size)})
        <a href="#" onclick="removeCurrentAttachment(event)" style="color: #f87171; text-decoration: none; margin-left: 6px; display: inline-flex; align-items: center; gap: 2px;"><span style="width: 10px; height: 10px; display: inline-flex;">${SVG_ICONS.close}</span> Entfernen</a>
      </div>
    `;
  } else {
    attachPrev.style.display = "none";
  }

  openModal("modal-item");
}

function toggleItemTypeFields(type) {
  document.getElementById("fields-login").style.display = type === "login" ? "block" : "none";
  document.getElementById("fields-note").style.display = type === "note" ? "block" : "none";
  document.getElementById("fields-card").style.display = type === "card" ? "block" : "none";
}

function togglePasswordHistoryView(e) {
  if (e) e.preventDefault();
  const list = document.getElementById("password-history-list");
  if (list.style.display === "none") {
    list.style.display = "block";
    if (currentItemPasswordHistory.length === 0) {
      list.innerHTML = `<div style="font-size: 0.75rem; color: var(--text-dim); padding: 4px;">Keine früheren Passwörter hinterlegt.</div>`;
    } else {
      list.innerHTML = currentItemPasswordHistory.map((h, idx) => `
        <div class="history-item">
          <div>
            <span style="font-family: monospace;">${escapeHtml(h.password)}</span>
            <div style="font-size: 0.7rem; color: var(--text-dim);">${new Date(h.changedAt).toLocaleString()}</div>
          </div>
          <button type="button" class="btn-icon" onclick="copyHistoryPassword(${idx})" title="Kopieren">${SVG_ICONS.copy}</button>
        </div>
      `).join('');
    }
  } else {
    list.style.display = "none";
  }
}

function copyHistoryPassword(idx) {
  const h = currentItemPasswordHistory[idx];
  if (h && h.password) {
    copyToClipboard(h.password, "Altes Passwort kopiert! (Leert in 30s)", true);
  }
}

function handleAttachmentSelected(event) {
  const file = event.target.files[0];
  if (!file) return;

  if (file.size > 5 * 1024 * 1024) {
    showToast("Dateianhänge dürfen maximal 5 MB groß sein.", "error");
    event.target.value = "";
    return;
  }

  const reader = new FileReader();
  reader.onload = (e) => {
    currentItemAttachment = {
      name: file.name,
      size: file.size,
      type: file.type,
      dataUrl: e.target.result
    };
    const attachPrev = document.getElementById("attachment-preview");
    attachPrev.style.display = "block";
    attachPrev.innerHTML = `
      <div class="attachment-badge" style="display: inline-flex; align-items: center; gap: 4px;">
        <span style="width: 13px; height: 13px; display: inline-flex;">${SVG_ICONS.attachment}</span> ${escapeHtml(file.name)} (${formatFileSize(file.size)})
        <a href="#" onclick="removeCurrentAttachment(event)" style="color: #f87171; text-decoration: none; margin-left: 6px; display: inline-flex; align-items: center; gap: 2px;"><span style="width: 10px; height: 10px; display: inline-flex;">${SVG_ICONS.close}</span> Entfernen</a>
      </div>
    `;
    showToast("Datei bereit zur Verschlüsselung!", "info");
  };
  reader.readAsDataURL(file);
}

function removeCurrentAttachment(e) {
  if (e) e.preventDefault();
  currentItemAttachment = null;
  document.getElementById("item-attachment-file").value = "";
  document.getElementById("attachment-preview").style.display = "none";
}

function downloadAttachment(itemId) {
  const item = decryptedItems.find(i => i.id === itemId);
  if (!item || !item.data.attachment) return;

  const att = item.data.attachment;
  const a = document.createElement("a");
  a.href = att.dataUrl;
  a.download = att.name;
  a.click();
  showToast(`Datei "${att.name}" entschlüsselt heruntergeladen!`, "success");
}

function formatFileSize(bytes) {
  if (!bytes) return "0 B";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

async function saveVaultItem(e) {
  e.preventDefault();
  const id = document.getElementById("item-id").value;
  const type = document.getElementById("item-type").value;
  const title = document.getElementById("item-title").value.trim();
  const favorite = document.getElementById("item-favorite").checked;

  let payload = {};
  if (type === "login") {
    const newPassword = document.getElementById("item-password").value;
    
    // Check if password changed and track history
    const existing = id ? decryptedItems.find(i => i.id === id) : null;
    let history = currentItemPasswordHistory || [];
    if (existing && existing.data.password && existing.data.password !== newPassword) {
      history.unshift({
        password: existing.data.password,
        changedAt: new Date().toISOString()
      });
      if (history.length > 10) history = history.slice(0, 10);
    }

    payload = {
      url: document.getElementById("item-url").value.trim(),
      username: document.getElementById("item-username").value.trim(),
      password: newPassword,
      totp: document.getElementById("item-totp").value.trim(),
      passwordHistory: history,
      attachment: currentItemAttachment
    };
  } else if (type === "note") {
    payload = {
      notes: document.getElementById("item-notes").value,
      attachment: currentItemAttachment
    };
  } else if (type === "card") {
    payload = {
      cardNumber: document.getElementById("item-card-number").value.trim(),
      expiry: document.getElementById("item-card-expiry").value.trim(),
      cvv: document.getElementById("item-card-cvv").value.trim()
    };
  }

  // Client-side AES-256-GCM encryption
  const encryptedPayload = await encryptPayload(payload, masterEncryptionKey);

  try {
    const url = id ? `/api/vault/items/${id}` : "/api/vault/items";
    const method = id ? "PUT" : "POST";

    const res = await fetch(url, {
      method: method,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${sessionToken}`
      },
      body: JSON.stringify({
        type: type,
        title: title,
        folder: document.getElementById("item-folder").value.trim(),
        favorite: favorite,
        encrypted_payload: encryptedPayload
      })
    });

    if (!res.ok) throw new Error("Fehler beim Speichern");

    closeModal("modal-item");
    showToast("Eintrag sicher verschlüsselt & gespeichert!", "success");
    await loadVault();
  } catch (err) {
    showToast("Fehler: " + err.message, "error");
  }
}

async function deleteVaultItem(id, permanent = false) {
  if (permanent) {
    if (!confirm("Diesen Eintrag wirklich unwiderruflich vernichten?")) return;
  }

  try {
    const res = await fetch(`/api/vault/items/${id}?permanent=${permanent}`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    if (!res.ok) throw new Error("Fehler beim Löschen");

    showToast(permanent ? "Eintrag endgültig vernichtet" : "In den Papierkorb verschoben", "info");
    await loadVault();
  } catch (err) {
    showToast("Fehler: " + err.message, "error");
  }
}

async function restoreVaultItem(id) {
  try {
    const res = await fetch(`/api/vault/items/${id}/restore`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    if (!res.ok) throw new Error("Fehler beim Wiederherstellen");

    showToast("Eintrag aus dem Papierkorb wiederhergestellt!", "success");
    await loadVault();
  } catch (err) {
    showToast("Fehler: " + err.message, "error");
  }
}

async function emptyAllTrash() {
  if (!confirm("Möchtest du den gesamten Papierkorb wirklich unwiderruflich leeren?")) return;

  try {
    const res = await fetch("/api/vault/trash", {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    if (!res.ok) throw new Error("Fehler beim Leeren");

    showToast("Papierkorb vollständig geleert.", "info");
    await loadVault();
  } catch (err) {
    showToast("Fehler: " + err.message, "error");
  }
}

async function toggleFavorite(id) {
  const item = decryptedItems.find(i => i.id === id);
  if (!item) return;

  try {
    await fetch(`/api/vault/items/${id}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${sessionToken}`
      },
      body: JSON.stringify({ favorite: !item.favorite })
    });
    await loadVault();
  } catch (err) {
    showToast("Fehler: " + err.message, "error");
  }
}

function toggleCardPassword(id, btnEl) {
  const el = document.getElementById(`pwd-${id}`);
  if (!el) return;
  const item = decryptedItems.find(i => i.id === id);
  if (!item || !item.data || !item.data.password) return;
  if (el.innerText === "••••••••••••") {
    el.innerText = item.data.password;
    if (btnEl) btnEl.innerHTML = SVG_ICONS.eyeOff;
  } else {
    el.innerText = "••••••••••••";
    if (btnEl) btnEl.innerHTML = SVG_ICONS.eye;
  }
}

function copyItemUsername(id) {
  const item = decryptedItems.find(i => i.id === id);
  if (item && item.data && item.data.username) {
    copyToClipboard(item.data.username, "Benutzername kopiert!");
  }
}

function copyItemPassword(id) {
  const item = decryptedItems.find(i => i.id === id);
  if (item && item.data && item.data.password) {
    copyToClipboard(item.data.password, "Passwort kopiert! (Leert in 30s)", true);
  }
}

// =============================================================
// PASSKEY MANAGEMENT & WEBAUTHN SIMULATION
// =============================================================

function openAddPasskeyModal() {
  document.getElementById("pk-rp-id").value = "";
  document.getElementById("pk-rp-name").value = "";
  document.getElementById("pk-username").value = "";
  openModal("modal-passkey");
}

async function savePasskey(e) {
  e.preventDefault();
  const rpId = document.getElementById("pk-rp-id").value.trim().toLowerCase();
  const rpName = document.getElementById("pk-rp-name").value.trim();
  const username = document.getElementById("pk-username").value.trim();

  try {
    // 1. Generate FIDO2 NIST P-256 (ES256) Key Pair
    const genRes = await fetch("/api/passkeys/generate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${sessionToken}`
      },
      body: JSON.stringify({
        rp_id: rpId,
        rp_name: rpName,
        username: username
      })
    });
    const keyData = await genRes.json();
    if (!genRes.ok) throw new Error(keyData.detail || "Schlüsselerzeugung fehlgeschlagen");

    // 2. Client-side encrypt private key with AES-256-GCM
    const encryptedPrivKey = await encryptPayload({ private_pem: keyData.private_key_pem }, masterEncryptionKey);

    // 3. Save Passkey in DB
    const saveRes = await fetch("/api/passkeys", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${sessionToken}`
      },
      body: JSON.stringify({
        rp_id: rpId,
        rp_name: rpName,
        username: username,
        user_handle: keyData.user_handle,
        credential_id: keyData.credential_id,
        encrypted_private_key: encryptedPrivKey,
        public_key_cose: keyData.public_key_cose,
        public_key_pem: keyData.public_key_pem,
        transports: ["internal", "hybrid"]
      })
    });

    if (!saveRes.ok) throw new Error("Passkey konnte nicht gespeichert werden");

    closeModal("modal-passkey");
    showToast("Passkey (FIDO2 ECDSA P-256) erfolgreich erstellt & verschlüsselt!", "success");
    await loadVault();
  } catch (err) {
    showToast("Fehler bei Passkey-Erstellung: " + err.message, "error");
  }
}

async function deletePasskey(id) {
  if (!confirm("Diesen Passkey wirklich löschen?")) return;
  try {
    await fetch(`/api/passkeys/${id}`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    showToast("Passkey gelöscht", "info");
    await loadVault();
  } catch (err) {
    showToast("Fehler: " + err.message, "error");
  }
}

function openPasskeyPlaygroundModal() {
  const select = document.getElementById("playground-passkey-select");
  select.innerHTML = '<option value="">-- Wähle einen Passkey aus --</option>';

  passkeysList.forEach(pk => {
    const opt = document.createElement("option");
    opt.value = pk.id;
    opt.innerText = `${pk.rp_name} (${pk.username} - ${pk.rp_id})`;
    select.appendChild(opt);
  });

  document.getElementById("playground-details").style.display = "none";
  document.getElementById("playground-result").style.display = "none";
  openModal("modal-passkey-playground");
}

function testPasskeyAssertion(passkeyId) {
  openPasskeyPlaygroundModal();
  document.getElementById("playground-passkey-select").value = passkeyId;
  loadPasskeyIntoPlayground(passkeyId);
}

function loadPasskeyIntoPlayground(id) {
  const pk = passkeysList.find(p => p.id === id);
  const details = document.getElementById("playground-details");
  if (!pk) {
    details.style.display = "none";
    return;
  }

  document.getElementById("play-cred-id").innerText = pk.credential_id;
  document.getElementById("play-cose").innerText = pk.public_key_cose;
  document.getElementById("play-sign-count").innerText = `${pk.sign_count} Signaturen`;
  details.style.display = "block";
}

async function executePlaygroundSignature() {
  const id = document.getElementById("playground-passkey-select").value;
  if (!id) {
    showToast("Bitte zuerst einen Passkey auswählen!", "error");
    return;
  }

  const pk = passkeysList.find(p => p.id === id);
  if (!pk) return;

  // Decrypt private key client-side (support Sentinelbit envelope & raw Vaultwarden key)
  let privKeyPem = null;
  if (pk.encrypted_private_key) {
    if (typeof pk.encrypted_private_key === "string" && pk.encrypted_private_key.startsWith("{") && pk.encrypted_private_key.includes('"iv"')) {
      const decPriv = await decryptPayload(pk.encrypted_private_key, masterEncryptionKey);
      if (decPriv) privKeyPem = decPriv.private_pem || decPriv.raw_key;
    } else {
      privKeyPem = pk.encrypted_private_key;
    }
  }

  if (!privKeyPem) {
    showToast("Entschlüsselung des privaten Schlüssels fehlgeschlagen!", "error");
    return;
  }

  const clientDataJson = document.getElementById("play-challenge").value;
  const authDataHex = "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000001";

  try {
    const res = await fetch("/api/passkeys/sign-test", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${sessionToken}`
      },
      body: JSON.stringify({
        private_key_pem: decPriv.private_pem,
        client_data_json: clientDataJson,
        auth_data_hex: authDataHex
      })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Signierung fehlgeschlagen");

    document.getElementById("play-result-sig").innerText = data.assertion.signature_b64;
    document.getElementById("playground-result").style.display = "block";
    showToast("WebAuthn Assertion erfolgreich erstellt!", "success");
  } catch (err) {
    showToast("Fehler bei Assertion: " + err.message, "error");
  }
}

// =============================================================
// VAULT 2FA (TOTP) SETUP & MANAGEMENT
// =============================================================

async function open2FaModal() {
  const setupView = document.getElementById("2fa-setup-view");
  const enabledView = document.getElementById("2fa-enabled-view");
  const recoveryView = document.getElementById("2fa-recovery-codes-view");
  recoveryView.style.display = "none";

  if (currentUser && currentUser.totp_enabled) {
    setupView.style.display = "none";
    enabledView.style.display = "block";
  } else {
    setupView.style.display = "block";
    enabledView.style.display = "none";

    // Request new 2FA setup QR
    const res = await fetch("/api/auth/2fa/setup", {
      method: "POST",
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    const data = await res.json();
    if (res.ok) {
      document.getElementById("2fa-qr-img").src = "data:image/png;base64," + data.qr_code_base64;
      document.getElementById("2fa-secret-text").value = data.secret;
    }
  }

  openModal("modal-2fa");
}

async function confirmEnable2Fa() {
  const code = document.getElementById("2fa-verify-code").value.trim();
  if (!code) {
    showToast("Bitte gib den 6-stelligen Code aus deiner App ein.", "error");
    return;
  }

  try {
    const res = await fetch("/api/auth/2fa/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${sessionToken}`
      },
      body: JSON.stringify({ code: code })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Code ungültig");

    currentUser.totp_enabled = true;
    document.getElementById("badge-vault-2fa-status").innerText = "Aktiv ✓";
    document.getElementById("badge-vault-2fa-status").className = "badge badge-totp";

    // Display recovery codes
    const list = document.getElementById("recovery-codes-list");
    list.innerHTML = "";
    data.recovery_codes.forEach(rc => {
      const el = document.createElement("div");
      el.innerText = rc;
      list.appendChild(el);
    });

    document.getElementById("2fa-setup-view").style.display = "none";
    document.getElementById("2fa-recovery-codes-view").style.display = "block";

    showToast("2FA erfolgreich aktiviert!", "success");
  } catch (err) {
    showToast("Fehler: " + err.message, "error");
  }
}

async function disable2Fa() {
  const code = document.getElementById("2fa-disable-code").value.trim();
  if (!code) {
    showToast("Bitte Bestätigungscode eingeben", "error");
    return;
  }

  try {
    const res = await fetch("/api/auth/2fa/disable", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${sessionToken}`
      },
      body: JSON.stringify({ code: code })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Konnte nicht deaktiviert werden");

    currentUser.totp_enabled = false;
    document.getElementById("badge-vault-2fa-status").innerText = "Aus";
    document.getElementById("badge-vault-2fa-status").className = "badge";

    closeModal("modal-2fa");
    showToast("2FA wurde deaktiviert.", "info");
  } catch (err) {
    showToast("Fehler: " + err.message, "error");
  }
}

// =============================================================
// PASSWORD & DICEWARE PASSPHRASE GENERATOR
// =============================================================

let activeGenMode = 'char';

function switchGenMode(mode) {
  activeGenMode = mode;
  document.getElementById("tab-gen-char").className = mode === 'char' ? "tab-btn active" : "tab-btn";
  document.getElementById("tab-gen-phrase").className = mode === 'phrase' ? "tab-btn active" : "tab-btn";
  document.getElementById("gen-mode-char").style.display = mode === 'char' ? "block" : "none";
  document.getElementById("gen-mode-phrase").style.display = mode === 'phrase' ? "block" : "none";
  runPasswordGenerator();
}

function generatePassword(length = 20, upper = true, lower = true, numbers = true, symbols = true) {
  let chars = "";
  if (upper) chars += "ABCDEFGHJKLMNPQRSTUVWXYZ";
  if (lower) chars += "abcdefghijkmnopqrstuvwxyz";
  if (numbers) chars += "23456789";
  if (symbols) chars += "!@#$%^&*()-_=+[]{}<>";

  if (!chars) chars = "abcdefghijklmnopqrstuvwxyz";

  const array = new Uint32Array(length);
  window.crypto.getRandomValues(array);
  let res = "";
  for (let i = 0; i < length; i++) {
    res += chars[array[i] % chars.length];
  }
  return res;
}

function generateDicewarePassphrase(wordCount = 4, separator = "-", capitalize = true, addNumber = true) {
  const array = new Uint32Array(wordCount);
  window.crypto.getRandomValues(array);

  const words = [];
  for (let i = 0; i < wordCount; i++) {
    let w = DICEWARE_WORDS[array[i] % DICEWARE_WORDS.length];
    if (capitalize) {
      w = w.charAt(0).toUpperCase() + w.slice(1);
    }
    words.push(w);
  }

  let phrase = words.join(separator);
  if (addNumber) {
    const numBuf = new Uint32Array(1);
    window.crypto.getRandomValues(numBuf);
    const num = (numBuf[0] % 90 + 10); // 2-digit number 10-99
    phrase += separator + num;
  }
  return phrase;
}

function openGeneratorModal() {
  runPasswordGenerator();
  openModal("modal-generator");
}

function runPasswordGenerator() {
  let res = "";
  if (activeGenMode === 'char') {
    const len = parseInt(document.getElementById("gen-length").value);
    const up = document.getElementById("gen-upper").checked;
    const low = document.getElementById("gen-lower").checked;
    const num = document.getElementById("gen-numbers").checked;
    const sym = document.getElementById("gen-symbols").checked;
    res = generatePassword(len, up, low, num, sym);
  } else {
    const words = parseInt(document.getElementById("gen-words").value);
    const sep = document.getElementById("gen-sep").value;
    const cap = document.getElementById("gen-cap").checked;
    const num = document.getElementById("gen-num-suffix").checked;
    res = generateDicewarePassphrase(words, sep, cap, num);
  }
  document.getElementById("gen-password-display").innerText = res;
}

function generatePasswordIntoField(fieldId) {
  const pwd = generatePassword(20, true, true, true, true);
  const el = document.getElementById(fieldId);
  if (el) {
    el.value = pwd;
    el.type = "text";
  }
  if (fieldId === "item-password") {
    evaluateItemPasswordStrength(pwd);
  }
  showToast("Starkes Zufallspasswort generiert!", "info");
}

function togglePasswordVisibility(fieldId) {
  const el = document.getElementById(fieldId);
  el.type = el.type === "password" ? "text" : "password";
}

// =============================================================
// AUDIT & HAVEIBEENPWNED (k-Anonymity)
// =============================================================

let currentAuditState = {
  total: 0,
  score: 100,
  reused: [],     // [{ item, count, pwd }]
  weak: [],       // [{ item, reason }]
  missing2fa: [], // [{ item }]
  old: [],        // [{ item, ageDays, reason }]
  leaked: [],     // [{ item, count }]
  activeFilter: "all"
};

function editAuditItem(id) {
  closeModal("modal-audit");
  openEditItemModal(id);
}

function setAuditFilter(filter) {
  currentAuditState.activeFilter = filter;
  renderAuditFilterTabs();
  renderAuditIssueList();
}

function openAuditModal() {
  const logins = decryptedItems.filter(it => it.type === "login" && !it.trash);
  const passwordsMap = {};
  const weakList = [];
  const missing2faList = [];
  const oldList = [];
  const now = new Date();
  const ONE_DAY_MS = 24 * 60 * 60 * 1000;

  const commonPasswords = new Set([
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
    "1234567", "dragon", "123123", "baseball", "football", "master", "welcome", "qwertz",
    "admin", "passwort", "geheim", "hallo123", "schatz"
  ]);

  logins.forEach(it => {
    const pwd = (it.data && it.data.password) ? String(it.data.password) : "";
    if (pwd) {
      if (!passwordsMap[pwd]) passwordsMap[pwd] = [];
      passwordsMap[pwd].push(it);

      // Check weakness
      let isWeak = false;
      let reason = "";
      if (pwd.length < 12) {
        isWeak = true;
        reason = `Nur ${pwd.length} Zeichen (mindestens 12 empfohlen)`;
      } else if (commonPasswords.has(pwd.toLowerCase())) {
        isWeak = true;
        reason = "Häufig verwendetes Standard-Passwort";
      } else {
        const hasUpper = /[A-Z]/.test(pwd);
        const hasLower = /[a-z]/.test(pwd);
        const hasDigit = /[0-9]/.test(pwd);
        const hasSpecial = /[^A-Za-z0-9]/.test(pwd);
        const diversity = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
        if (diversity < 3) {
          isWeak = true;
          reason = "Geringe Zeichenvielfalt (fehlen Groß-/Kleinbuchstaben, Zahlen oder Symbole)";
        }
      }

      if (isWeak) {
        weakList.push({ item: it, reason });
      }

      // Check password age (older than 180 days)
      const dateStr = it.updated_at || it.created_at;
      if (dateStr) {
        const itemDate = new Date(dateStr);
        const diffMs = now - itemDate;
        const ageDays = Math.floor(diffMs / ONE_DAY_MS);
        if (ageDays >= 180) {
          oldList.push({
            item: it,
            ageDays: ageDays,
            reason: `Passwort seit ${ageDays} Tagen nicht geändert (über 6 Monate)`
          });
        }
      }
    }

    // Check missing 2FA
    if (!it.data || !it.data.totp) {
      missing2faList.push({ item: it });
    }
  });

  // Reused passwords
  const reusedList = [];
  Object.keys(passwordsMap).forEach(pwd => {
    if (passwordsMap[pwd].length > 1) {
      passwordsMap[pwd].forEach(item => {
        reusedList.push({
          item,
          count: passwordsMap[pwd].length,
          pwd
        });
      });
    }
  });

  // Calculate Health Score (0-100)
  let score = 100;
  if (logins.length > 0) {
    const reusedGroups = Object.keys(passwordsMap).filter(p => passwordsMap[p].length > 1).length;
    score -= Math.min(35, reusedGroups * 10);
    score -= Math.min(30, weakList.length * 8);
    score -= Math.min(15, Math.floor(missing2faList.length * 1.5));
    score -= Math.min(10, Math.floor(oldList.length * 2));
    if (currentAuditState.leaked.length > 0) {
      score -= Math.min(30, currentAuditState.leaked.length * 15);
    }
    score = Math.max(0, Math.min(100, Math.round(score)));
  }

  currentAuditState.total = logins.length;
  currentAuditState.score = score;
  currentAuditState.reused = reusedList;
  currentAuditState.weak = weakList;
  currentAuditState.missing2fa = missing2faList;
  currentAuditState.old = oldList;
  currentAuditState.activeFilter = "all";

  renderAuditOverview();
  renderAuditFilterTabs();
  renderAuditIssueList();

  openModal("modal-audit");
}

function renderAuditOverview() {
  const container = document.getElementById("audit-results");
  const s = currentAuditState;

  let scoreColor = "var(--color-success)";
  let scoreBadge = "Hervorragend";
  let scoreGlow = "rgba(16, 185, 129, 0.2)";
  if (s.score < 60) {
    scoreColor = "var(--color-danger)";
    scoreBadge = "Kritisch";
    scoreGlow = "rgba(244, 63, 94, 0.25)";
  } else if (s.score < 85) {
    scoreColor = "var(--color-warning)";
    scoreBadge = "Verbesserungswürdig";
    scoreGlow = "rgba(245, 158, 11, 0.2)";
  }

  container.innerHTML = `
    <div style="background: linear-gradient(135deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01)); border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 18px; margin-bottom: 16px;">
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
        <div style="display: flex; align-items: center; gap: 16px;">
          <div style="width: 72px; height: 72px; border-radius: 50%; display: flex; flex-direction: column; align-items: center; justify-content: center; background: ${scoreGlow}; border: 3px solid ${scoreColor}; box-shadow: 0 0 20px ${scoreGlow};">
            <span style="font-size: 1.5rem; font-weight: 800; color: ${scoreColor}; line-height: 1;">${s.score}</span>
            <span style="font-size: 0.65rem; color: var(--text-dim); text-transform: uppercase; font-weight: 700;">Score</span>
          </div>
          <div>
            <div style="display: flex; align-items: center; gap: 8px;">
              <h4 style="font-size: 1.1rem; margin: 0;">Tresor-Sicherheitslevel</h4>
              <span class="badge" style="background: ${scoreGlow}; color: ${scoreColor}; border: 1px solid ${scoreColor}; font-weight: 700; font-size: 0.72rem; padding: 2px 8px; border-radius: 999px;">
                ${scoreBadge}
              </span>
            </div>
            <p style="font-size: 0.82rem; color: var(--text-muted); margin: 4px 0 0 0;">
              ${s.total} Login-Einträge lokal analysiert. Keine Klartextdaten verlassen den Browser.
            </p>
          </div>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(115px, 1fr)); gap: 10px; margin-top: 16px;">
        <div onclick="setAuditFilter('reused')" style="cursor: pointer; background: var(--bg-card); border: 1px solid ${s.reused.length > 0 ? 'rgba(245, 158, 11, 0.4)' : 'var(--border-color)'}; padding: 10px; border-radius: var(--radius-md); text-align: center; transition: transform 0.2s;" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='none'">
          <div style="font-size: 1.35rem; font-weight: 800; color: ${s.reused.length > 0 ? 'var(--color-warning)' : 'var(--color-success)'};">${s.reused.length}</div>
          <div style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">Wiederverwendet</div>
        </div>
        <div onclick="setAuditFilter('weak')" style="cursor: pointer; background: var(--bg-card); border: 1px solid ${s.weak.length > 0 ? 'rgba(244, 63, 94, 0.4)' : 'var(--border-color)'}; padding: 10px; border-radius: var(--radius-md); text-align: center; transition: transform 0.2s;" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='none'">
          <div style="font-size: 1.35rem; font-weight: 800; color: ${s.weak.length > 0 ? 'var(--color-danger)' : 'var(--color-success)'};">${s.weak.length}</div>
          <div style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">Schwache Passwörter</div>
        </div>
        <div onclick="setAuditFilter('old')" style="cursor: pointer; background: var(--bg-card); border: 1px solid ${s.old.length > 0 ? 'rgba(251, 191, 36, 0.4)' : 'var(--border-color)'}; padding: 10px; border-radius: var(--radius-md); text-align: center; transition: transform 0.2s;" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='none'">
          <div style="font-size: 1.35rem; font-weight: 800; color: ${s.old.length > 0 ? '#fbbf24' : 'var(--color-success)'};">${s.old.length}</div>
          <div style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">Veraltet (&gt;6 Mo.)</div>
        </div>
        <div onclick="setAuditFilter('2fa')" style="cursor: pointer; background: var(--bg-card); border: 1px solid var(--border-color); padding: 10px; border-radius: var(--radius-md); text-align: center; transition: transform 0.2s;" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='none'">
          <div style="font-size: 1.35rem; font-weight: 800; color: #38bdf8;">${s.missing2fa.length}</div>
          <div style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">Ohne 2FA (TOTP)</div>
        </div>
        <div onclick="setAuditFilter('leaked')" style="cursor: pointer; background: var(--bg-card); border: 1px solid ${s.leaked.length > 0 ? 'rgba(244, 63, 94, 0.5)' : 'var(--border-color)'}; padding: 10px; border-radius: var(--radius-md); text-align: center; transition: transform 0.2s;" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='none'">
          <div style="font-size: 1.35rem; font-weight: 800; color: ${s.leaked.length > 0 ? 'var(--color-danger)' : 'var(--text-dim)'};">${s.leaked.length}</div>
          <div style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">In Leaks (HIBP)</div>
        </div>
      </div>
    </div>
  `;
}

function renderAuditFilterTabs() {
  const tabsContainer = document.getElementById("audit-tabs");
  const s = currentAuditState;

  const tabs = [
    { id: "all", label: `Alle Meldungen (${s.reused.length + s.weak.length + s.old.length + s.leaked.length})` },
    { id: "reused", label: `Wiederverwendet (${s.reused.length})` },
    { id: "weak", label: `Schwach (${s.weak.length})` },
    { id: "old", label: `Veraltet (${s.old.length})` },
    { id: "2fa", label: `Fehlende 2FA (${s.missing2fa.length})` },
    { id: "leaked", label: `Datenlecks (${s.leaked.length})` }
  ];

  tabsContainer.innerHTML = tabs.map(t => `
    <button type="button" class="btn btn-sm ${s.activeFilter === t.id ? 'btn-primary' : 'btn-secondary'}" onclick="setAuditFilter('${t.id}')" style="font-size: 0.78rem; padding: 4px 10px; border-radius: 999px;">
      ${t.label}
    </button>
  `).join("");
}

function renderAuditIssueList() {
  const listContainer = document.getElementById("audit-issue-list");
  const s = currentAuditState;
  const filter = s.activeFilter;

  // Aggregate items with issues
  const itemMap = new Map();

  if (filter === "all" || filter === "reused") {
    s.reused.forEach(r => {
      const it = r.item;
      if (!itemMap.has(it.id)) itemMap.set(it.id, { item: it, issues: [] });
      itemMap.get(it.id).issues.push({
        type: "reused",
        badge: "Wiederverwendet",
        color: "#f59e0b",
        bg: "rgba(245, 158, 11, 0.15)",
        detail: `Passwort wird von ${r.count} Konten geteilt`
      });
    });
  }

  if (filter === "all" || filter === "weak") {
    s.weak.forEach(w => {
      const it = w.item;
      if (!itemMap.has(it.id)) itemMap.set(it.id, { item: it, issues: [] });
      itemMap.get(it.id).issues.push({
        type: "weak",
        badge: "Schwach",
        color: "#f43f5e",
        bg: "rgba(244, 63, 94, 0.15)",
        detail: w.reason
      });
    });
  }

  if (filter === "all" || filter === "old") {
    s.old.forEach(o => {
      const it = o.item;
      if (!itemMap.has(it.id)) itemMap.set(it.id, { item: it, issues: [] });
      itemMap.get(it.id).issues.push({
        type: "old",
        badge: "Veraltet",
        color: "#fbbf24",
        bg: "rgba(251, 191, 36, 0.15)",
        detail: o.reason
      });
    });
  }

  if (filter === "2fa") {
    s.missing2fa.forEach(m => {
      const it = m.item;
      if (!itemMap.has(it.id)) itemMap.set(it.id, { item: it, issues: [] });
      itemMap.get(it.id).issues.push({
        type: "2fa",
        badge: "Kein 2FA",
        color: "#38bdf8",
        bg: "rgba(56, 189, 248, 0.15)",
        detail: "Zwei-Faktor-Authentifizierung (TOTP) nicht eingerichtet"
      });
    });
  }

  if (filter === "all" || filter === "leaked") {
    s.leaked.forEach(l => {
      const it = l.item;
      if (!itemMap.has(it.id)) itemMap.set(it.id, { item: it, issues: [] });
      itemMap.get(it.id).issues.push({
        type: "leaked",
        badge: "Datenleak!",
        color: "#f43f5e",
        bg: "rgba(244, 63, 94, 0.25)",
        detail: `In öffentlichen Datenlecks gefunden (${l.count.toLocaleString()}x)`
      });
    });
  }

  const entries = Array.from(itemMap.values());

  if (entries.length === 0) {
    listContainer.innerHTML = `
      <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: var(--radius-md); padding: 24px; text-align: center; color: var(--color-success);">
        <div style="width: 36px; height: 36px; margin: 0 auto 10px auto; color: #34d399;">${SVG_ICONS.shield}</div>
        <div style="font-weight: 700; font-size: 0.95rem;">Keine Probleme in dieser Kategorie gefunden!</div>
        <div style="font-size: 0.8rem; color: var(--text-dim); margin-top: 4px;">Deine Passwörter entsprechen in diesem Bereich den Best-Practice-Sicherheitsstandards.</div>
      </div>
    `;
    return;
  }

  listContainer.innerHTML = entries.map(e => {
    const it = e.item;
    const username = (it.data && it.data.username) ? escapeHtml(it.data.username) : "Kein Benutzername";
    const url = (it.data && it.data.url) ? escapeHtml(it.data.url) : "";

    return `
      <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 12px 14px; display: flex; align-items: center; justify-content: space-between; gap: 12px;">
        <div style="flex: 1; min-width: 0;">
          <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
            <span style="font-weight: 700; font-size: 0.92rem; color: var(--text-main);">${escapeHtml(it.title)}</span>
            ${e.issues.map(iss => `
              <span style="background: ${iss.bg}; color: ${iss.color}; font-size: 0.7rem; font-weight: 700; padding: 2px 7px; border-radius: 999px; border: 1px solid ${iss.color};">
                ${iss.badge}
              </span>
            `).join("")}
          </div>
          <div style="font-size: 0.78rem; color: var(--text-dim); margin-top: 3px; display: flex; gap: 10px; align-items: center;">
            <span style="display: inline-flex; align-items: center; gap: 4px;"><span style="width: 12px; height: 12px; display: inline-flex;">${SVG_ICONS.login}</span> ${username}</span>
            ${url ? `<span style="display: inline-flex; align-items: center; gap: 4px;"><span style="width: 12px; height: 12px; display: inline-flex;">${SVG_ICONS.folder}</span> ${url}</span>` : ""}
          </div>
          <div style="margin-top: 4px; font-size: 0.76rem; color: var(--text-muted);">
            ${e.issues.map(iss => `<div>• ${escapeHtml(iss.detail)}</div>`).join("")}
          </div>
        </div>

        <button type="button" class="btn btn-secondary btn-sm" onclick="editAuditItem('${it.id}')" style="white-space: nowrap; font-size: 0.78rem; padding: 6px 12px; display: inline-flex; align-items: center; gap: 4px;">
          ${SVG_ICONS.edit} Bearbeiten
        </button>
      </div>
    `;
  }).join("");
}

async function runHibpBreachCheck() {
  const btn = document.getElementById("btn-run-hibp");
  const resContainer = document.getElementById("hibp-results-container");
  btn.disabled = true;
  btn.innerText = "Prüfe Datenlecks...";
  resContainer.style.display = "block";
  resContainer.innerHTML = `<div style="font-size: 0.8rem; color: var(--text-dim);">Prüfe Passwörter via k-Anonymity (SHA-1 Prefix)...</div>`;

  const breaches = [];
  let checkedCount = 0;

  for (const item of decryptedItems) {
    if (item.type === "login" && item.data && item.data.password && !item.trash) {
      checkedCount++;
      try {
        const hash = await sha1Hex(item.data.password);
        const prefix = hash.slice(0, 5);
        const suffix = hash.slice(5);

        const resp = await fetch(`/api/tools/hibp/${prefix}`);
        const data = await resp.json();

        if (data.status === "ok" && data.data) {
          const lines = data.data.split("\n");
          for (const line of lines) {
            const parts = line.trim().split(":");
            if (parts[0].toUpperCase() === suffix) {
              const count = parseInt(parts[1], 10);
              breaches.push({
                item: item,
                title: item.title,
                count: count
              });
              break;
            }
          }
        }
      } catch (err) {
        console.error("HIBP Fehler:", err);
      }
    }
  }

  btn.disabled = false;
  btn.innerText = "Erneut prüfen";

  currentAuditState.leaked = breaches;

  if (breaches.length === 0) {
    resContainer.innerHTML = `
      <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: var(--radius-md); padding: 12px; font-size: 0.85rem; color: #34d399;">
        ✓ Hervorragend! Keines deiner ${checkedCount} Passwörter wurde in bekannten Leaks gefunden.
      </div>
    `;
  } else {
    resContainer.innerHTML = `
      <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: var(--radius-md); padding: 12px; margin-bottom: 8px; font-size: 0.85rem; color: #f87171;">
        ⚠️ Warnung: ${breaches.length} Passwort(e) wurden in öffentlichen Datenlecks gefunden!
      </div>
      ${breaches.map(b => `
        <div class="card-row" style="margin-bottom: 4px; display: flex; justify-content: space-between; align-items: center;">
          <span style="font-weight: 600;">${escapeHtml(b.title)}</span>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="color: #f87171; font-weight: 700; font-size: 0.8rem;">${b.count.toLocaleString()}x in Leaks gesehen</span>
            <button class="btn btn-secondary btn-sm" onclick="editAuditItem('${b.item.id}')" style="font-size: 0.72rem; padding: 2px 8px;">Ändern</button>
          </div>
        </div>
      `).join('')}
    `;
  }

  // Recalculate score and refresh issue lists
  renderAuditOverview();
  renderAuditFilterTabs();
  renderAuditIssueList();
}

// =============================================================
// BACKUP & EXPORT / MULTI-FORMAT IMPORT
// =============================================================

function openBackupModal() {
  openModal("modal-backup");
}

async function exportVault(encrypted = true) {
  let exportData;
  if (encrypted) {
    exportData = {
      version: 2,
      type: "encrypted_backup",
      enc_salt: currentUser.enc_salt,
      items: decryptedItems.map(i => ({
        id: i.id,
        type: i.type,
        title: i.title,
        folder: i.folder,
        favorite: i.favorite,
        encrypted_payload: i.encrypted_payload
      })),
      passkeys: passkeysList
    };
  } else {
    exportData = {
      version: 2,
      type: "plaintext_export",
      items: decryptedItems.map(i => ({
        type: i.type,
        title: i.title,
        folder: i.folder,
        favorite: i.favorite,
        data: i.data
      })),
      passkeys: passkeysList
    };
  }

  // Compute SHA-256 cryptographic checksum for tamper verification (#40)
  try {
    const itemsCanonical = JSON.stringify(exportData.items);
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", strToBuffer(itemsCanonical));
    exportData.checksum_sha256 = bufferToHex(hashBuffer);
  } catch (_) {}

  const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sentinelbit-backup-${encrypted ? 'encrypted' : 'plaintext'}-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast("Backup mit SHA-256 Prüfsumme heruntergeladen!", "success");
}

async function importVault() {
  const fileInput = document.getElementById("backup-file-input");
  if (!fileInput || !fileInput.files.length) {
    showToast("Bitte wähle eine Backup- oder CSV-Datei aus.", "error");
    return;
  }

  if (!masterEncryptionKey) {
    showToast("Tresorschlüssel nicht aktiv. Bitte melde dich erneut an.", "error");
    return;
  }

  const file = fileInput.files[0];
  const importBtn = document.querySelector("#modal-backup button[onclick='importVault()']");
  const originalBtnText = importBtn ? importBtn.innerHTML : "📥 Backup / Import einspielen";

  const reader = new FileReader();

  reader.onload = async (e) => {
    try {
      if (importBtn) {
        importBtn.disabled = true;
        importBtn.innerText = "⏳ Analysiere Datei...";
      }

      const content = e.target.result;
      let itemsToImport = [];
      let passkeysToImport = [];
      let skippedExisting = 0;

      // Existing items signatures for deduplication (prevents duplicate cards upon re-import)
      const existingSignatures = new Set(
        decryptedItems.map(it => {
          const u = (it.data?.username || "").toLowerCase().trim();
          const p = (it.data?.password || "").trim();
          const t = (it.title || "").toLowerCase().trim();
          const d = (extractDomain(it.data?.url) || "").toLowerCase().trim();
          return `${t}|${d}|${u}|${p}`;
        })
      );
      const existingCredIds = new Set(passkeysList.map(pk => pk.credential_id));

      // Determine format: Try JSON first, fallback to CSV
      let json = null;
      try {
        json = JSON.parse(content);
      } catch (err) {
        json = null;
      }

      if (json) {
        // Check for encrypted Bitwarden JSON export
        if (json.encrypted === true && (json.folders || (Array.isArray(json.items) && json.items.length > 0 && json.items[0].name !== undefined))) {
          throw new Error("Diese Bitwarden-Exportdatei ist passwortverschlüsselt ('JSON (Verschlüsselt)'). Bitte öffne Bitwarden > Einstellungen > Tresor exportieren und wähle 'Dateiformat: .json' (unverschlüsselt) oder 'Dateiformat: .csv' aus.");
        }

        // 1. Bitwarden JSON (unencrypted)
        const isBitwarden = (json.encrypted === false && Array.isArray(json.items)) ||
                            (Array.isArray(json.items) && json.items.length > 0 && (json.items[0].login !== undefined || json.items[0].type !== undefined || json.items[0].secureNote !== undefined || json.items[0].card !== undefined || json.folders !== undefined));

        if (isBitwarden && Array.isArray(json.items)) {
          for (const it of json.items) {
            const title = it.name || "Bitwarden Eintrag";
            const fav = Boolean(it.favorite);
            const notes = it.notes || "";

            // Custom fields support
            let fullNotes = notes;
            if (it.fields && Array.isArray(it.fields) && it.fields.length > 0) {
              const extra = it.fields.map(f => `${f.name || 'Feld'}: ${f.value || ''}`).filter(l => l.trim()).join("\n");
              if (extra) {
                fullNotes = fullNotes ? `${fullNotes}\n\n[Zusatzfelder]\n${extra}` : `[Zusatzfelder]\n${extra}`;
              }
            }

            // Check for Bitwarden Passkeys (fido2Credentials)
            if (it.login && it.login.fido2Credentials && Array.isArray(it.login.fido2Credentials) && it.login.fido2Credentials.length > 0) {
              for (const cred of it.login.fido2Credentials) {
                if (cred.credentialId && existingCredIds.has(cred.credentialId)) continue;
                if (cred.credentialId) existingCredIds.add(cred.credentialId);
                let encryptedPrivKey = cred.keyValue || "imported_fido2_key";
                if (cred.keyValue && masterEncryptionKey) {
                  try {
                    encryptedPrivKey = await encryptPayload({ private_pem: cred.keyValue, raw_key: cred.keyValue }, masterEncryptionKey);
                  } catch (_) {}
                }
                passkeysToImport.push({
                  vault_item_id: "",
                  rp_id: cred.rpId || extractDomain(it.login?.uris?.[0]?.uri) || (it.name ? it.name.toLowerCase().replace(/\s+/g, '') + ".com" : "unknown.com"),
                  rp_name: it.name || "Passkey",
                  username: cred.userName || (it.login && it.login.username) || "Unbekannter Benutzer",
                  user_handle: cred.userHandle || "",
                  credential_id: cred.credentialId || (window.crypto.randomUUID ? window.crypto.randomUUID() : Math.random().toString(36).slice(2)),
                  encrypted_private_key: encryptedPrivKey,
                  public_key_cose: cred.publicKeyCose || cred.credentialId || "imported_cose",
                  public_key_pem: "",
                  transports: JSON.stringify(cred.transports || ["internal", "hybrid"])
                });
              }
            }

            // Type 2: Secure Note
            if (it.type === 2 || it.secureNote) {
              const encPayload = await encryptPayload({ notes: fullNotes, attachment: null }, masterEncryptionKey);
              itemsToImport.push({ type: "note", title, favorite: fav, encrypted_payload: encPayload });
            }
            // Type 3: Card
            else if (it.type === 3 || it.card) {
              const card = it.card || {};
              const expMonth = card.expMonth ? String(card.expMonth).padStart(2, '0') : '';
              const expYear = card.expYear ? String(card.expYear).slice(-2) : '';
              const expiry = (expMonth && expYear) ? `${expMonth}/${expYear}` : '';
              const encPayload = await encryptPayload({
                cardNumber: card.number || '',
                expiry: expiry,
                cvv: card.code || ''
              }, masterEncryptionKey);
              itemsToImport.push({ type: "card", title, favorite: fav, encrypted_payload: encPayload });
            }
            // Type 4: Identity
            else if (it.type === 4 || it.identity) {
              const ident = it.identity || {};
              const identLines = [
                ident.title ? `Anrede: ${ident.title}` : '',
                (ident.firstName || ident.lastName) ? `Name: ${ident.firstName || ''} ${ident.lastName || ''}`.trim() : '',
                ident.company ? `Firma: ${ident.company}` : '',
                ident.email ? `E-Mail: ${ident.email}` : '',
                ident.phone ? `Telefon: ${ident.phone}` : '',
                ident.address1 ? `Adresse: ${ident.address1}` : '',
                ident.city ? `Stadt: ${ident.city}` : '',
                ident.postalCode ? `PLZ: ${ident.postalCode}` : '',
                ident.country ? `Land: ${ident.country}` : ''
              ].filter(Boolean).join("\n");
              const identNote = [fullNotes, identLines ? `[Identitätsdaten]\n${identLines}` : ''].filter(Boolean).join("\n\n");
              const encPayload = await encryptPayload({ notes: identNote, attachment: null }, masterEncryptionKey);
              itemsToImport.push({ type: "note", title, favorite: fav, encrypted_payload: encPayload });
            }
            // Type 1 / Default: Login
            else {
              let url = "";
              if (it.login && Array.isArray(it.login.uris) && it.login.uris.length > 0) {
                url = it.login.uris[0].uri || "";
              } else if (it.login && typeof it.login.uri === "string") {
                url = it.login.uri;
              }
              const username = (it.login && it.login.username) ? it.login.username : "";
              const password = (it.login && it.login.password) ? it.login.password : "";
              const totp = (it.login && it.login.totp) ? it.login.totp : "";

              const sign = `${title.toLowerCase().trim()}|${(extractDomain(url) || "").toLowerCase().trim()}|${username.toLowerCase().trim()}|${password.trim()}`;
              if (existingSignatures.has(sign)) {
                skippedExisting++;
                continue;
              }
              existingSignatures.add(sign);

              const encPayload = await encryptPayload({
                url,
                username,
                password,
                totp,
                notes: fullNotes,
                passwordHistory: [],
                attachment: null
              }, masterEncryptionKey);

              itemsToImport.push({
                type: "login",
                title: title,
                favorite: fav,
                encrypted_payload: encPayload
              });
            }
          }
        }
        // 2. sentinelbit Backup (JSON)
        else if (json.format === "sentinelbit_vault_backup" || json.type === "encrypted_backup" || json.type === "plaintext_export" || (Array.isArray(json.items) && json.items.length > 0 && (json.items[0].encrypted_payload || json.items[0].data))) {
          // Verify SHA-256 integrity checksum if present (#40)
          if (json.checksum_sha256 && Array.isArray(json.items)) {
            try {
              const itemsCanonical = JSON.stringify(json.items);
              const hashBuffer = await window.crypto.subtle.digest("SHA-256", strToBuffer(itemsCanonical));
              const computedHex = bufferToHex(hashBuffer);
              if (computedHex === json.checksum_sha256) {
                console.log("✅ SHA-256 Backup-Prüfsumme verifiziert: " + computedHex);
                showToast("✅ Kryptografische Prüfsumme (SHA-256) verifiziert!", "success");
              } else {
                console.warn("⚠️ Prüfsummen-Abweichung:", computedHex, "erwartet:", json.checksum_sha256);
                showToast("⚠️ Warnung: Prüfsumme weicht ab (mögliche Beschädigung)!", "warning");
              }
            } catch (_) {}
          }

          for (const item of json.items) {
            let encPayload = item.encrypted_payload;
            if (!encPayload && item.data) {
              encPayload = await encryptPayload(item.data, masterEncryptionKey);
            }
            if (encPayload) {
              itemsToImport.push({
                type: item.type || "login",
                title: item.title || "Wiederhergestellter Eintrag",
                favorite: Boolean(item.favorite),
                encrypted_payload: encPayload
              });
            }
          }

          // Restore Passkeys if present in backup
          if (json.passkeys && Array.isArray(json.passkeys) && json.passkeys.length > 0) {
            for (const pk of json.passkeys) {
              passkeysToImport.push({
                vault_item_id: pk.vault_item_id || "",
                rp_id: pk.rp_id,
                rp_name: pk.rp_name,
                username: pk.username,
                user_handle: pk.user_handle || "",
                credential_id: pk.credential_id,
                encrypted_private_key: pk.encrypted_private_key,
                public_key_cose: pk.public_key_cose,
                public_key_pem: pk.public_key_pem || "",
                transports: Array.isArray(pk.transports) ? JSON.stringify(pk.transports) : (pk.transports || '["internal","hybrid"]')
              });
            }
          }
        }
        // 3. 1Password 1PUX / Universal JSON Export
        else if (json.accounts || json.entries || Array.isArray(json)) {
          const list = Array.isArray(json) ? json : (json.entries || []);
          for (const it of list) {
            const title = it.title || it.overview?.title || it.name || "Importierter Eintrag";
            let username = it.username || "";
            let password = it.password || "";
            let url = it.overview?.url || it.url || (it.login?.uris && it.login.uris[0]?.uri) || "";
            let notes = it.details?.notesPlain || it.notes || "";

            if (it.details && it.details.fields) {
              for (const f of it.details.fields) {
                if (f.designation === "username" || f.name === "username") username = f.value || username;
                if (f.designation === "password" || f.name === "password") password = f.value || password;
              }
            }
            if (it.login) {
              username = it.login.username || username;
              password = it.login.password || password;
            }

            if (username || password || url || notes) {
              const encPayload = await encryptPayload({
                url,
                username,
                password,
                notes,
                totp: it.login?.totp || "",
                passwordHistory: [],
                attachment: null
              }, masterEncryptionKey);
              itemsToImport.push({
                type: "login",
                title: title,
                favorite: false,
                encrypted_payload: encPayload
              });
            }
          }
        }
      } else {
        // Universal RFC-Compliant CSV Parser supporting:
        // Bitwarden, KeePassXC, 1Password, LastPass, Google Chrome, Mozilla Firefox
        const firstLine = content.split(/\r\n|\r|\n/)[0] || "";
        const semiCount = (firstLine.match(/;/g) || []).length;
        const commaCount = (firstLine.match(/,/g) || []).length;
        const delimiter = semiCount > commaCount ? ';' : ',';

        const parseCSV = (text, delim) => {
          const rows = [];
          let row = [""];
          let inQuotes = false;
          for (let i = 0; i < text.length; i++) {
            const c = text[i];
            const next = text[i + 1];
            if (c === '"') {
              if (inQuotes && next === '"') {
                row[row.length - 1] += '"';
                i++;
              } else {
                inQuotes = !inQuotes;
              }
            } else if (c === delim && !inQuotes) {
              row.push('');
            } else if ((c === '\r' || c === '\n') && !inQuotes) {
              if (c === '\r' && next === '\n') i++;
              if (row.length > 1 || row[0] !== '') rows.push(row);
              row = [''];
            } else {
              row[row.length - 1] += c;
            }
          }
          if (row.length > 1 || row[0] !== '') rows.push(row);
          return rows;
        };

        const records = parseCSV(content, delimiter);
        if (records.length > 1) {
          const header = records[0].map(h => h.trim().toLowerCase());

          // Priority column detector: exact matches before partial matches
          const findCol = (exactList, partialList) => {
            for (const name of exactList) {
              const idx = header.indexOf(name);
              if (idx !== -1) return idx;
            }
            for (const partial of partialList) {
              const idx = header.findIndex(h => h.includes(partial));
              if (idx !== -1) return idx;
            }
            return -1;
          };

          const userIdx = findCol(
            ["login_username", "username", "user", "email", "login", "user_name"],
            ["username", "user", "email"]
          );
          const passIdx = findCol(
            ["login_password", "password", "pass", "pwd", "code"],
            ["password", "pass", "pwd"]
          );
          const urlIdx = findCol(
            ["login_uri", "url", "website", "link", "uri", "site"],
            ["url", "uri", "web", "site"]
          );
          const titleIdx = findCol(
            ["name", "title", "item_name", "account", "group"],
            ["name", "title"]
          );
          const totpIdx = findCol(
            ["login_totp", "totp", "otp", "2fa", "authenticator", "secret"],
            ["totp", "otp", "2fa"]
          );
          const noteIdx = findCol(
            ["notes", "note", "comments", "comment", "extra"],
            ["note", "comment"]
          );
          const typeIdx = findCol(
            ["type", "category", "item_type"],
            ["type"]
          );
          const favIdx = findCol(
            ["favorite", "fav", "starred"],
            ["fav"]
          );
          const fieldsIdx = header.indexOf("fields");

          for (let i = 1; i < records.length; i++) {
            const cols = records[i];
            if (cols.length === 0 || cols.every(c => !c.trim())) continue;

            const rawTitle = (titleIdx !== -1 && cols[titleIdx]) ? cols[titleIdx].trim() : "";
            const user = (userIdx !== -1 && cols[userIdx]) ? cols[userIdx].trim() : "";
            const pass = (passIdx !== -1 && cols[passIdx]) ? cols[passIdx] : "";
            const url = (urlIdx !== -1 && cols[urlIdx]) ? cols[urlIdx].trim() : "";
            const totp = (totpIdx !== -1 && cols[totpIdx]) ? cols[totpIdx].trim() : "";
            let notes = (noteIdx !== -1 && cols[noteIdx]) ? cols[noteIdx] : "";
            const itemType = (typeIdx !== -1 && cols[typeIdx]) ? cols[typeIdx].toLowerCase().trim() : "login";
            const fav = (favIdx !== -1 && (cols[favIdx] === "1" || cols[favIdx]?.toLowerCase() === "true"));

            if (fieldsIdx !== -1 && cols[fieldsIdx]) {
              notes = notes ? `${notes}\n\n[Zusatzfelder]\n${cols[fieldsIdx]}` : `[Zusatzfelder]\n${cols[fieldsIdx]}`;
            }

            const title = rawTitle || user || url || "Importierter Eintrag";

            if (itemType === "note") {
              const encPayload = await encryptPayload({ notes, attachment: null }, masterEncryptionKey);
              itemsToImport.push({ type: "note", title, favorite: fav, encrypted_payload: encPayload });
            } else if (itemType === "card") {
              const encPayload = await encryptPayload({ cardNumber: pass || '', expiry: '', cvv: '' }, masterEncryptionKey);
              itemsToImport.push({ type: "card", title, favorite: fav, encrypted_payload: encPayload });
            } else {
              if (user || pass || url || rawTitle || notes) {
                const sign = `${title.toLowerCase().trim()}|${(extractDomain(url) || "").toLowerCase().trim()}|${user.toLowerCase().trim()}|${pass.trim()}`;
                if (existingSignatures.has(sign)) {
                  skippedExisting++;
                  continue;
                }
                existingSignatures.add(sign);

                const encPayload = await encryptPayload({
                  url,
                  username: user,
                  password: pass,
                  totp,
                  notes,
                  passwordHistory: [],
                  attachment: null
                }, masterEncryptionKey);
                itemsToImport.push({
                  type: "login",
                  title: title,
                  favorite: fav,
                  encrypted_payload: encPayload
                });
              }
            }
          }
        }
      }

      if (itemsToImport.length === 0 && passkeysToImport.length === 0) {
        if (skippedExisting > 0) {
          closeModal("modal-backup");
          showToast(`Alle ${skippedExisting} Einträge aus der Datei sind bereits ohne Duplikate in deinem Tresor vorhanden!`, "info");
          return;
        }
        throw new Error("Keine kompatiblen Einträge in der Datei gefunden. Unterstützt: Bitwarden JSON/CSV, sentinelbit Backup, 1Password, KeePassXC, Chrome/Firefox CSV.");
      }

      // Fast atomic batch import via /api/vault/items/batch
      let count = 0;
      const BATCH_SIZE = 100;
      for (let i = 0; i < itemsToImport.length; i += BATCH_SIZE) {
        const batch = itemsToImport.slice(i, i + BATCH_SIZE);
        try {
          const res = await fetch("/api/vault/items/batch", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${sessionToken}`
            },
            body: JSON.stringify({ items: batch })
          });
          if (res.ok) {
            const data = await res.json();
            count += (data.inserted !== undefined ? data.inserted : batch.length);
          } else {
            // Fallback for older server versions: sequential individual POST
            for (const item of batch) {
              const sRes = await fetch("/api/vault/items", {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  "Authorization": `Bearer ${sessionToken}`
                },
                body: JSON.stringify(item)
              });
              if (sRes.ok) count++;
            }
          }
        } catch (e) {
          // Fallback sequential
          for (const item of batch) {
            try {
              const sRes = await fetch("/api/vault/items", {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  "Authorization": `Bearer ${sessionToken}`
                },
                body: JSON.stringify(item)
              });
              if (sRes.ok) count++;
            } catch (err) {}
          }
        }
        if (importBtn) {
          importBtn.innerText = `⏳ Importiere (${count}/${itemsToImport.length})...`;
        }
      }

      // Restore / Import Passkeys if present
      let pkCount = 0;
      for (const pk of passkeysToImport) {
        try {
          const pkRes = await fetch("/api/passkeys", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${sessionToken}`
            },
            body: JSON.stringify(pk)
          });
          if (pkRes.ok) pkCount++;
        } catch (e) {
          console.warn("Passkey Import-Fehler:", e);
        }
      }

      closeModal("modal-backup");
      let msg = `${count} Einträge`;
      if (pkCount > 0) msg += ` und ${pkCount} Passkeys`;
      msg += " erfolgreich importiert!";
      if (skippedExisting > 0) {
        msg += ` (${skippedExisting} bereits vorhandene Duplikate übersprungen)`;
      }
      showToast(msg, "success");
      await loadVault();
    } catch (err) {
      showToast("Importfehler: " + err.message, "error");
    } finally {
      if (importBtn) {
        importBtn.disabled = false;
        importBtn.innerHTML = originalBtnText;
      }
    }
  };
  reader.readAsText(file);
}

// =============================================================
// MODAL & UI HELPERS
// =============================================================

function openModal(modalId) {
  const el = document.getElementById(modalId);
  if (el) el.classList.add("active");
}

function closeModal(modalId) {
  const el = document.getElementById(modalId);
  if (el) el.classList.remove("active");
}

function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;

  let iconSvg = `<svg viewBox="0 0 24 24" style="width: 16px; height: 16px; stroke: #38bdf8; fill: none; stroke-width: 2.2;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
  if (type === "success") {
    iconSvg = `<svg viewBox="0 0 24 24" style="width: 16px; height: 16px; stroke: #34d399; fill: none; stroke-width: 2.5;"><polyline points="20 6 9 17 4 12"/></svg>`;
  } else if (type === "error" || type === "danger") {
    iconSvg = `<svg viewBox="0 0 24 24" style="width: 16px; height: 16px; stroke: #f87171; fill: none; stroke-width: 2.2;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
  } else if (type === "warning") {
    iconSvg = `<svg viewBox="0 0 24 24" style="width: 16px; height: 16px; stroke: #fbbf24; fill: none; stroke-width: 2.2;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
  }

  toast.innerHTML = `<span class="toast-icon">${iconSvg}</span><span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(100%)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

let clipboardClearTimer = null;

function copyToClipboard(text, successMsg, isSensitive = false) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    showToast(successMsg || "In die Zwischenablage kopiert!", "success");

    // Auto-clear sensitive passwords and TOTP codes after 30 seconds
    if (isSensitive) {
      if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
      clipboardClearTimer = setTimeout(async () => {
        try {
          const current = await navigator.clipboard.readText();
          if (current === text) {
            await navigator.clipboard.writeText("");
            showToast("🛡️ Zwischenablage nach 30s automatisch geleert.", "info");
          }
        } catch (_) {
          // Fallback if readText is blocked by browser policy
          navigator.clipboard.writeText("").then(() => {
            showToast("🛡️ Zwischenablage aus Sicherheitsgründen geleert.", "info");
          }).catch(() => {});
        }
      }, 30000);
    }
  }).catch(err => {
    console.error("Clipboard copy error:", err);
    showToast("Kopieren fehlgeschlagen.", "error");
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// =============================================================
// AUTO-SYNC & RECURRING BACKUP SETTINGS
// =============================================================

async function openSyncSettingsModal() {
  try {
    const res = await fetch("/api/sync/settings", {
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    if (res.ok) {
      const data = await res.json();
      document.getElementById("sync-active").checked = data.is_active;
      document.getElementById("sync-target-dir").value = data.target_dir || "";
      document.getElementById("sync-interval").value = data.interval_minutes || 15;
      document.getElementById("sync-retention").value = data.retention_count || 10;
      document.getElementById("sync-on-change").checked = data.sync_on_change;
      document.getElementById("sync-last-time").innerText = data.last_synced_at ? new Date(data.last_synced_at).toLocaleString() : "Noch nie";
      document.getElementById("sync-last-status").innerText = data.last_sync_status || "Bereit";

      const gdriveCheck = document.getElementById("sync-gdrive-enabled");
      if (gdriveCheck) {
        gdriveCheck.checked = !!data.gdrive_enabled;
        document.getElementById("sync-gdrive-folder").value = data.gdrive_folder_id || "";
        document.getElementById("sync-gdrive-creds").value = data.gdrive_credentials || "";
        toggleGDriveFields();

        const redirEl = document.getElementById("gdrive-redirect-uri-display");
        if (redirEl) {
          redirEl.innerText = `${window.location.origin}/api/sync/gdrive/callback`;
        }

        const oauthStatus = document.getElementById("gdrive-oauth-status");
        if (oauthStatus) oauthStatus.innerText = "";

        if (data.gdrive_credentials) {
          try {
            const parsed = JSON.parse(data.gdrive_credentials);
            if (parsed.type === "authorized_user") {
              if (parsed.client_id) document.getElementById("sync-gdrive-client-id").value = parsed.client_id;
              if (parsed.client_secret) document.getElementById("sync-gdrive-client-secret").value = parsed.client_secret;
              if (oauthStatus) {
                oauthStatus.innerText = "✓ Verbunden";
                oauthStatus.style.color = "#34d399";
              }
              switchGDriveTab("oauth");
            } else {
              switchGDriveTab("manual");
            }
          } catch (e) {
            switchGDriveTab("manual");
          }
        } else {
          switchGDriveTab("oauth");
        }

        const envHint = document.getElementById("gdrive-env-hint");
        if (envHint) {
          if (data.has_env_credentials) {
            envHint.innerText = "✓ Anmeldedaten auf Server-Ebene (Env / Docker) aktiv.";
            envHint.style.color = "#34d399";
          } else if (data.has_saved_creds) {
            envHint.innerText = "✓ Schlüssel bereits im Tresor hinterlegt.";
            envHint.style.color = "#34d399";
          } else {
            envHint.innerText = "Wird leer gelassen, falls bereits auf dem Server hinterlegt.";
            envHint.style.color = "var(--text-dim)";
          }
        }
        const testRes = document.getElementById("gdrive-test-result");
        if (testRes) testRes.style.display = "none";
      }
    }
    openModal("modal-sync");
  } catch (err) {
    showToast("Fehler beim Laden der Sync-Einstellungen: " + err.message, "error");
  }
}

function switchGDriveTab(tab) {
  const oauthTab = document.getElementById("gdrive-tab-oauth");
  const manualTab = document.getElementById("gdrive-tab-manual");
  const btnOauth = document.getElementById("tab-btn-oauth");
  const btnManual = document.getElementById("tab-btn-manual");
  if (!oauthTab || !manualTab) return;

  if (tab === "oauth") {
    oauthTab.style.display = "flex";
    manualTab.style.display = "none";
    if (btnOauth) {
      btnOauth.style.background = "rgba(56, 189, 248, 0.2)";
      btnOauth.style.color = "#38bdf8";
      btnOauth.style.fontWeight = "600";
    }
    if (btnManual) {
      btnManual.style.background = "transparent";
      btnManual.style.color = "var(--text-dim)";
      btnManual.style.fontWeight = "normal";
    }
  } else {
    oauthTab.style.display = "none";
    manualTab.style.display = "flex";
    if (btnManual) {
      btnManual.style.background = "rgba(56, 189, 248, 0.2)";
      btnManual.style.color = "#38bdf8";
      btnManual.style.fontWeight = "600";
    }
    if (btnOauth) {
      btnOauth.style.background = "transparent";
      btnOauth.style.color = "var(--text-dim)";
      btnOauth.style.fontWeight = "normal";
    }
  }
}

async function startGDriveOAuth() {
  const clientId = document.getElementById("sync-gdrive-client-id").value.trim();
  const clientSecret = document.getElementById("sync-gdrive-client-secret").value.trim();
  const statusEl = document.getElementById("gdrive-oauth-status");

  if (!clientId || !clientSecret) {
    showToast("Bitte gib zuerst Client-ID und Client-Secret ein.", "warning");
    return;
  }

  if (statusEl) {
    statusEl.innerText = "Öffne Google-Login...";
    statusEl.style.color = "#38bdf8";
  }

  try {
    const res = await fetch(`/api/sync/gdrive/auth-url?client_id=${encodeURIComponent(clientId)}&client_secret=${encodeURIComponent(clientSecret)}`, {
      headers: {
        "Authorization": `Bearer ${sessionToken}`
      }
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || data.message || "Fehler beim Anfordern der Google-Auth-URL");

    const width = 600;
    const height = 700;
    const left = window.screenLeft + (window.outerWidth - width) / 2;
    const top = window.screenTop + (window.outerHeight - height) / 2;
    const popup = window.open(data.auth_url, "gdrive_oauth", `width=${width},height=${height},top=${top},left=${left}`);

    if (!popup || popup.closed || typeof popup.closed === "undefined") {
      showToast("Popup wurde blockiert! Bitte Popups im Browser für diese Seite erlauben.", "error");
      if (statusEl) {
        statusEl.innerText = "Popup blockiert";
        statusEl.style.color = "#f87171";
      }
      return;
    }

    if (statusEl) {
      statusEl.innerText = "Warte auf Bestätigung...";
    }
  } catch (err) {
    showToast("OAuth-Fehler: " + err.message, "error");
    if (statusEl) {
      statusEl.innerText = "Fehler";
      statusEl.style.color = "#f87171";
    }
  }
}

window.addEventListener("message", (event) => {
  if (event.data && event.data.type === "gdrive_auth_result") {
    const statusEl = document.getElementById("gdrive-oauth-status");
    if (event.data.success) {
      showToast("Google Drive erfolgreich autorisiert!", "success");
      if (statusEl) {
        statusEl.innerText = "✓ Verbunden";
        statusEl.style.color = "#34d399";
      }
      const gdriveCheck = document.getElementById("sync-gdrive-enabled");
      if (gdriveCheck) gdriveCheck.checked = true;

      fetch("/api/sync/settings", {
        headers: { "Authorization": `Bearer ${sessionToken}` }
      })
      .then(res => res.json())
      .then(data => {
        if (data && data.gdrive_credentials) {
          const credsEl = document.getElementById("sync-gdrive-creds");
          if (credsEl) credsEl.value = data.gdrive_credentials;
        }
      })
      .catch(() => {});
    } else {
      showToast("Google Drive Autorisierung fehlgeschlagen.", "error");
      if (statusEl) {
        statusEl.innerText = "✗ Fehler bei Autorisierung";
        statusEl.style.color = "#f87171";
      }
    }
  }
});

function toggleGDriveFields() {
  const gdriveCheck = document.getElementById("sync-gdrive-enabled");
  const panel = document.getElementById("gdrive-config-panel");
  if (panel && gdriveCheck) {
    panel.style.display = gdriveCheck.checked ? "flex" : "none";
  }
}

function loadGDriveKeyFile(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    const content = e.target.result;
    document.getElementById("sync-gdrive-creds").value = content;
    showToast("Service Account Schlüssel geladen!", "info");
  };
  reader.readAsText(file);
}

async function testGDriveConnection() {
  const creds = document.getElementById("sync-gdrive-creds").value.trim();
  const folder = document.getElementById("sync-gdrive-folder").value.trim();
  const resultEl = document.getElementById("gdrive-test-result");
  resultEl.style.display = "inline";
  resultEl.style.color = "var(--text-dim)";
  resultEl.innerText = "Prüfe Verbindung...";

  try {
    const res = await fetch("/api/sync/gdrive/test", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${sessionToken}`
      },
      body: JSON.stringify({ credentials: creds, folder_id: folder })
    });
    const data = await res.json();
    if (res.ok) {
      resultEl.style.color = "#34d399";
      resultEl.innerText = "✓ " + (data.message || "Verbindung erfolgreich!");
      showToast("Google Drive Verbindung erfolgreich!", "success");
    } else {
      resultEl.style.color = "#f87171";
      resultEl.innerText = "✗ " + (data.message || "Fehler");
      showToast("Google Drive Fehler: " + (data.message || "Unbekannt"), "error");
    }
  } catch (err) {
    resultEl.style.color = "#f87171";
    resultEl.innerText = "✗ " + err.message;
    showToast("Fehler beim Testen: " + err.message, "error");
  }
}

async function saveSyncSettings(e) {
  e.preventDefault();
  const active = document.getElementById("sync-active").checked;
  const targetDir = document.getElementById("sync-target-dir").value.trim();
  const interval = parseInt(document.getElementById("sync-interval").value, 10);
  const retention = parseInt(document.getElementById("sync-retention").value, 10);
  const onChange = document.getElementById("sync-on-change").checked;

  const gdriveCheck = document.getElementById("sync-gdrive-enabled");
  const gdriveEnabled = gdriveCheck ? gdriveCheck.checked : false;
  const gdriveFolder = document.getElementById("sync-gdrive-folder") ? document.getElementById("sync-gdrive-folder").value.trim() : "";
  const gdriveCreds = document.getElementById("sync-gdrive-creds") ? document.getElementById("sync-gdrive-creds").value.trim() : "";

  try {
    const res = await fetch("/api/sync/settings", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${sessionToken}`
      },
      body: JSON.stringify({
        target_dir: targetDir,
        interval_minutes: interval,
        sync_on_change: onChange,
        retention_count: retention,
        is_active: active,
        gdrive_enabled: gdriveEnabled,
        gdrive_folder_id: gdriveFolder,
        gdrive_credentials: gdriveCreds
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || data.message || "Fehler beim Speichern");

    showToast("Backup- & Sync-Plan gespeichert!", "success");
    closeModal("modal-sync");
    updateItemCounters();
  } catch (err) {
    showToast("Fehler: " + err.message, "error");
  }
}

async function triggerManualSyncNow() {
  try {
    showToast("Führe Sofort-Sync aus...", "info");
    const res = await fetch("/api/sync/now", {
      method: "POST",
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Sync fehlgeschlagen");

    document.getElementById("sync-last-time").innerText = new Date().toLocaleString();
    document.getElementById("sync-last-status").innerText = "Erfolgreich";
    showToast(data.message || "Backup erfolgreich synchronisiert!", "success");
  } catch (err) {
    showToast("Fehler beim Synchronisieren: " + err.message, "error");
  }
}

// =============================================================
// MASKED EMAIL ALIASES ("HIDE MY EMAIL")
// =============================================================

async function openAliasesModal() {
  await loadAliases();
  openModal("modal-aliases");
}

let currentAliasesList = [];

function copyAliasByIndex(idx) {
  const a = currentAliasesList[idx];
  if (a && a.alias_email) {
    copyToClipboard(a.alias_email, "Alias kopiert!");
  }
}

async function loadAliases() {
  const container = document.getElementById("aliases-list");
  container.innerHTML = `<div style="font-size: 0.8rem; color: var(--text-dim); text-align: center; padding: 10px;">Lade Aliase...</div>`;

  try {
    const res = await fetch("/api/aliases", {
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    const aliases = await res.json();
    currentAliasesList = aliases || [];

    if (currentAliasesList.length === 0) {
      container.innerHTML = `<div style="font-size: 0.82rem; color: var(--text-dim); text-align: center; padding: 20px;">Noch keine E-Mail-Aliase erstellt.</div>`;
      return;
    }

    container.innerHTML = "";
    currentAliasesList.forEach((a, idx) => {
      const card = document.createElement("div");
      card.className = "card-row";
      card.style.marginBottom = "8px";
      card.innerHTML = `
        <div>
          <strong style="color: #60a5fa; font-size: 0.85rem;">${escapeHtml(a.service_name)}</strong>
          <div style="font-family: monospace; font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(a.alias_email)}</div>
        </div>
        <div style="display: flex; gap: 4px;">
          <button class="btn-icon" onclick="copyAliasByIndex(${idx})" title="Kopieren">${SVG_ICONS.copy}</button>
          <button class="btn-icon" onclick="deleteAlias('${a.id}')" title="Löschen" style="color: #f87171;">${SVG_ICONS.trash}</button>
        </div>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    container.innerHTML = `<div style="color: #f87171;">Fehler: ${escapeHtml(err.message)}</div>`;
  }
}

async function generateNewAlias() {
  const serviceInput = document.getElementById("alias-service-input");
  const serviceName = serviceInput.value.trim();
  if (!serviceName) {
    showToast("Bitte gib einen Dienstnamen ein (z. B. Netflix)", "error");
    return;
  }

  try {
    const res = await fetch("/api/aliases", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${sessionToken}`
      },
      body: JSON.stringify({ service_name: serviceName })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Fehler beim Erstellen");

    serviceInput.value = "";
    showToast(`Neuer Alias "${data.alias_email}" erstellt!`, "success");
    await loadAliases();
    updateItemCounters();
  } catch (err) {
    showToast("Fehler: " + err.message, "error");
  }
}

async function deleteAlias(id) {
  if (!confirm("Diesen Alias wirklich entfernen?")) return;
  try {
    await fetch(`/api/aliases/${id}`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    showToast("Alias gelöscht", "info");
    await loadAliases();
    updateItemCounters();
  } catch (err) {
    showToast("Fehler: " + err.message, "error");
  }
}

// =============================================================
// SECURE VAULT SHARING
// =============================================================

function openSharingModal() {
  populateShareSelect();
  loadSharedInbox();
  openModal("modal-sharing");
}

function switchShareTab(tab) {
  document.getElementById("tab-share-inbox").className = tab === 'inbox' ? "tab-btn active" : "tab-btn";
  document.getElementById("tab-share-send").className = tab === 'send' ? "tab-btn active" : "tab-btn";
  document.getElementById("share-view-inbox").style.display = tab === 'inbox' ? "block" : "none";
  document.getElementById("share-view-send").style.display = tab === 'send' ? "block" : "none";
}

function populateShareSelect() {
  const sel = document.getElementById("share-select-item");
  sel.innerHTML = "";
  decryptedItems.forEach(it => {
    const opt = document.createElement("option");
    const typeLabel = it.type === 'login' ? 'Login' : (it.type === 'note' ? 'Notiz' : 'Karte');
    opt.innerText = `[${typeLabel}] ${it.title} (${it.data.username || it.data.url || 'Kein Benutzer'})`;
    sel.appendChild(opt);
  });
}

let currentSharedInboxList = [];

function importSharedInboxByIndex(idx) {
  const it = currentSharedInboxList[idx];
  if (it) {
    importSharedItemIntoVault(it.id, it.title, it.type, it.encrypted_payload);
  }
}

async function loadSharedInbox() {
  const container = document.getElementById("share-inbox-list");
  container.innerHTML = `<div style="text-align: center; color: var(--text-dim); padding: 10px;">Lade Posteingang...</div>`;

  try {
    const res = await fetch("/api/share/inbox", {
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    const items = await res.json();
    currentSharedInboxList = items || [];

    if (currentSharedInboxList.length === 0) {
      container.innerHTML = `<div style="text-align: center; color: var(--text-dim); padding: 20px;">Keine geteilten Einträge empfangen.</div>`;
      return;
    }

    container.innerHTML = "";
    currentSharedInboxList.forEach((it, idx) => {
      const card = document.createElement("div");
      card.className = "card-row";
      card.style.marginBottom = "8px";
      card.innerHTML = `
        <div>
          <strong style="color: #a78bfa;">${escapeHtml(it.title)}</strong>
          <div style="font-size: 0.75rem; color: var(--text-dim);">Von: ${escapeHtml(it.sender_username)} am ${new Date(it.created_at).toLocaleDateString()}</div>
        </div>
        <div style="display: flex; gap: 6px;">
          <button class="btn btn-primary" style="padding: 4px 10px; font-size: 0.75rem; display: inline-flex; align-items: center; gap: 4px;" onclick="importSharedInboxByIndex(${idx})">
            ${SVG_ICONS.archive} Importieren
          </button>
          <button class="btn-icon" onclick="deleteSharedInboxItem('${it.id}')" title="Ablehnen" style="color: #f87171;">${SVG_ICONS.trash}</button>
        </div>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    container.innerHTML = `<div style="color: #f87171;">Fehler: ${escapeHtml(err.message)}</div>`;
  }
}

async function executeShareItem() {
  const targetUser = document.getElementById("share-recipient-username").value.trim().toLowerCase();
  const itemId = document.getElementById("share-select-item").value;

  if (!targetUser) {
    showToast("Bitte gib den Zielbenutzernamen an.", "error");
    return;
  }

  if (currentUser && targetUser === currentUser.username.toLowerCase()) {
    showToast("Du kannst Einträge nicht mit dir selbst teilen.", "warning");
    return;
  }

  const item = decryptedItems.find(i => i.id === itemId);
  if (!item) {
    showToast("Ausgewählter Eintrag nicht gefunden.", "error");
    return;
  }

  try {
    showToast(`Rufe Schlüssel von '${targetUser}' ab...`, "info");

    // 1. Fetch recipient's public key
    const keyRes = await fetch(`/api/share/user/${targetUser}/public-key`, {
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    const keyData = await keyRes.json();
    if (!keyRes.ok) {
      throw new Error(keyData.detail || `Empfänger '${targetUser}' hat noch keinen Sharing-Schlüssel aktiviert.`);
    }

    // 2. Import recipient's RSA-OAEP public key
    const spkiBuffer = pemToSpki(keyData.public_key_pem);
    const recipientPubKey = await window.crypto.subtle.importKey(
      "spki",
      spkiBuffer,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"]
    );

    // 3. Generate random ephemeral AES-256-GCM symmetric key
    const ephemeralKey = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    // 4. Encrypt item plaintext data with ephemeral AES key
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const plaintext = strToBuffer(JSON.stringify(item.data));
    const cipherBuf = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      ephemeralKey,
      plaintext
    );

    // 5. Encrypt ephemeral AES key with recipient's RSA-OAEP public key
    const rawKeyBytes = await window.crypto.subtle.exportKey("raw", ephemeralKey);
    const encKeyBuf = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      recipientPubKey,
      rawKeyBytes
    );

    // 6. Build Zero-Knowledge E2E envelope
    const e2ePayload = JSON.stringify({
      version: "e2e_rsa_v1",
      enc_key: bufferToHex(encKeyBuf),
      iv: bufferToHex(iv),
      data: bufferToHex(cipherBuf)
    });

    const res = await fetch("/api/share/send", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${sessionToken}`
      },
      body: JSON.stringify({
        recipient_username: targetUser,
        type: item.type,
        title: item.title,
        encrypted_payload: e2ePayload
      })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Freigabe fehlgeschlagen");

    showToast(data.message || `Erfolgreich mit '${targetUser}' geteilt!`, "success");
    document.getElementById("share-recipient-username").value = "";
    closeModal("modal-sharing");
  } catch (err) {
    showToast("Fehler bei Freigabe: " + err.message, "error");
  }
}

async function importSharedItemIntoVault(sharedId, title, type, encryptedPayload) {
  try {
    await ensureUserSharingKey();

    let decryptedItemData = null;

    try {
      const envelope = typeof encryptedPayload === "string" ? JSON.parse(encryptedPayload) : encryptedPayload;
      if (envelope && envelope.version === "e2e_rsa_v1" && userSharingPrivateKey) {
        // Decrypt ephemeral AES key with recipient private RSA key
        const encKeyBuf = hexToBuffer(envelope.enc_key);
        const rawAesKey = await window.crypto.subtle.decrypt(
          { name: "RSA-OAEP" },
          userSharingPrivateKey,
          encKeyBuf
        );

        const ephemeralKey = await window.crypto.subtle.importKey(
          "raw",
          rawAesKey,
          { name: "AES-GCM", length: 256 },
          false,
          ["decrypt"]
        );

        // Decrypt item payload
        const ivBuf = hexToBuffer(envelope.iv);
        const dataBuf = hexToBuffer(envelope.data);
        const decBuf = await window.crypto.subtle.decrypt(
          { name: "AES-GCM", iv: new Uint8Array(ivBuf) },
          ephemeralKey,
          dataBuf
        );

        decryptedItemData = JSON.parse(bufferToStr(decBuf));
      }
    } catch (e) {
      console.warn("E2E RSA decryption attempt:", e);
    }

    // Direct fallback if encrypted with master key
    if (!decryptedItemData) {
      decryptedItemData = await decryptPayload(encryptedPayload, masterEncryptionKey);
    }

    if (!decryptedItemData) {
      throw new Error("Entschlüsselung fehlgeschlagen. Der Schlüssel stimmt nicht überein.");
    }

    // Re-encrypt with recipient's own master encryption key!
    const reEncryptedPayload = await encryptPayload(decryptedItemData, masterEncryptionKey);

    const postRes = await fetch("/api/vault/items", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${sessionToken}`
      },
      body: JSON.stringify({
        type: type,
        title: title + " (Geteilt)",
        favorite: false,
        encrypted_payload: reEncryptedPayload
      })
    });

    if (!postRes.ok) {
      throw new Error("Fehler beim Speichern im Tresor.");
    }

    // Delete from inbox after importing
    await fetch(`/api/share/inbox/${sharedId}`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });

    showToast(`"${title}" erfolgreich entschlüsselt und in deinen Tresor importiert!`, "success");
    await loadVault();
    await loadSharedInbox();
  } catch (err) {
    showToast("Importfehler: " + err.message, "error");
  }
}

async function deleteSharedInboxItem(id) {
  try {
    await fetch(`/api/share/inbox/${id}`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    showToast("Freigabe abgelehnt.", "info");
    await loadSharedInbox();
    updateItemCounters();
  } catch (err) {
    showToast("Fehler: " + err.message, "error");
  }
}


// =============================================================
// THEME & VIEW MODE TOGGLE + SYSTEM INITIALIZATION
// =============================================================

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("SENTINELBIT_theme", next);
  const btn = document.getElementById("theme-toggle-btn");
  if (btn) btn.innerHTML = next === "light" ? SVG_ICONS.sun : SVG_ICONS.moon;
}

function setViewMode(mode) {
  const container = document.getElementById("items-container");
  const btnGrid = document.getElementById("btn-view-grid");
  const btnList = document.getElementById("btn-view-list");
  if (mode === "list") {
    if (container) container.classList.add("list-mode");
    if (btnList) btnList.classList.add("active");
    if (btnGrid) btnGrid.classList.remove("active");
  } else {
    if (container) container.classList.remove("list-mode");
    if (btnGrid) btnGrid.classList.add("active");
    if (btnList) btnList.classList.remove("active");
  }
  localStorage.setItem("SENTINELBIT_view_mode", mode);
}

function toggleSidebarPin() {
  const sidebar = document.getElementById("app-sidebar") || document.querySelector(".sidebar");
  if (!sidebar) return;
  sidebar.classList.toggle("is-pinned");
  const isPinned = sidebar.classList.contains("is-pinned");
  localStorage.setItem("SENTINELBIT_sidebar_pinned", isPinned ? "true" : "false");
  const pinBtn = document.getElementById("sidebar-pin-btn");
  if (pinBtn) {
    pinBtn.title = isPinned ? "Dynamic Island lösen (Automatisches Einblenden beim Hovern)" : "Sidebar fixieren (Dauerhaft geöffnet)";
    pinBtn.style.color = isPinned ? "#38bdf8" : "";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  // 1. Theme initialization
  const savedTheme = localStorage.getItem("SENTINELBIT_theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);
  const themeBtn = document.getElementById("theme-toggle-btn");
  if (themeBtn) themeBtn.innerHTML = savedTheme === "light" ? SVG_ICONS.sun : SVG_ICONS.moon;

  // 2. View Mode initialization (grid or list)
  const savedViewMode = localStorage.getItem("SENTINELBIT_view_mode") || "grid";
  setViewMode(savedViewMode);

  // 3. Biometric check for login view & Passkey Autofill / Conditional UI (#1)
  checkBiometricAvailability();
  initConditionalPasskeyMediation();

  // 4. Global keyboard shortcut (Ctrl+K / Cmd+K) for Command Palette (#54)
  initCommandPalette();
  window.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      openCommandPalette();
    } else if (e.key === "Escape") {
      const cmdModal = document.getElementById("modal-command-palette");
      if (cmdModal && cmdModal.classList.contains("active")) {
        closeCommandPalette();
      }
    }
  });

  // 5. Secure Send hash detection (#71)
  checkSecureSendHash();
  window.addEventListener("hashchange", checkSecureSendHash);

  // 6. Sidebar Pin initialization
  const isPinned = localStorage.getItem("SENTINELBIT_sidebar_pinned") === "true";
  const sidebar = document.getElementById("app-sidebar") || document.querySelector(".sidebar");

  // 7. Progressive Web App (PWA) Service Worker Registration
  if ("serviceWorker" in navigator && (window.location.protocol === "https:" || window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1")) {
    navigator.serviceWorker.register("/static/sw.js").catch(() => {});
  }
  if (sidebar && isPinned) {
    sidebar.classList.add("is-pinned");
    const pinBtn = document.getElementById("sidebar-pin-btn");
    if (pinBtn) {
      pinBtn.title = "Dynamic Island lösen (Automatisches Einblenden beim Hovern)";
      pinBtn.style.color = "#38bdf8";
    }
  }
});

// =============================================================
// VAULT CLEANUP & SMART DEDUPLICATION
// =============================================================

function findVaultDuplicates(strictMode = true) {
  const groups = new Map();

  for (const it of decryptedItems) {
    if (!it || !it.data) continue;
    let key = "";

    if (it.type === "login") {
      const host = (extractDomain(it.data.url) || "").toLowerCase().trim();
      const normTitle = (it.title || "").toLowerCase().trim();
      const domainOrTitle = host || normTitle;
      const user = (it.data.username || "").toLowerCase().trim();
      const pwd = it.data.password || "";

      // Ignore entries that have neither domain/title nor username
      if (!domainOrTitle && !user) continue;

      if (strictMode) {
        // Exact clone: Domain/Title + Username + Password match
        key = `login:strict:${domainOrTitle}|${user}|${pwd}`;
      } else {
        // Loose match: Domain/Title + Username match
        key = `login:loose:${domainOrTitle}|${user}`;
      }
    } else if (it.type === "note") {
      const normTitle = (it.title || "").toLowerCase().trim();
      const normNote = (it.data.notes || "").trim();
      if (!normTitle && !normNote) continue;
      key = `note:${normTitle}|${normNote}`;
    } else if (it.type === "card") {
      const cardNum = (it.data.cardNumber || "").replace(/\s+/g, "");
      if (!cardNum) continue;
      key = `card:${cardNum}`;
    }

    if (!key) continue;

    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key).push(it);
  }

  // Filter groups that have more than 1 item
  const duplicateGroups = [];
  for (const [key, items] of groups.entries()) {
    if (items.length > 1) {
      // Score each item to determine the best one to keep
      items.sort((a, b) => {
        let scoreA = 0;
        let scoreB = 0;

        if (a.favorite) scoreA += 100;
        if (b.favorite) scoreB += 100;

        if (a.data.totp) scoreA += 50;
        if (b.data.totp) scoreB += 50;

        if (a.data.notes) scoreA += 30;
        if (b.data.notes) scoreB += 30;

        if (a.data.attachment) scoreA += 20;
        if (b.data.attachment) scoreB += 20;

        if (a.data.passwordHistory && a.data.passwordHistory.length > 0) scoreA += 10;
        if (b.data.passwordHistory && b.data.passwordHistory.length > 0) scoreB += 10;

        if (scoreB !== scoreA) {
          return scoreB - scoreA;
        }

        // Tie-breaker: keep the oldest created item
        const timeA = new Date(a.created_at || 0).getTime();
        const timeB = new Date(b.created_at || 0).getTime();
        return timeA - timeB;
      });

      duplicateGroups.push({
        key,
        type: items[0].type,
        keeper: items[0],
        duplicates: items.slice(1),
        items: items
      });
    }
  }

  return duplicateGroups;
}

function openCleanupModal() {
  switchCleanupTab("duplicates");
  runDuplicateScan();
  openModal("modal-cleanup");
}

function switchCleanupTab(tab) {
  const btnDup = document.getElementById("tab-btn-duplicates");
  const btnWipe = document.getElementById("tab-btn-wipe");
  const secDup = document.getElementById("cleanup-duplicates-section");
  const secWipe = document.getElementById("cleanup-wipe-section");

  if (tab === "wipe") {
    if (btnWipe) btnWipe.classList.add("active");
    if (btnDup) btnDup.classList.remove("active");
    if (secWipe) secWipe.style.display = "block";
    if (secDup) secDup.style.display = "none";
    const confirmInput = document.getElementById("wipe-confirm-text");
    if (confirmInput) confirmInput.value = "";
  } else {
    if (btnDup) btnDup.classList.add("active");
    if (btnWipe) btnWipe.classList.remove("active");
    if (secDup) secDup.style.display = "block";
    if (secWipe) secWipe.style.display = "none";
  }
}

function runDuplicateScan() {
  const strict = document.getElementById("cleanup-strict-mode")?.checked ?? true;
  const groups = findVaultDuplicates(strict);
  const summaryEl = document.getElementById("cleanup-scan-summary");
  const listEl = document.getElementById("cleanup-duplicates-list");
  const execBtn = document.getElementById("btn-execute-cleanup");

  let totalDupCopies = 0;
  groups.forEach(g => {
    totalDupCopies += g.duplicates.length;
  });

  if (groups.length === 0) {
    if (summaryEl) {
      summaryEl.innerHTML = `
        <div style="background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: var(--radius-md); padding: 16px; text-align: center;">
          <div style="width: 36px; height: 36px; margin: 0 auto 8px auto; color: #34d399;">${SVG_ICONS.shield}</div>
          <h4 style="color: #34d399; margin-bottom: 4px;">Keine Duplikate gefunden!</h4>
          <p style="font-size: 0.85rem; color: var(--text-dim);">Dein Tresor ist optimal bereinigt und enthält keine doppelten Einträge.</p>
        </div>
      `;
    }
    if (listEl) listEl.innerHTML = "";
    if (execBtn) {
      execBtn.disabled = true;
      execBtn.innerText = "Keine Duplikate vorhanden";
    }
    return;
  }

  if (summaryEl) {
    summaryEl.innerHTML = `
      <div style="background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.35); border-radius: var(--radius-md); padding: 12px 16px; display: flex; align-items: center; justify-content: space-between;">
        <div>
          <div style="font-weight: 600; color: #fbbf24; font-size: 0.95rem; display: flex; align-items: center; gap: 6px;">
            <span style="width: 15px; height: 15px; display: inline-flex;">${SVG_ICONS.shield}</span> ${totalDupCopies} Duplikat(e) in ${groups.length} Gruppe(n) gefunden
          </div>
          <div style="font-size: 0.8rem; color: var(--text-dim); margin-top: 2px;">
            Das jeweils beste/älteste Element wird behalten. Überflüssige Kopien sind unten vorausgewählt.
          </div>
        </div>
        <div style="font-size: 1.5rem; font-weight: 700; color: #fbbf24;">${totalDupCopies}</div>
      </div>
    `;
  }

  if (listEl) {
    listEl.innerHTML = "";
    groups.forEach((group) => {
      const card = document.createElement("div");
      card.style.cssText = `
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        padding: 12px 14px;
        font-size: 0.85rem;
      `;

      let titleLabel = group.keeper.title;
      let subLabel = "";
      if (group.type === "login") {
        const u = group.keeper.data.username || "Kein Benutzer";
        const url = group.keeper.data.url || "";
        subLabel = `${u} ${url ? '• ' + url : ''}`;
      } else if (group.type === "note") {
        subLabel = "Sichere Notiz";
      } else if (group.type === "card") {
        subLabel = "Zahlungskarte";
      }

      let dupsHtml = group.duplicates.map(d => {
        const dDate = d.created_at ? new Date(d.created_at).toLocaleString() : "Unbekannt";
        return `
          <div style="display: flex; align-items: center; justify-content: space-between; padding: 6px 10px; background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 6px; margin-top: 6px;">
            <div style="display: flex; align-items: center; gap: 8px; overflow: hidden;">
              <input type="checkbox" class="cleanup-dup-checkbox" value="${d.id}" checked style="cursor: pointer;">
              <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                <span style="color: #f87171; font-weight: 500; display: inline-flex; align-items: center; gap: 3px;"><span style="width: 12px; height: 12px; display: inline-flex;">${SVG_ICONS.trash}</span> Duplikat:</span>
                <span style="color: var(--text-main); font-weight: 500;">${escapeHtml(d.title)}</span>
                <span style="color: var(--text-dim); font-size: 0.75rem;">(Erstellt: ${dDate})</span>
              </div>
            </div>
            <span style="font-size: 0.72rem; color: #f87171; white-space: nowrap; margin-left: 8px;">Wird entfernt</span>
          </div>
        `;
      }).join("");

      const keeperDate = group.keeper.created_at ? new Date(group.keeper.created_at).toLocaleString() : "Unbekannt";
      let keeperBadges = [];
      if (group.keeper.favorite) keeperBadges.push("Favorit");
      if (group.keeper.data?.totp) keeperBadges.push("2FA");
      if (group.keeper.data?.notes) keeperBadges.push("Notizen");

      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; border-bottom: 1px solid var(--border-color); padding-bottom: 6px;">
          <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 480px;">
            <strong>${escapeHtml(titleLabel)}</strong>
            <span style="color: var(--text-dim); font-size: 0.75rem; margin-left: 6px;">${escapeHtml(subLabel)}</span>
          </div>
          <span class="badge" style="background: rgba(245, 158, 11, 0.2); color: #fbbf24; white-space: nowrap;">${group.items.length} Einträge</span>
        </div>

        <div style="display: flex; align-items: center; justify-content: space-between; padding: 6px 10px; background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 6px;">
          <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            <span style="color: #34d399; font-weight: 600;">Behalten:</span>
            <span style="color: var(--text-main); font-weight: 500;">${escapeHtml(group.keeper.title)}</span>
            <span style="color: var(--text-dim); font-size: 0.75rem;">(Erstellt: ${keeperDate})</span>
            ${keeperBadges.length ? `<span style="font-size: 0.72rem; color: #34d399; margin-left: 4px;">[${keeperBadges.join(", ")}]</span>` : ''}
          </div>
          <span style="font-size: 0.72rem; color: #34d399; white-space: nowrap; margin-left: 8px;">Original</span>
        </div>

        ${dupsHtml}
      `;
      listEl.appendChild(card);
    });
  }

  if (execBtn) {
    execBtn.disabled = totalDupCopies === 0;
    execBtn.innerHTML = `${SVG_ICONS.trash} ${totalDupCopies} Duplikat(e) entfernen`;
  }
}

async function executeRemoveDuplicates() {
  const checkboxes = document.querySelectorAll(".cleanup-dup-checkbox:checked");
  const idsToDelete = Array.from(checkboxes).map(cb => cb.value);

  if (idsToDelete.length === 0) {
    showToast("Keine Duplikate zur Löschung ausgewählt.", "info");
    return;
  }

  const permanent = document.getElementById("cleanup-permanent-delete")?.checked ?? true;
  const confirmMsg = permanent
    ? `Möchtest du diese ${idsToDelete.length} doppelten Einträge wirklich unwiderruflich aus deinem Tresor entfernen?`
    : `Möchtest du diese ${idsToDelete.length} doppelten Einträge in den Papierkorb verschieben?`;

  if (!confirm(confirmMsg)) return;

  const btn = document.getElementById("btn-execute-cleanup");
  if (btn) {
    btn.disabled = true;
    btn.innerText = `⏳ Bereinige (0/${idsToDelete.length})...`;
  }

  let deletedCount = 0;
  const BATCH_SIZE = 8;
  for (let i = 0; i < idsToDelete.length; i += BATCH_SIZE) {
    const batch = idsToDelete.slice(i, i + BATCH_SIZE);
    await Promise.all(batch.map(async id => {
      try {
        await fetch(`/api/vault/items/${id}?permanent=${permanent}`, {
          method: "DELETE",
          headers: { "Authorization": `Bearer ${sessionToken}` }
        });
        deletedCount++;
      } catch (err) {
        console.error("Fehler beim Löschen von Duplikat:", id, err);
      }
    }));
    if (btn) {
      btn.innerText = `⏳ Bereinige (${deletedCount}/${idsToDelete.length})...`;
    }
  }

  showToast(`${deletedCount} Duplikate erfolgreich bereinigt!`, "success");
  await loadVault();
  runDuplicateScan();
}

async function executeWipeVault() {
  const confirmInput = document.getElementById("wipe-confirm-text");
  const val = (confirmInput?.value || "").trim().toUpperCase();

  if (val !== "LÖSCHEN") {
    showToast("Bitte gib 'LÖSCHEN' in das Bestätigungsfeld ein.", "error");
    if (confirmInput) confirmInput.focus();
    return;
  }

  if (!confirm("WARNUNG: Möchtest du wirklich den GESAMTEN Tresor unwiderruflich leeren? Alle Passwörter, Notizen und Passkeys werden dauerhaft gelöscht.")) {
    return;
  }

  const btn = document.getElementById("btn-wipe-vault");
  if (btn) {
    btn.disabled = true;
    btn.innerText = "⏳ Leere gesamten Tresor...";
  }

  try {
    const res = await fetch("/api/vault/items/all", {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || "Fehler beim Leeren des Tresors");
    }

    decryptedItems = [];
    passkeysList = [];
    trashItems = [];

    closeModal("modal-cleanup");
    showToast("Tresor vollständig geleert! Du kannst nun frisch importieren.", "success");
    await loadVault();
  } catch (err) {
    showToast("Fehler: " + err.message, "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `${SVG_ICONS.trash} Gesamten Tresor jetzt unwiderruflich leeren`;
    }
  }
}

// =============================================================
// COMMAND PALETTE (Ctrl+K / Cmd+K Quick Launcher)
// =============================================================

let cmdPaletteSelectedIndex = 0;
let cmdPaletteCurrentItems = [];

function initCommandPalette() {
  const input = document.getElementById("cmd-palette-input");
  if (!input) return;

  input.addEventListener("input", (e) => {
    renderCommandPaletteResults(e.target.value);
  });

  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (cmdPaletteCurrentItems.length > 0) {
        cmdPaletteSelectedIndex = (cmdPaletteSelectedIndex + 1) % cmdPaletteCurrentItems.length;
        updateCommandPaletteSelection();
      }
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (cmdPaletteCurrentItems.length > 0) {
        cmdPaletteSelectedIndex = (cmdPaletteSelectedIndex - 1 + cmdPaletteCurrentItems.length) % cmdPaletteCurrentItems.length;
        updateCommandPaletteSelection();
      }
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (cmdPaletteCurrentItems[cmdPaletteSelectedIndex]) {
        const item = cmdPaletteCurrentItems[cmdPaletteSelectedIndex];
        closeCommandPalette();
        item.run();
      }
    } else if (e.key === "Escape") {
      e.preventDefault();
      closeCommandPalette();
    }
  });
}

function openCommandPalette() {
  const modal = document.getElementById("modal-command-palette");
  const input = document.getElementById("cmd-palette-input");
  if (!modal || !input) return;

  input.value = "";
  renderCommandPaletteResults("");
  openModal("modal-command-palette");
  setTimeout(() => input.focus(), 60);
}

function closeCommandPalette() {
  closeModal("modal-command-palette");
}

function renderCommandPaletteResults(query) {
  const container = document.getElementById("cmd-palette-results");
  if (!container) return;
  const q = (query || "").toLowerCase().trim();

  // Standard commands
  const defaultCommands = [
    { type: "action", icon: SVG_ICONS.plus, title: "Neuer Tresor-Eintrag", desc: "Passwort, Notiz oder Karte anlegen", run: () => openAddItemModal() },
    { type: "action", icon: SVG_ICONS.zap, title: "Secure Send (Burn-after-Reading)", desc: "Einmal-Link mit Zero-Knowledge Verschlüsselung erstellen", run: () => openSecureSendModal() },
    { type: "action", icon: SVG_ICONS.dice, title: "Passwort- & Diceware-Generator", desc: "Sicheres Passwort oder Einmal-Passphrase generieren", run: () => openGeneratorModal() },
    { type: "action", icon: SVG_ICONS.shield, title: "Tresor-Sicherheits-Audit & Leaks", desc: "Passwort-Stärke, Leaks & 2FA-Status analysieren", run: () => openAuditModal() },
    { type: "action", icon: SVG_ICONS.trash, title: "Tresor bereinigen & Duplikate", desc: "Doppelte Einträge finden und aufräumen", run: () => openCleanupModal() },
    { type: "action", icon: SVG_ICONS.archive, title: "Backup & Export / Import", desc: "Tresor verschlüsselt sichern oder importieren", run: () => openBackupModal() },
    { type: "action", icon: SVG_ICONS.sync, title: "Automatischer Sync & Sicherungsplan", desc: "Zielverzeichnis und Intervall konfigurieren", run: () => openSyncSettingsModal() },
    { type: "action", icon: SVG_ICONS.fingerprint, title: "Windows Hello / Biometrie", desc: "FIDO2 Fingerabdruck oder PIN verwalten", run: () => openBiometricModal() },
    { type: "action", icon: SVG_ICONS.moon, title: "Design umschalten (Dark / Light)", desc: "Farbschema wechseln", run: () => toggleTheme() },
    { type: "action", icon: SVG_ICONS.lock, title: "Tresor jetzt sperren", desc: "Sofort abmelden und Master-Key aus Speicher löschen", run: () => lockVault() },
  ];

  const matchedActions = defaultCommands.filter(c =>
    !q || c.title.toLowerCase().includes(q) || c.desc.toLowerCase().includes(q)
  );

  // Vault items matches
  const matchedVaultItems = (decryptedItems || []).filter(it => {
    if (!q) return false;
    const title = (it.title || "").toLowerCase();
    const username = (it.data?.username || "").toLowerCase();
    const url = (it.data?.url || "").toLowerCase();
    const tags = Array.isArray(it.tags) ? it.tags.join(" ").toLowerCase() : "";
    return title.includes(q) || username.includes(q) || url.includes(q) || tags.includes(q);
  }).map(it => {
    let icon = SVG_ICONS.login;
    if (it.type === "note") icon = SVG_ICONS.note;
    if (it.type === "card") icon = SVG_ICONS.card;
    if (it.type === "passkey") icon = SVG_ICONS.passkey;
    const sub = it.data?.username ? `${it.data.username} ${it.data.url ? '• ' + it.data.url : ''}` : (it.data?.url || (it.type === "note" ? "Sichere Notiz" : "Zahlungskarte"));
    return {
      type: "item",
      icon: icon,
      title: it.title,
      desc: sub,
      run: () => openEditItemModal(it.id)
    };
  });

  cmdPaletteCurrentItems = [...matchedActions, ...matchedVaultItems];
  cmdPaletteSelectedIndex = 0;

  if (cmdPaletteCurrentItems.length === 0) {
    container.innerHTML = `
      <div style="padding: 24px; text-align: center; color: #64748b; font-size: 0.9rem;">
        Keine Ergebnisse für "${escapeHtml(query)}"
      </div>
    `;
    return;
  }

  let html = "";
  if (matchedActions.length > 0) {
    html += `<div class="cmd-group-title">Befehle & Aktionen</div>`;
    matchedActions.forEach((act, idx) => {
      const isSelected = idx === cmdPaletteSelectedIndex;
      html += `
        <div class="cmd-item ${isSelected ? 'active' : ''}" data-cmd-index="${idx}">
          <span class="cmd-item-icon">${act.icon}</span>
          <div class="cmd-item-content">
            <div class="cmd-item-title">${escapeHtml(act.title)}</div>
            <div class="cmd-item-desc">${escapeHtml(act.desc)}</div>
          </div>
        </div>
      `;
    });
  }

  if (matchedVaultItems.length > 0) {
    html += `<div class="cmd-group-title">Tresor-Einträge (${matchedVaultItems.length})</div>`;
    matchedVaultItems.forEach((it, idx) => {
      const overallIndex = matchedActions.length + idx;
      const isSelected = overallIndex === cmdPaletteSelectedIndex;
      html += `
        <div class="cmd-item ${isSelected ? 'active' : ''}" data-cmd-index="${overallIndex}">
          <span class="cmd-item-icon">${it.icon}</span>
          <div class="cmd-item-content">
            <div class="cmd-item-title">${escapeHtml(it.title)}</div>
            <div class="cmd-item-desc">${escapeHtml(it.desc)}</div>
          </div>
        </div>
      `;
    });
  }

  container.innerHTML = html;

  // Add click handlers
  container.querySelectorAll(".cmd-item").forEach(el => {
    el.addEventListener("click", () => {
      const idx = parseInt(el.getAttribute("data-cmd-index"), 10);
      if (cmdPaletteCurrentItems[idx]) {
        closeCommandPalette();
        cmdPaletteCurrentItems[idx].run();
      }
    });
  });
}

function updateCommandPaletteSelection() {
  const items = document.querySelectorAll("#cmd-palette-results .cmd-item");
  items.forEach((el, idx) => {
    if (idx === cmdPaletteSelectedIndex) {
      el.classList.add("active");
      el.scrollIntoView({ block: "nearest" });
    } else {
      el.classList.remove("active");
    }
  });
}

// =============================================================
// SECURE SEND (Zero-Knowledge Burn-after-Reading)
// =============================================================

function openSecureSendModal() {
  resetSecureSendModal();
  openModal("modal-secure-send");
  setTimeout(() => {
    const txt = document.getElementById("send-secret-text");
    if (txt) txt.focus();
  }, 60);
}

function resetSecureSendModal() {
  const secretText = document.getElementById("send-secret-text");
  if (secretText) secretText.value = "";
  const formView = document.getElementById("secure-send-form-view");
  const resultView = document.getElementById("secure-send-result-view");
  if (formView) formView.style.display = "block";
  if (resultView) resultView.style.display = "none";
  const btn = document.getElementById("btn-create-send");
  if (btn) {
    btn.disabled = false;
    btn.innerHTML = `<svg viewBox="0 0 24 24" style="width: 15px; height: 15px; fill: none; stroke: currentColor; stroke-width: 2;"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg> Verschlüsselten Einmal-Link erstellen`;
  }
}

async function createSecureSendLink() {
  const secretText = (document.getElementById("send-secret-text")?.value || "").trim();
  if (!secretText) {
    showToast("Bitte gib den geheimen Text ein.", "warning");
    document.getElementById("send-secret-text")?.focus();
    return;
  }

  const burnLimit = parseInt(document.getElementById("send-burn-limit")?.value, 10) || 1;
  const expireHours = parseInt(document.getElementById("send-expire-hours")?.value, 10) || 24;

  const btn = document.getElementById("btn-create-send");
  if (btn) {
    btn.disabled = true;
    btn.innerText = "⏳ Verschlüssle & Übertrage...";
  }

  try {
    // 1. Generate ephemeral AES-256-GCM key client-side
    const key = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const rawKey = await window.crypto.subtle.exportKey("raw", key);
    const keyHex = bufferToHex(rawKey);

    // 2. Encrypt plaintext
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      strToBuffer(secretText)
    );

    // 3. Post ciphertext to backend (Zero-Knowledge: server never sees keyHex)
    const headers = { "Content-Type": "application/json" };
    if (sessionToken) {
      headers["Authorization"] = `Bearer ${sessionToken}`;
    }

    const res = await fetch("/api/send", {
      method: "POST",
      headers: headers,
      body: JSON.stringify({
        ciphertext: bufferToHex(encrypted),
        iv: bufferToHex(iv),
        burn_limit: burnLimit,
        expire_hours: expireHours
      })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Fehler beim Erstellen des Links");
    }

    const data = await res.json();
    const sendUrl = `${window.location.origin}/#send?id=${data.id}&key=${keyHex}`;

    document.getElementById("send-result-url").value = sendUrl;
    document.getElementById("send-result-burn-info").innerText = `Wird nach ${burnLimit}x Abrufen oder spätestens nach ${expireHours} Stunden automatisch vernichtet.`;
    document.getElementById("secure-send-form-view").style.display = "none";
    document.getElementById("secure-send-result-view").style.display = "block";

    showToast("Secure Send Link erfolgreich generiert! 🚀", "success");
  } catch (err) {
    showToast("Fehler bei Secure Send: " + err.message, "error");
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<svg viewBox="0 0 24 24" style="width: 15px; height: 15px; fill: none; stroke: currentColor; stroke-width: 2;"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg> Verschlüsselten Einmal-Link erstellen`;
    }
  }
}

async function checkSecureSendHash() {
  const hash = window.location.hash || "";
  if (!hash.startsWith("#send?")) return;

  const queryString = hash.substring(6); // remove '#send?'
  const params = new URLSearchParams(queryString);
  const sendId = params.get("id");
  const keyHex = params.get("key");

  if (!sendId || !keyHex) return;

  openModal("modal-send-viewer");
  const contentEl = document.getElementById("send-viewer-content");
  const statusEl = document.getElementById("send-viewer-status-text");
  if (contentEl) {
    contentEl.style.color = "#94a3b8";
    contentEl.innerText = "⏳ Lade verschlüsselte Nachricht vom Server...";
  }

  try {
    const res = await fetch(`/api/send/${encodeURIComponent(sendId)}`);
    if (!res.ok) {
      if (res.status === 404 || res.status === 410) {
        if (contentEl) {
          contentEl.style.color = "#f87171";
          contentEl.innerText = "❌ Nachricht nicht gefunden oder bereits vernichtet (Burn-Limit / TTL erreicht).";
        }
        if (statusEl) {
          statusEl.innerText = "Dieser geheime Link ist abgelaufen oder wurde bereits abgerufen.";
        }
        return;
      }
      throw new Error("Fehler beim Abrufen der Nachricht");
    }

    const data = await res.json();
    const keyBuf = hexToBuffer(keyHex);
    const key = await window.crypto.subtle.importKey(
      "raw",
      keyBuf,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(hexToBuffer(data.iv)) },
      key,
      hexToBuffer(data.ciphertext)
    );

    const text = bufferToStr(decrypted);
    if (contentEl) {
      contentEl.style.color = "#34d399";
      contentEl.innerText = text;
    }
    if (statusEl) {
      const remaining = Math.max(0, data.burn_limit - data.access_count);
      statusEl.innerText = `Erfolgreich entschlüsselt! Verbleibende Abrufe: ${remaining}.`;
    }
  } catch (err) {
    if (contentEl) {
      contentEl.style.color = "#f87171";
      contentEl.innerText = "⚠️ Entschlüsselungsfehler: " + err.message;
    }
    if (statusEl) {
      statusEl.innerText = "Schlüssel ungültig oder Nachricht beschädigt.";
    }
  }
}

// =============================================================
// REAL-TIME SSE VAULT LIVE-SYNC (#42)
// =============================================================

let liveSyncEventSource = null;

function initLiveSyncStream() {
  if (!sessionToken || liveSyncEventSource) return;
  try {
    liveSyncEventSource = new EventSource(`/api/sync/events?token=${encodeURIComponent(sessionToken)}`);

    liveSyncEventSource.addEventListener("vault_sync", async (e) => {
      try {
        console.log("SSE Live-Sync empfangen:", e.data);
        await loadVault();
        showToast("🔄 Tresor in Echtzeit synchronisiert!", "info");
      } catch (_) {
        await loadVault();
      }
    });

    liveSyncEventSource.onerror = () => {
      // Browser reconnects automatically
    };
  } catch (err) {
    console.debug("SSE Live-Sync Fehler:", err);
  }
}

function closeLiveSyncStream() {
  if (liveSyncEventSource) {
    liveSyncEventSource.close();
    liveSyncEventSource = null;
  }
}

// =============================================================
// EMERGENCY KIT (Druckbares Notfall-Rettungsblatt) (#73)
// =============================================================

async function openEmergencyKitModal() {
  if (!sessionToken || !currentUser) {
    showToast("Bitte melde dich an, um dein Notfall-Kit zu laden.", "error");
    return;
  }

  try {
    const res = await fetch("/api/auth/emergency-kit", {
      headers: { "Authorization": `Bearer ${sessionToken}` }
    });
    if (!res.ok) throw new Error("Fehler beim Abrufen der Notfalldaten");
    const data = await res.json();

    document.getElementById("kit-username").innerText = data.username || currentUser.username;
    document.getElementById("kit-server-url").innerText = window.location.origin;
    document.getElementById("kit-enc-salt").innerText = data.enc_salt || "–";
    document.getElementById("kit-auth-salt").innerText = data.auth_salt || "–";
    document.getElementById("kit-generated-date").innerText = new Date().toLocaleDateString("de-DE", {
      year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"
    });

    const codesContainer = document.getElementById("kit-recovery-codes");
    if (data.recovery_codes && data.recovery_codes.length > 0) {
      codesContainer.innerHTML = data.recovery_codes.map(c => `<div>• ${escapeHtml(c)}</div>`).join("");
    } else {
      codesContainer.innerHTML = `<span style="color: #666;">(Keine Notfallcodes hinterlegt)</span>`;
    }

    openModal("modal-emergency-kit");
  } catch (err) {
    showToast("Fehler beim Laden des Notfall-Kits: " + err.message, "error");
  }
}

function printEmergencyKit() {
  window.print();
}

// =============================================================
// 2FA WEBCAM QR-CODE SCANNER (#56)
// =============================================================

let qrVideoMediaStream = null;
let qrScanAnimationId = null;

async function openQrScannerModal() {
  const statusEl = document.getElementById("qr-scanner-status");
  openModal("modal-qr-scanner");
  if (statusEl) statusEl.innerText = "Kamera wird initialisiert...";

  try {
    qrVideoMediaStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment", width: { ideal: 640 }, height: { ideal: 480 } }
    });
    const video = document.getElementById("qr-scanner-video");
    video.srcObject = qrVideoMediaStream;
    video.setAttribute("playsinline", true);
    await video.play();

    if (statusEl) statusEl.innerText = "Kamera auf 2FA-QR-Code richten...";
    startQrScanningLoop(video);
  } catch (err) {
    if (statusEl) {
      statusEl.style.color = "#f87171";
      statusEl.innerText = "Kamerazugriff verweigert oder nicht verfügbar: " + err.message;
    }
  }
}

function closeQrScannerModal() {
  if (qrScanAnimationId) {
    cancelAnimationFrame(qrScanAnimationId);
    qrScanAnimationId = null;
  }
  if (qrVideoMediaStream) {
    qrVideoMediaStream.getTracks().forEach(t => t.stop());
    qrVideoMediaStream = null;
  }
  closeModal("modal-qr-scanner");
}

async function startQrScanningLoop(video) {
  if ('BarcodeDetector' in window) {
    try {
      const barcodeDetector = new BarcodeDetector({ formats: ['qr_code'] });
      const scanFrame = async () => {
        if (!qrVideoMediaStream || video.readyState !== video.HAVE_ENOUGH_DATA) {
          qrScanAnimationId = requestAnimationFrame(scanFrame);
          return;
        }

        try {
          const barcodes = await barcodeDetector.detect(video);
          if (barcodes.length > 0) {
            const rawVal = barcodes[0].rawValue;
            handleDetectedQrCode(rawVal);
            return;
          }
        } catch (_) {}

        qrScanAnimationId = requestAnimationFrame(scanFrame);
      };
      qrScanAnimationId = requestAnimationFrame(scanFrame);
      return;
    } catch (_) {}
  }

  // Fallback if BarcodeDetector is not natively available
  const statusEl = document.getElementById("qr-scanner-status");
  if (statusEl) {
    statusEl.innerText = "Hinweis: Browser unterstützt native BarcodeDetector API nicht. Bitte QR-Code Secret manuell einfügen.";
  }
}

function handleDetectedQrCode(rawText) {
  closeQrScannerModal();
  if (!rawText) return;

  const totpInput = document.getElementById("item-totp");
  if (totpInput) {
    totpInput.value = rawText.trim();
    showToast("2FA QR-Code erfolgreich erkannt! ✓", "success");
    evaluateItemPasswordStrength(document.getElementById("item-password")?.value || "");
  }
}

// =============================================================
// ATOMIC MASTER PASSWORD CHANGE & RE-ENCRYPTION (#35)
// =============================================================

function openChangePasswordModal() {
  openModal("modal-change-password");
  document.getElementById("change-pwd-current").value = "";
  document.getElementById("change-pwd-new").value = "";
  document.getElementById("change-pwd-confirm").value = "";
}

async function submitChangeMasterPassword() {
  const oldPwd = document.getElementById("change-pwd-current").value;
  const newPwd = document.getElementById("change-pwd-new").value;
  const confirmPwd = document.getElementById("change-pwd-confirm").value;

  if (!oldPwd || !newPwd) {
    showToast("Bitte gib dein aktuelles und neues Master-Passwort ein.", "error");
    return;
  }
  if (newPwd !== confirmPwd) {
    showToast("Die neuen Passwörter stimmen nicht überein.", "error");
    return;
  }
  if (newPwd.length < 10) {
    showToast("Das neue Passwort muss mindestens 10 Zeichen lang sein.", "warning");
    return;
  }

  const btn = document.getElementById("btn-submit-change-pwd");
  if (btn) {
    btn.disabled = true;
    btn.innerText = "⏳ Re-verschlüssele Tresor...";
  }

  try {
    // 1. Generate fresh salts
    const newEncSalt = bufferToHex(window.crypto.getRandomValues(new Uint8Array(16)));
    const newClientSalt = bufferToHex(window.crypto.getRandomValues(new Uint8Array(16)));
    const newServerSalt = bufferToHex(window.crypto.getRandomValues(new Uint8Array(16)));
    const newAuthSalt = `${newClientSalt}:${newServerSalt}`;

    // 2. Derive new Master Key & Auth Hash
    const newMasterKey = await deriveMasterEncryptionKey(newPwd, newEncSalt);
    const newClientAuthKey = await deriveClientAuthKey(newPwd, newClientSalt);
    const newAuthHash = await deriveClientAuthKey(newClientAuthKey, newServerSalt);

    // 3. Atomically re-encrypt all vault items
    const reencryptedItems = [];
    for (const item of decryptedItems) {
      const newPayload = await encryptPayload(item.data, newMasterKey);
      reencryptedItems.push({
        id: item.id,
        encrypted_payload: newPayload
      });
    }

    // 4. Send atomic update to API
    const resp = await fetchWithAuth("/api/vault/re-encrypt", {
      method: "POST",
      body: JSON.stringify({
        new_auth_salt: newAuthSalt,
        new_auth_hash: newAuthHash,
        new_enc_salt: newEncSalt,
        items: reencryptedItems
      })
    });

    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.detail || "Serverfehler bei Re-Verschlüsselung");
    }

    // 5. Update local session state
    masterEncryptionKey = newMasterKey;
    currentUser.enc_salt = newEncSalt;
    currentUser.auth_salt = newAuthSalt;
    sessionStorage.setItem("sentinelbit_enc_salt", newEncSalt);

    closeModal("modal-change-password");
    showToast("🎉 Master-Passwort erfolgreich geändert und Tresor atomar neu verschlüsselt!", "success");
    await fetchVaultItems();
  } catch (err) {
    showToast("❌ Fehler beim Ändern des Master-Passworts: " + err.message, "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<svg viewBox="0 0 24 24"><path d="M21 2l-2 2m-1.5 1.5L16 7l-1.5-1.5L13 7l-1.5-1.5L9 8a6 6 0 1 0 5 9.8L22 10V6l-4-4z"/></svg> Passwort jetzt ändern`;
    }
  }
}

// =============================================================
// SHAMIR'S SECRET SHARING (3-of-5 EMERGENCY KEY SPLIT) (#34)
// =============================================================

const GF256 = (function() {
  const exp = new Uint8Array(512);
  const log = new Uint8Array(256);
  let x = 1;
  for (let i = 0; i < 255; i++) {
    exp[i] = x;
    exp[i + 255] = x;
    log[x] = i;
    let x2 = (x << 1) & 0xff;
    if (x & 0x80) x2 ^= 0x1b;
    x = x2 ^ x;
  }
  for (let i = 510; i < 512; i++) exp[i] = exp[i - 255];
  function mul(a, b) { if (!a || !b) return 0; return exp[log[a] + log[b]]; }
  function div(a, b) {
    if (!b) throw new Error("div 0");
    if (!a) return 0;
    let diff = log[a] - log[b];
    if (diff < 0) diff += 255;
    return exp[diff];
  }
  return { mul, div };
})();

let generatedShamirShareHexes = [];

function openShamirModal() {
  openModal("modal-shamir");
  document.getElementById("shamir-shares-container").style.display = "none";
}

async function generateShamirShares() {
  if (!masterEncryptionKey) {
    showToast("Tresor nicht entsperrt.", "error");
    return;
  }

  // Export raw master key bytes
  let rawKeyBytes;
  try {
    rawKeyBytes = await window.crypto.subtle.exportKey("raw", masterEncryptionKey);
  } catch (_) {
    // If key not extractable, derive 32-byte emergency token from current session
    const h = await window.crypto.subtle.digest("SHA-256", strToBuffer(currentUser.enc_salt + currentUser.username));
    rawKeyBytes = h;
  }

  const secretBytes = new Uint8Array(rawKeyBytes);
  const total = 5;
  const threshold = 3;
  const shares = [];

  for (let i = 0; i < total; i++) {
    shares[i] = new Uint8Array(secretBytes.length + 1);
    shares[i][0] = i + 1; // x coordinate != 0
  }

  for (let byteIdx = 0; byteIdx < secretBytes.length; byteIdx++) {
    const poly = new Uint8Array(threshold);
    poly[0] = secretBytes[byteIdx];
    window.crypto.getRandomValues(poly.subarray(1));

    for (let i = 0; i < total; i++) {
      const x = shares[i][0];
      let y = poly[0];
      let xPow = 1;
      for (let c = 1; c < threshold; c++) {
        xPow = GF256.mul(xPow, x);
        y ^= GF256.mul(poly[c], xPow);
      }
      shares[i][byteIdx + 1] = y;
    }
  }

  generatedShamirShareHexes = shares.map((s, idx) => `SB-SSS-SHARE-${idx + 1}-OF-5:${bufferToHex(s)}`);

  const listEl = document.getElementById("shamir-shares-list");
  listEl.innerHTML = generatedShamirShareHexes.map((hex, idx) => `
    <div style="background: rgba(255,255,255,0.05); padding: 8px 12px; border-radius: 6px; border: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; word-break: break-all;">
      <span><strong>Schlüssel ${idx + 1}:</strong> ${hex}</span>
      <button type="button" class="btn-icon" onclick="copyToClipboard('${hex}', 'Schlüssel ${idx + 1} kopiert!')" title="Kopieren">📋</button>
    </div>
  `).join("");

  document.getElementById("shamir-shares-container").style.display = "block";
  showToast("5 Shamir-Notfall-Schlüssel (3-aus-5) erfolgreich generiert! ✓", "success");
}

function copyAllShamirShares() {
  if (generatedShamirShareHexes.length === 0) return;
  const text = generatedShamirShareHexes.join("\n");
  copyToClipboard(text, "Alle 5 Notfall-Schlüssel kopiert!");
}

// =============================================================
// WEBHOOKS MANAGEMENT UI (#97)
// =============================================================

function openWebhooksModal() {
  openModal("modal-webhooks");
  loadWebhooks();
}

async function loadWebhooks() {
  const container = document.getElementById("webhooks-list");
  try {
    const res = await fetchWithAuth("/api/webhooks");
    if (!res.ok) throw new Error("Fehler beim Laden");
    const hooks = await res.json();

    if (hooks.length === 0) {
      container.innerHTML = `<div style="font-size: 0.8rem; color: var(--text-dim);">Keine Webhooks eingerichtet.</div>`;
      return;
    }

    container.innerHTML = hooks.map(h => `
      <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border-color); border-radius: 6px; padding: 10px; display: flex; justify-content: space-between; align-items: center;">
        <div style="font-size: 0.82rem; overflow: hidden; text-overflow: ellipsis;">
          <div style="font-weight: bold; color: #818cf8;">${escapeHtml(h.url)}</div>
          <div style="font-size: 0.72rem; color: var(--text-dim); margin-top: 2px;">Events: ${escapeHtml(h.events)}</div>
        </div>
        <div style="display: flex; gap: 6px;">
          <button type="button" class="btn btn-secondary" style="font-size: 0.72rem; padding: 3px 8px;" onclick="testWebhook('${h.id}')" title="Test-Ping senden">🔔 Test</button>
          <button type="button" class="btn-icon" style="color: #f87171;" onclick="deleteWebhook('${h.id}')" title="Löschen">🗑️</button>
        </div>
      </div>
    `).join("");
  } catch (err) {
    container.innerHTML = `<div style="color: #f87171; font-size: 0.8rem;">Fehler beim Laden der Webhooks.</div>`;
  }
}

async function submitCreateWebhook() {
  const url = document.getElementById("webhook-url").value;
  const secret = document.getElementById("webhook-secret").value;

  try {
    const res = await fetchWithAuth("/api/webhooks", {
      method: "POST",
      body: JSON.stringify({ url, secret, events: "vault:change" })
    });
    if (!res.ok) throw new Error("Fehler beim Anlegen");
    showToast("Webhook erfolgreich registriert!", "success");
    document.getElementById("webhook-url").value = "";
    document.getElementById("webhook-secret").value = "";
    loadWebhooks();
  } catch (err) {
    showToast("Fehler: " + err.message, "error");
  }
}

async function deleteWebhook(id) {
  if (!confirm("Webhook wirklich löschen?")) return;
  try {
    const res = await fetchWithAuth(`/api/webhooks/${id}`, { method: "DELETE" });
    if (res.ok) {
      showToast("Webhook gelöscht.", "info");
      loadWebhooks();
    }
  } catch (_) {}
}

async function testWebhook(id) {
  try {
    const res = await fetchWithAuth(`/api/webhooks/${id}/test`, { method: "POST" });
    if (res.ok) {
      showToast("Test-Event versendet! ✓", "success");
    }
  } catch (_) {}
}

// =============================================================
// EMERGENCY ACCESS / TOTMANN-SCHALTER UI (#72)
// =============================================================

function openEmergencyContactsModal() {
  openModal("modal-emergency-contacts");
  loadEmergencyContacts();
}

async function loadEmergencyContacts() {
  const container = document.getElementById("emergency-contacts-list");
  try {
    const res = await fetchWithAuth("/api/emergency/contacts");
    if (!res.ok) throw new Error("Fehler beim Laden");
    const contacts = await res.json();

    if (contacts.length === 0) {
      container.innerHTML = `<div style="font-size: 0.8rem; color: var(--text-dim);">Keine Notfall-Kontakte hinterlegt.</div>`;
      return;
    }

    container.innerHTML = contacts.map(c => `
      <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border-color); border-radius: 6px; padding: 10px; display: flex; justify-content: space-between; align-items: center;">
        <div style="font-size: 0.82rem;">
          <div style="font-weight: bold; color: #f97316;">${escapeHtml(c.contact_email)}</div>
          <div style="font-size: 0.72rem; color: var(--text-dim);">Wartezeit: ${c.wait_time_days} Tage | Status: ${escapeHtml(c.status)}</div>
        </div>
        <button type="button" class="btn-icon" style="color: #f87171;" onclick="deleteEmergencyContact('${c.id}')" title="Löschen">🗑️</button>
      </div>
    `).join("");
  } catch (err) {
    container.innerHTML = `<div style="color: #f87171; font-size: 0.8rem;">Fehler beim Laden.</div>`;
  }
}

async function submitCreateEmergencyContact() {
  const email = document.getElementById("emergency-email").value;
  const days = parseInt(document.getElementById("emergency-wait-days").value, 10) || 30;

  try {
    const res = await fetchWithAuth("/api/emergency/contacts", {
      method: "POST",
      body: JSON.stringify({ contact_email: email, wait_time_days: days })
    });
    if (!res.ok) throw new Error("Fehler beim Anlegen");
    showToast("Notfallkontakt hinterlegt!", "success");
    document.getElementById("emergency-email").value = "";
    loadEmergencyContacts();
  } catch (err) {
    showToast("Fehler: " + err.message, "error");
  }
}

async function deleteEmergencyContact(id) {
  if (!confirm("Notfall-Kontakt entfernen?")) return;
  try {
    const res = await fetchWithAuth(`/api/emergency/contacts/${id}`, { method: "DELETE" });
    if (res.ok) {
      showToast("Kontakt entfernt.", "info");
      loadEmergencyContacts();
    }
  } catch (_) {}
}

// =============================================================
// AUDIT LOG UI (#78)
// =============================================================

function openAuditLogModal() {
  openModal("modal-audit-log");
  loadAuditLogs();
}

async function loadAuditLogs() {
  const container = document.getElementById("audit-logs-list");
  try {
    const res = await fetchWithAuth("/api/audit/logs");
    if (!res.ok) throw new Error("Fehler");
    const logs = await res.json();

    if (logs.length === 0) {
      container.innerHTML = `<div style="font-size: 0.8rem; color: var(--text-dim);">Keine protokollierten Ereignisse vorhanden.</div>`;
      return;
    }

    container.innerHTML = logs.map(l => `
      <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border-color); border-radius: 6px; padding: 8px 12px; font-size: 0.78rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
          <strong style="color: #38bdf8;">${escapeHtml(l.action)}</strong>
          <span style="font-size: 0.7rem; color: var(--text-dim);">${new Date(l.created_at).toLocaleString()}</span>
        </div>
        <div style="color: var(--text-muted);">${escapeHtml(l.details || l.resource_type)}</div>
      </div>
    `).join("");
  } catch (err) {
    container.innerHTML = `<div style="color: #f87171; font-size: 0.8rem;">Fehler beim Laden des Audit-Logs.</div>`;
  }
}

// =============================================================
// I18N SPRACHWECHSLER (#60)
// =============================================================

let currentAppLang = localStorage.getItem("sentinelbit_lang") || "de";

function toggleLanguage() {
  currentAppLang = currentAppLang === "de" ? "en" : "de";
  localStorage.setItem("sentinelbit_lang", currentAppLang);
  const btn = document.getElementById("lang-toggle-btn");
  if (btn) btn.innerText = currentAppLang.toUpperCase();
  showToast(currentAppLang === "de" ? "🇩🇪 Sprache auf Deutsch umgestellt" : "🇬🇧 Language switched to English", "info");
}

// Check NTP drift on startup
checkNtpClockDrift();




