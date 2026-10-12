// ==============================================================================
// sentinelbit Password & Passkey Manager
// WebAuthn / FIDO2 Interception Engine (Injected into Webpage MAIN context)
// ==============================================================================

(function () {
  "use strict";

  if (window.__sentinelbitWebAuthnInjected) return;
  window.__sentinelbitWebAuthnInjected = true;

  if (!navigator || !navigator.credentials) return;

  const origGet = navigator.credentials.get.bind(navigator.credentials);
  const origCreate = navigator.credentials.create.bind(navigator.credentials);

  // Buffer helpers
  function bufferToBase64Url(buffer) {
    if (!buffer) return "";
    let bytes;
    if (buffer instanceof Uint8Array) {
      bytes = buffer;
    } else if (buffer instanceof ArrayBuffer) {
      bytes = new Uint8Array(buffer);
    } else if (ArrayBuffer.isView(buffer)) {
      bytes = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    } else {
      return "";
    }
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64UrlToBuffer(base64url) {
    if (!base64url) return new Uint8Array(0);
    const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((base64url.length + 3) % 4);
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Ensure Platform Authenticator feature discovery passes
  if (window.PublicKeyCredential) {
    const origPlatformAuth = PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable;
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async function () {
      if (origPlatformAuth) {
        try {
          const res = await origPlatformAuth.call(PublicKeyCredential);
          if (res) return true;
        } catch (_) {}
      }
      return true;
    };

    if (PublicKeyCredential.isConditionalMediationAvailable) {
      const origConditional = PublicKeyCredential.isConditionalMediationAvailable;
      PublicKeyCredential.isConditionalMediationAvailable = async function () {
        if (origConditional) {
          try {
            const res = await origConditional.call(PublicKeyCredential);
            if (res) return true;
          } catch (_) {}
        }
        return true;
      };
    }
  }

  let requestCounter = 0;
  const pendingRequests = new Map();

  // Listen for responses from sentinelbit content script
  window.addEventListener("message", (event) => {
    if (event.source !== window || !event.data || event.data.source !== "SENTINELBIT_CONTENT_WEBAUTHN") {
      return;
    }

    const { requestId, status, data, error } = event.data;
    const resolver = pendingRequests.get(requestId);
    if (!resolver) return;
    pendingRequests.delete(requestId);

    if (status === "success") {
      resolver.resolve(data);
    } else if (status === "fallback") {
      resolver.fallback();
    } else {
      resolver.reject(new Error(error || "sentinelbit Passkey operation cancelled"));
    }
  });

  // -------------------------------------------------------------
  // 1. Intercept navigator.credentials.get (Assertion / Login)
  // -------------------------------------------------------------
  navigator.credentials.get = async function (options) {
    if (!options || !options.publicKey) {
      return origGet(options);
    }

    const pk = options.publicKey;
    const reqId = "sb_get_" + (++requestCounter) + "_" + Math.random().toString(36).slice(2);

    const cleanChallenge = bufferToBase64Url(pk.challenge);
    const cleanRpId = pk.rpId || window.location.hostname;
    const cleanAllow = (pk.allowCredentials || []).map(c => ({
      id: bufferToBase64Url(c.id),
      type: c.type || "public-key",
      transports: c.transports || []
    }));

    return new Promise((resolve, reject) => {
      const timeoutMs = (pk.timeout && pk.timeout > 1000) ? Math.min(pk.timeout, 120000) : 60000;
      const timeoutTimer = setTimeout(() => {
        if (pendingRequests.has(reqId)) {
          pendingRequests.delete(reqId);
          origGet(options).then(resolve).catch(reject);
        }
      }, timeoutMs);

      pendingRequests.set(reqId, {
        resolve: (assertionData) => {
          clearTimeout(timeoutTimer);
          try {
            const rawIdBytes = base64UrlToBuffer(assertionData.rawIdB64 || assertionData.id);
            const clientDataBytes = base64UrlToBuffer(assertionData.clientDataB64);
            const authDataBytes = base64UrlToBuffer(assertionData.authDataB64);
            const sigBytes = base64UrlToBuffer(assertionData.signatureB64);
            const userHandleBytes = assertionData.userHandleB64 ? base64UrlToBuffer(assertionData.userHandleB64) : null;

            // Construct compliant PublicKeyCredential
            const cred = Object.create(window.PublicKeyCredential ? window.PublicKeyCredential.prototype : Object.prototype);
            cred.id = assertionData.id;
            cred.rawId = rawIdBytes.buffer;
            cred.type = "public-key";
            cred.authenticatorAttachment = "platform";

            const resp = Object.create(window.AuthenticatorAssertionResponse ? window.AuthenticatorAssertionResponse.prototype : Object.prototype);
            resp.clientDataJSON = clientDataBytes.buffer;
            resp.authenticatorData = authDataBytes.buffer;
            resp.signature = sigBytes.buffer;
            resp.userHandle = userHandleBytes ? userHandleBytes.buffer : null;
            cred.response = resp;
            cred.getClientExtensionResults = () => ({});

            resolve(cred);
          } catch (err) {
            console.warn("[sentinelbit] Assertion construction error, falling back to native:", err);
            origGet(options).then(resolve).catch(reject);
          }
        },
        fallback: () => {
          clearTimeout(timeoutTimer);
          origGet(options).then(resolve).catch(reject);
        },
        reject: (err) => {
          clearTimeout(timeoutTimer);
          origGet(options).then(resolve).catch(reject);
        }
      });

      // Post message to sentinelbit content.js
      window.postMessage({
        source: "SENTINELBIT_PAGE_WEBAUTHN",
        type: "GET_REQUEST",
        requestId: reqId,
        options: {
          challenge: cleanChallenge,
          rpId: cleanRpId,
          allowCredentials: cleanAllow,
          userVerification: pk.userVerification || "preferred",
          mediation: options.mediation || "optional"
        }
      }, "*");
    });
  };

  // -------------------------------------------------------------
  // 2. Intercept navigator.credentials.create (Attestation / Register)
  // -------------------------------------------------------------
  navigator.credentials.create = async function (options) {
    if (!options || !options.publicKey) {
      return origCreate(options);
    }

    const pk = options.publicKey;
    const reqId = "sb_create_" + (++requestCounter) + "_" + Math.random().toString(36).slice(2);

    const cleanChallenge = bufferToBase64Url(pk.challenge);
    const cleanRpId = pk.rp ? (pk.rp.id || window.location.hostname) : window.location.hostname;
    const cleanRpName = pk.rp ? (pk.rp.name || cleanRpId) : cleanRpId;
    const cleanUserId = pk.user ? bufferToBase64Url(pk.user.id) : "";
    const cleanUserName = pk.user ? (pk.user.name || "") : "";
    const cleanUserDisplayName = pk.user ? (pk.user.displayName || cleanUserName) : cleanUserName;

    return new Promise((resolve, reject) => {
      const timeoutMs = (pk.timeout && pk.timeout > 1000) ? Math.min(pk.timeout, 120000) : 60000;
      const timeoutTimer = setTimeout(() => {
        if (pendingRequests.has(reqId)) {
          pendingRequests.delete(reqId);
          origCreate(options).then(resolve).catch(reject);
        }
      }, timeoutMs);

      pendingRequests.set(reqId, {
        resolve: (attestationData) => {
          clearTimeout(timeoutTimer);
          try {
            const rawIdBytes = base64UrlToBuffer(attestationData.rawIdB64 || attestationData.id);
            const clientDataBytes = base64UrlToBuffer(attestationData.clientDataB64);
            const attObjBytes = base64UrlToBuffer(attestationData.attestationObjectB64);

            const cred = Object.create(window.PublicKeyCredential ? window.PublicKeyCredential.prototype : Object.prototype);
            cred.id = attestationData.id;
            cred.rawId = rawIdBytes.buffer;
            cred.type = "public-key";
            cred.authenticatorAttachment = "platform";

            const resp = Object.create(window.AuthenticatorAttestationResponse ? window.AuthenticatorAttestationResponse.prototype : Object.prototype);
            resp.clientDataJSON = clientDataBytes.buffer;
            resp.attestationObject = attObjBytes.buffer;
            resp.getAuthenticatorData = () => {
              if (attestationData.authDataB64) {
                return base64UrlToBuffer(attestationData.authDataB64).buffer;
              }
              return new ArrayBuffer(0);
            };
            resp.getPublicKey = () => {
              if (attestationData.spkiB64) {
                return base64UrlToBuffer(attestationData.spkiB64).buffer;
              }
              return null;
            };
            resp.getPublicKeyAlgorithm = () => -7;
            resp.getTransports = () => ["internal", "hybrid"];
            cred.response = resp;
            cred.getClientExtensionResults = () => ({});

            resolve(cred);
          } catch (err) {
            console.warn("[sentinelbit] Attestation construction error, falling back to native:", err);
            origCreate(options).then(resolve).catch(reject);
          }
        },
        fallback: () => {
          clearTimeout(timeoutTimer);
          origCreate(options).then(resolve).catch(reject);
        },
        reject: (err) => {
          clearTimeout(timeoutTimer);
          origCreate(options).then(resolve).catch(reject);
        }
      });

      window.postMessage({
        source: "SENTINELBIT_PAGE_WEBAUTHN",
        type: "CREATE_REQUEST",
        requestId: reqId,
        options: {
          challenge: cleanChallenge,
          rp: { id: cleanRpId, name: cleanRpName },
          user: { id: cleanUserId, name: cleanUserName, displayName: cleanUserDisplayName },
          pubKeyCredParams: pk.pubKeyCredParams || []
        }
      }, "*");
    });
  };

  console.debug("[sentinelbit] WebAuthn Passkey Interceptor active.");
})();
