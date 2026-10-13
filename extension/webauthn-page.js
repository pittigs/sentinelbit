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
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    } catch (e) {
      console.warn("[sentinelbit] base64 decode error for:", str, e);
      return new Uint8Array(0);
    }
  }

  function toArrayBuffer(bufOrView) {
    if (!bufOrView) return new ArrayBuffer(0);
    if (bufOrView instanceof ArrayBuffer) return bufOrView;
    if (ArrayBuffer.isView(bufOrView)) {
      return bufOrView.buffer.slice(bufOrView.byteOffset, bufOrView.byteOffset + bufOrView.byteLength);
    }
    return new ArrayBuffer(0);
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
  async function sentinelbitCredentialsGet(options) {
    console.log("[sentinelbit] Intercepted credentials.get:", options);
    if (!options || !options.publicKey) {
      return origGet.call(navigator.credentials, options);
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

    if (options.signal && options.signal.aborted) {
      return Promise.reject(new DOMException("The operation was aborted.", "AbortError"));
    }

    return new Promise((resolve, reject) => {
      const timeoutMs = (pk.timeout && pk.timeout > 1000) ? Math.min(pk.timeout, 120000) : 60000;
      const timeoutTimer = setTimeout(() => {
        if (pendingRequests.has(reqId)) {
          pendingRequests.delete(reqId);
          console.log("[sentinelbit] credentials.get timed out, falling back to native");
          origGet.call(navigator.credentials, options).then(resolve).catch(reject);
        }
      }, timeoutMs);

      if (options.signal) {
        options.signal.addEventListener("abort", () => {
          if (pendingRequests.has(reqId)) {
            pendingRequests.delete(reqId);
            clearTimeout(timeoutTimer);
            reject(new DOMException("The operation was aborted.", "AbortError"));
          }
        }, { once: true });
      }

      pendingRequests.set(reqId, {
        resolve: (assertionData) => {
          clearTimeout(timeoutTimer);
          try {
            const rawIdBytes = base64UrlToBuffer(assertionData.rawIdB64 || assertionData.id);
            const clientDataBytes = base64UrlToBuffer(assertionData.clientDataB64);
            const authDataBytes = base64UrlToBuffer(assertionData.authDataB64);
            const sigBytes = base64UrlToBuffer(assertionData.signatureB64);
            const userHandleBytes = assertionData.userHandleB64 ? base64UrlToBuffer(assertionData.userHandleB64) : null;

            const clientDataBuf = toArrayBuffer(clientDataBytes);
            const authDataBuf = toArrayBuffer(authDataBytes);
            const sigBuf = toArrayBuffer(sigBytes);
            const userHandleBuf = userHandleBytes && userHandleBytes.length > 0 ? toArrayBuffer(userHandleBytes) : null;
            let rawIdBuf = toArrayBuffer(rawIdBytes);
            let idB64Url = bufferToBase64Url(rawIdBytes) || assertionData.id;

            // If the Relying Party provided allowCredentials in options, match the exact credential
            // descriptor so rawId is bit-for-bit identical to what the server requested
            if (pk.allowCredentials && pk.allowCredentials.length > 0) {
              function normHexOrB64(bufOrStr) {
                if (!bufOrStr) return "";
                if (bufOrStr instanceof ArrayBuffer || bufOrStr instanceof Uint8Array || ArrayBuffer.isView(bufOrStr)) {
                  let bytes = bufOrStr instanceof Uint8Array ? bufOrStr : new Uint8Array(bufOrStr.buffer || bufOrStr, bufOrStr.byteOffset || 0, bufOrStr.byteLength);
                  let binary = "";
                  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
                  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
                }
                const s = String(bufOrStr).trim();
                const isUuid = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(s);
                const isPureHex = /^[0-9a-fA-F]{32,}$/.test(s) && s.length % 2 === 0;
                if (isUuid || isPureHex) {
                  const cleanHex = s.replace(/-/g, "");
                  try {
                    const matchBytes = new Uint8Array(cleanHex.length / 2);
                    for (let i = 0; i < cleanHex.length; i += 2) {
                      matchBytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
                    }
                    return bufferToBase64Url(matchBytes);
                  } catch (_) {}
                }
                return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
              }

              try {
                const targetNorm = normHexOrB64(assertionData.id);
                const matched = pk.allowCredentials.find(c => {
                  return normHexOrB64(c.id) === targetNorm;
                }) || (pk.allowCredentials.length === 1 ? pk.allowCredentials[0] : null);

                if (matched && matched.id) {
                  rawIdBuf = toArrayBuffer(matched.id);
                  idB64Url = bufferToBase64Url(matched.id);
                }
              } catch (matchErr) {
                console.warn("[sentinelbit] allowCredentials matching non-fatal error:", matchErr);
              }
            }

            // Construct AuthenticatorAssertionResponse with own property descriptors
            // to shadow WebIDL getters and prevent Illegal invocation errors
            const respProto = (window.AuthenticatorAssertionResponse && window.AuthenticatorAssertionResponse.prototype)
              ? window.AuthenticatorAssertionResponse.prototype
              : Object.prototype;
            const resp = Object.create(respProto);

            Object.defineProperties(resp, {
              clientDataJSON: { value: clientDataBuf, enumerable: true, configurable: true, writable: false },
              authenticatorData: { value: authDataBuf, enumerable: true, configurable: true, writable: false },
              signature: { value: sigBuf, enumerable: true, configurable: true, writable: false },
              userHandle: { value: userHandleBuf, enumerable: true, configurable: true, writable: false }
            });

            // Construct PublicKeyCredential with own property descriptors
            const credProto = (window.PublicKeyCredential && window.PublicKeyCredential.prototype)
              ? window.PublicKeyCredential.prototype
              : Object.prototype;
            const cred = Object.create(credProto);

            Object.defineProperties(cred, {
              id: { value: idB64Url, enumerable: true, configurable: true, writable: false },
              rawId: { value: rawIdBuf, enumerable: true, configurable: true, writable: false },
              type: { value: "public-key", enumerable: true, configurable: true, writable: false },
              authenticatorAttachment: { value: "platform", enumerable: true, configurable: true, writable: false },
              response: { value: resp, enumerable: true, configurable: true, writable: false },
              getClientExtensionResults: {
                value: function () { return {}; },
                enumerable: true,
                configurable: true,
                writable: false
              },
              toJSON: {
                value: function () {
                  return {
                    id: idB64Url,
                    rawId: idB64Url,
                    response: {
                      clientDataJSON: bufferToBase64Url(clientDataBytes),
                      authenticatorData: bufferToBase64Url(authDataBytes),
                      signature: bufferToBase64Url(sigBytes),
                      userHandle: userHandleBuf ? bufferToBase64Url(userHandleBytes) : null
                    },
                    authenticatorAttachment: "platform",
                    type: "public-key",
                    clientExtensionResults: {}
                  };
                },
                enumerable: true,
                configurable: true,
                writable: false
              }
            });

            console.log("[sentinelbit] Successfully resolved credentials.get with passkey assertion:", cred);
            resolve(cred);
          } catch (err) {
            console.error("[sentinelbit] Assertion construction error, falling back to native:", err);
            origGet.call(navigator.credentials, options).then(resolve).catch(reject);
          }
        },
        fallback: () => {
          clearTimeout(timeoutTimer);
          console.log("[sentinelbit] Fallback requested, calling native credentials.get");
          origGet.call(navigator.credentials, options).then(resolve).catch(reject);
        },
        reject: (err) => {
          clearTimeout(timeoutTimer);
          origGet.call(navigator.credentials, options).then(resolve).catch(reject);
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
  }

  // -------------------------------------------------------------
  // 2. Intercept navigator.credentials.create (Attestation / Register)
  // -------------------------------------------------------------
  async function sentinelbitCredentialsCreate(options) {
    console.log("[sentinelbit] Intercepted credentials.create:", options);
    if (!options || !options.publicKey) {
      return origCreate.call(navigator.credentials, options);
    }

    const pk = options.publicKey;
    const reqId = "sb_create_" + (++requestCounter) + "_" + Math.random().toString(36).slice(2);

    const cleanChallenge = bufferToBase64Url(pk.challenge);
    const cleanRpId = pk.rp ? (pk.rp.id || window.location.hostname) : window.location.hostname;
    const cleanRpName = pk.rp ? (pk.rp.name || cleanRpId) : cleanRpId;
    const cleanUserId = pk.user ? bufferToBase64Url(pk.user.id) : "";
    const cleanUserName = pk.user ? (pk.user.name || "") : "";
    const cleanUserDisplayName = pk.user ? (pk.user.displayName || cleanUserName) : cleanUserName;

    if (options.signal && options.signal.aborted) {
      return Promise.reject(new DOMException("The operation was aborted.", "AbortError"));
    }

    return new Promise((resolve, reject) => {
      const timeoutMs = (pk.timeout && pk.timeout > 1000) ? Math.min(pk.timeout, 120000) : 60000;
      const timeoutTimer = setTimeout(() => {
        if (pendingRequests.has(reqId)) {
          pendingRequests.delete(reqId);
          console.log("[sentinelbit] credentials.create timed out, falling back to native");
          origCreate.call(navigator.credentials, options).then(resolve).catch(reject);
        }
      }, timeoutMs);

      if (options.signal) {
        options.signal.addEventListener("abort", () => {
          if (pendingRequests.has(reqId)) {
            pendingRequests.delete(reqId);
            clearTimeout(timeoutTimer);
            reject(new DOMException("The operation was aborted.", "AbortError"));
          }
        }, { once: true });
      }

      pendingRequests.set(reqId, {
        resolve: (attestationData) => {
          clearTimeout(timeoutTimer);
          try {
            const rawIdBytes = base64UrlToBuffer(attestationData.rawIdB64 || attestationData.id);
            const clientDataBytes = base64UrlToBuffer(attestationData.clientDataB64);
            const attObjBytes = base64UrlToBuffer(attestationData.attestationObjectB64);
            const authDataBytes = attestationData.authDataB64 ? base64UrlToBuffer(attestationData.authDataB64) : new Uint8Array(0);
            const spkiBytes = attestationData.spkiB64 ? base64UrlToBuffer(attestationData.spkiB64) : null;

            const clientDataBuf = toArrayBuffer(clientDataBytes);
            const attObjBuf = toArrayBuffer(attObjBytes);
            const authDataBuf = toArrayBuffer(authDataBytes);
            const spkiBuf = spkiBytes ? toArrayBuffer(spkiBytes) : null;
            const rawIdBuf = toArrayBuffer(rawIdBytes);
            const idB64Url = bufferToBase64Url(rawIdBytes) || attestationData.id;

            const respProto = (window.AuthenticatorAttestationResponse && window.AuthenticatorAttestationResponse.prototype)
              ? window.AuthenticatorAttestationResponse.prototype
              : Object.prototype;
            const resp = Object.create(respProto);

            Object.defineProperties(resp, {
              clientDataJSON: { value: clientDataBuf, enumerable: true, configurable: true, writable: false },
              attestationObject: { value: attObjBuf, enumerable: true, configurable: true, writable: false },
              getAuthenticatorData: {
                value: function () { return authDataBuf; },
                enumerable: true,
                configurable: true,
                writable: false
              },
              getPublicKey: {
                value: function () { return spkiBuf; },
                enumerable: true,
                configurable: true,
                writable: false
              },
              getPublicKeyAlgorithm: {
                value: function () { return -7; },
                enumerable: true,
                configurable: true,
                writable: false
              },
              getTransports: {
                value: function () { return ["internal", "hybrid"]; },
                enumerable: true,
                configurable: true,
                writable: false
              }
            });

            const credProto = (window.PublicKeyCredential && window.PublicKeyCredential.prototype)
              ? window.PublicKeyCredential.prototype
              : Object.prototype;
            const cred = Object.create(credProto);

            Object.defineProperties(cred, {
              id: { value: idB64Url, enumerable: true, configurable: true, writable: false },
              rawId: { value: rawIdBuf, enumerable: true, configurable: true, writable: false },
              type: { value: "public-key", enumerable: true, configurable: true, writable: false },
              authenticatorAttachment: { value: "platform", enumerable: true, configurable: true, writable: false },
              response: { value: resp, enumerable: true, configurable: true, writable: false },
              getClientExtensionResults: {
                value: function () { return {}; },
                enumerable: true,
                configurable: true,
                writable: false
              },
              toJSON: {
                value: function () {
                  return {
                    id: idB64Url,
                    rawId: idB64Url,
                    response: {
                      clientDataJSON: bufferToBase64Url(clientDataBytes),
                      attestationObject: bufferToBase64Url(attObjBytes),
                      transports: ["internal", "hybrid"]
                    },
                    authenticatorAttachment: "platform",
                    type: "public-key",
                    clientExtensionResults: {}
                  };
                },
                enumerable: true,
                configurable: true,
                writable: false
              }
            });

            console.log("[sentinelbit] Successfully registered new passkey:", cred);
            resolve(cred);
          } catch (err) {
            console.error("[sentinelbit] Attestation construction error, falling back to native:", err);
            origCreate.call(navigator.credentials, options).then(resolve).catch(reject);
          }
        },
        fallback: () => {
          clearTimeout(timeoutTimer);
          console.log("[sentinelbit] Fallback requested, calling native credentials.create");
          origCreate.call(navigator.credentials, options).then(resolve).catch(reject);
        },
        reject: (err) => {
          clearTimeout(timeoutTimer);
          origCreate.call(navigator.credentials, options).then(resolve).catch(reject);
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
  }

  // Hook prototype and instance
  if (window.CredentialsContainer && CredentialsContainer.prototype) {
    try {
      Object.defineProperty(CredentialsContainer.prototype, "get", {
        value: sentinelbitCredentialsGet,
        writable: true,
        configurable: true
      });
      Object.defineProperty(CredentialsContainer.prototype, "create", {
        value: sentinelbitCredentialsCreate,
        writable: true,
        configurable: true
      });
    } catch (_) {
      CredentialsContainer.prototype.get = sentinelbitCredentialsGet;
      CredentialsContainer.prototype.create = sentinelbitCredentialsCreate;
    }
  }

  try {
    Object.defineProperty(navigator.credentials, "get", {
      value: sentinelbitCredentialsGet,
      writable: true,
      configurable: true
    });
    Object.defineProperty(navigator.credentials, "create", {
      value: sentinelbitCredentialsCreate,
      writable: true,
      configurable: true
    });
  } catch (_) {
    navigator.credentials.get = sentinelbitCredentialsGet;
    navigator.credentials.create = sentinelbitCredentialsCreate;
  }

  console.info("[sentinelbit] WebAuthn Passkey Interceptor hooked into CredentialsContainer.");
})();
