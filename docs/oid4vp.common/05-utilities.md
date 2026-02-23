# 05 — Utility Classes

---

## Utility Inventory

| Class | Lines | Focus Area | Static | Dependencies |
|---|---|---|---|---|
| `SecurityUtils` | ~354 | Input validation, crypto, timing-safe ops | All static | `SecureRandom`, `MessageDigest` |
| `OpenID4VPUtil` | ~250 | Config, nonce/state gen, URL building | All static | `IdentityUtil` (WSO2), `SecureRandom` |
| `PresentationDefinitionUtil` | ~280 | PD parsing, validation, building | All static | Gson (`JsonParser`, `JsonObject`) |
| `CORSUtil` | ~170 | CORS headers, preflight, origin validation | All static | `HttpServletRequest/Response` |
| `URLValidator` | ~130 | URL/URI format validation, whitelist matching | All static | `java.net.URI` |
| `LogSanitizer` | ~75 | Log injection prevention | All static | None |

---

## 1. SecurityUtils

The security workhorse — handles input validation, cryptographic operations, and secure comparison.

### Regex Patterns (Compiled Constants)

```java
DID_PATTERN   = "^did:[a-z]+:[a-zA-Z0-9._%-]+.*$"
NONCE_PATTERN = "^[A-Za-z0-9_-]+={0,2}$"  // Base64URL
STATE_PATTERN = "^[A-Za-z0-9_-]+={0,2}$"  // Base64URL
UUID_PATTERN  = "^[0-9a-fA-F]{8}-..."      // RFC 4122
```

### Max Lengths

| Constant | Value | Purpose |
|---|---|---|
| `MAX_NONCE_LENGTH` | 256 | Prevents oversized nonce DoS |
| `MAX_STATE_LENGTH` | 256 | Prevents oversized state DoS |
| `MAX_URL_LENGTH` | 2048 | URL size limit |
| `MAX_DID_LENGTH` | 1024 | DID size limit |
| `MAX_VP_TOKEN_SIZE` | 1,048,576 (1 MB) | VP token payload limit |

### Cryptographic Generation

```java
// Uses java.security.SecureRandom (thread-safe singleton)
private static final SecureRandom SECURE_RANDOM = new SecureRandom();

generateNonce()             // 32 bytes → Base64URL (no padding)
generateNonce(int byteLen)  // Custom length
generateState()             // 16 bytes → Base64URL (no padding)
generateState(int byteLen)  // Custom length
generateChallenge()         // Alias for generateNonce()
```

**Base64URL encoding** uses `java.util.Base64.getUrlEncoder().withoutPadding()` — safe for URL query parameters.

### Validation Methods

| Method | Logic |
|---|---|
| `isValidDID(did)` | Null + length + regex match |
| `isValidUrl(url)` | Null + length + `new URI(url)` parse (no regex → avoids ReDOS) |
| `isValidNonce(nonce)` | Null + length + regex match |
| `isValidState(state)` | Null + length + regex match |
| `isValidUUID(uuid)` | Null + regex match |
| `isValidVPTokenSize(token)` | Null + `token.length() <= MAX_VP_TOKEN_SIZE` |
| `isWellFormedJWT(token)` | Exactly 3 dot-separated parts, each Base64URL |

### Secure Operations

```java
// Timing-safe comparison (prevents timing side-channel attacks)
constantTimeEquals(String a, String b)
// Uses MessageDigest.isEqual() internally

// SHA-256 hash
sha256(String input) → hex-encoded string

// Redirect URI safety check
isSafeRedirectUri(String uri)
// HTTPS only (exception: localhost for dev)
// No fragments (#)
// Must have scheme + host
```

### Log Sanitization (in SecurityUtils)

```java
sanitizeForLogging(String value, int visibleChars)
// Shows first N chars, masks rest with ***

sanitizeDIDForLogging(String did)
// Shows "did:method:first8chars***"
```

---

## 2. OpenID4VPUtil

Configuration reader and URL builder. The bridge between the OID4VP protocol and WSO2 IS configuration.

### WSO2 IS Configuration Integration

Uses `IdentityUtil.getProperty(key)` to read from `identity.xml`:

```java
// Config key → identity.xml path
"OpenID4VP.VPRequestExpirySeconds"   → int (default 300)
"OpenID4VP.RequestUriEnabled"        → boolean (default true)
"OpenID4VP.SigningAlgorithm"         → String (default "EdDSA")
"OpenID4VP.VerificationEnabled"      → boolean (default true)
"OpenID4VP.RevocationCheckEnabled"   → boolean (default true)
"OpenID4VP.MaxCacheSize"             → int (default 1000)
```

**How IdentityUtil works**: WSO2 Identity Server reads `repository/conf/identity/identity.xml` at startup. `IdentityUtil.getProperty()` provides access to values under `<Server>` element. The config key format (dot-separated) maps to XML element paths.

### Nonce and State Generation

Delegates to `SecurityUtils` but provides protocol-level API:

```java
generateNonce()  → SecurityUtils.generateNonce()   // 32 bytes
generateState()  → SecurityUtils.generateState()    // 16 bytes
```

### URL Builders

```java
buildRequestUri(String requestId)
// → {baseUrl}/api/identity/oid4vp/v1.0/request/{requestId}

buildResponseUri()
// → {baseUrl}/api/identity/oid4vp/v1.0/response

buildOpenID4VPDeepLink(String requestUri)
// → openid4vp://?request_uri={encoded_requestUri}&client_id={encoded_clientId}
```

### Base URL Resolution ⚠️

```java
public static String getBaseUrl() {
    String serverUrl = IdentityUtil.getProperty("OpenID4VP.ServerUrl");
    if (serverUrl != null) return serverUrl;

    // HARDCODED FALLBACK — development leftover
    return "https://masked-unprofitably-ardith.ngrok-free.dev";
}
```

**This is a critical code review finding** — the ngrok URL must be removed before production.

---

## 3. PresentationDefinitionUtil

Handles DIF Presentation Exchange JSON manipulation using Gson.

### Validation

```java
isValidPresentationDefinition(String json)
```

Validates:
1. Valid JSON (parseable by Gson)
2. Has `"id"` field (non-empty string)
3. Has `"input_descriptors"` field (non-empty array)
4. Each input descriptor has an `"id"` field

Returns `false` on any failure — does NOT throw.

### Parsing

```java
parsePresentationDefinition(String json) → JsonObject
// Gson JsonParser + validation

parsePresentationDefinitionResponse(String json) → PresentationDefinitionResponseDTO
// Full deserialization to typed DTO
```

### Building

```java
buildPresentationDefinition(String id, String name, List<JsonObject> inputDescriptors)
→ JsonObject

buildInputDescriptor(String id, String name, String purpose, List<String> paths, FilterDTO filter)
→ JsonObject
```

`buildInputDescriptor` automatically adds:
- `jwt_vp_json` format with `ES256` + `ES384` algorithms
- Constraints with the specified field paths and filter

### Submission Validation

```java
validateSubmissionAgainstDefinition(PresentationSubmissionDTO submission, String definitionJson)
→ boolean
```

Checks:
1. `submission.definitionId` matches `definition.id`
2. Every input descriptor in the PD has a matching descriptor map entry

### Pretty Printing

```java
prettyPrint(String json) → String   // Formatted with GsonBuilder().setPrettyPrinting()
prettyPrint(JsonObject obj) → String
```

---

## 4. CORSUtil

Handles Cross-Origin Resource Sharing for the OID4VP endpoints.

### Header Setting

```java
addCORSHeaders(HttpServletRequest request, HttpServletResponse response)
```

Sets:
| Header | Value |
|---|---|
| `Access-Control-Allow-Origin` | Reflected from `Origin` header |
| `Access-Control-Allow-Credentials` | `true` |
| `Access-Control-Allow-Methods` | `GET, POST, PUT, DELETE, OPTIONS` |
| `Access-Control-Allow-Headers` | `Content-Type, Authorization, X-Requested-With, Accept, Origin` |
| `Access-Control-Max-Age` | `86400` (24 hours) |
| `Access-Control-Expose-Headers` | `Content-Type, Authorization` |

### Preflight Handling

```java
handlePreflight(HttpServletRequest request, HttpServletResponse response)
→ boolean  // true if this was a preflight request (OPTIONS)
```

### Origin Validation

```java
isOriginAllowed(String origin)
```

Validates:
1. Not null/empty
2. No CRLF injection (`\r`, `\n`, `%0d`, `%0a`)
3. Valid URI with scheme and host

### Security Annotations

```java
@SuppressFBWarnings("HTTP_RESPONSE_SPLITTING")  // CRLF check handles this
@SuppressFBWarnings("PERMISSIVE_CORS")           // Origin reflection is intentional for OID4VP
```

**⚠️ This is a permissive CORS configuration** — it reflects any origin with credentials. This is acceptable for OID4VP because:
1. The wallet is a native app making cross-origin requests
2. The endpoint only accepts VP tokens bound to specific nonces
3. CSRF protection is via the nonce/state mechanism, not CORS

---

## 5. URLValidator

Validates URLs and redirect URIs.

### Allowed Schemes
```java
ALLOWED_SCHEMES = {"http", "https", "openid4vp"}
```

### Methods

```java
isValidURL(String url)
// Checks: not null, parseable URI, allowed scheme, has host

isValidRedirectUri(String uri, List<String> whitelist)
// isValidURL() + must match at least one whitelist entry

matchesBaseUrl(String uri, String baseUrl)
// Scheme must match + host must equal or be subdomain of base
// e.g., "https://app.example.com" matches base "https://example.com"
```

### Subdomain Matching Logic
```java
// uriHost.equals(baseHost)  → exact match
// uriHost.endsWith("." + baseHost)  → subdomain match
```

---

## 6. LogSanitizer

Prevents log injection attacks by sanitizing user-controlled input before logging.

```java
sanitize(String input)
// Replaces \n → _, \r → _

sanitize(String input, int maxLength)
// sanitize() + truncate to maxLength
```

---

## Utility Overlap Analysis

There's some functional overlap between utilities:

| Capability | SecurityUtils | OpenID4VPUtil | CORSUtil | URLValidator |
|---|---|---|---|---|
| Nonce generation | ✅ (core) | ✅ (delegates) | — | — |
| URL validation | ✅ `isValidUrl()` | — | — | ✅ `isValidURL()` |
| Origin validation | — | — | ✅ `isOriginAllowed()` | — |
| DID validation | ✅ `isValidDID()` | — | — | — |
| Redirect URI safety | ✅ `isSafeRedirectUri()` | — | — | ✅ `isValidRedirectUri()` |
| Log sanitization | ✅ `sanitizeForLogging()` | — | — | — |
| Log injection prev. | — | — | — | — |

The `LogSanitizer` utility in this common module and `SecurityUtils.sanitizeForLogging()` serve similar but distinct purposes:
- `LogSanitizer.sanitize()` — Removes CRLF (log injection)
- `SecurityUtils.sanitizeForLogging()` — Masks sensitive data

---

## Code Review Notes

| Issue | Severity | Details |
|---|---|---|
| **Hardcoded ngrok URL in `OpenID4VPUtil.getBaseUrl()`** | **Critical** | Must be removed before production. Should throw an exception if no server URL is configured. |
| **`SecurityUtils` + `URLValidator` overlap** | Medium | Both validate URLs but with different logic. `SecurityUtils.isValidUrl()` uses URI parsing, `URLValidator.isValidURL()` uses URI + scheme whitelist. Consolidate. |
| **`SecurityUtils.isSafeRedirectUri()` vs `URLValidator.isValidRedirectUri()`** | Medium | Two different redirect URI validators. `SecurityUtils` checks HTTPS + no fragments. `URLValidator` checks whitelist. They should compose. |
| **Permissive CORS in `CORSUtil`** | Medium | Reflects any origin with credentials. While justified for OID4VP, should be configurable or restricted to known wallet origins in production. |
| **No rate limiting utilities** | Info | `SecurityUtils` validates sizes but there's no request rate limiting utility. |
| **`PresentationDefinitionUtil` creates new `Gson` instances** | Low | Multiple methods create `new Gson()` or `new GsonBuilder().create()`. Cache as static final field. |
| **`SecurityUtils.DID_PATTERN` too permissive** | Low | `^did:[a-z]+:[a-zA-Z0-9._%-]+.*$` — the trailing `.*` allows any characters after the method-specific identifier. May be intentional for DID method flexibility. |
| **`CORSUtil` allows all HTTP methods** | Low | `GET, POST, PUT, DELETE, OPTIONS` — OID4VP only needs `GET`, `POST`, and `OPTIONS`. |
| **No `private` constructor on utility classes** | Low | Utility classes with all static methods should have `private` constructors to prevent instantiation. |
