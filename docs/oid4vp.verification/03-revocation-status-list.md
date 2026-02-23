# 03 — Revocation & Status List Service

This document covers `StatusListService.java` (interface, ~100 lines) and `StatusListServiceImpl.java` (implementation, 441 lines) — the credential revocation checking layer.

---

## Interface: StatusListService

| Method | Purpose |
|---|---|
| `checkRevocationStatus(CredentialStatus)` | Auto-detect status type and check |
| `checkStatusList2021(url, index, purpose)` | Check StatusList2021 specifically |
| `checkBitstringStatusList(url, index, purpose)` | Check BitstringStatusList specifically |
| `fetchAndDecodeStatusList(url)` | Fetch + decode status list to byte array |
| `isBitSet(bitstring, index)` | Check a single bit in the decoded bitstring |
| `clearCache()` | Clear cached status lists |
| `isRevocationCheckEnabled()` | Feature flag check |

---

## Supported Revocation Mechanisms

### 1. StatusList2021 (W3C CCG)

The [StatusList2021](https://www.w3.org/community/reports/credentials/CG-FINAL-vc-status-list-2021-20230102/) spec defines a bitstring-based revocation mechanism:

1. Each credential has a `credentialStatus` field with:
   - `type`: `"StatusList2021Entry"` or `"StatusList2021"`
   - `statusListCredential`: URL to a status list credential
   - `statusListIndex`: Bit position in the list
   - `statusPurpose`: `"revocation"` or `"suspension"`

2. The status list credential contains a GZIP-compressed, Base64-encoded bitstring
3. If the bit at `statusListIndex` is **set (1)**, the credential is revoked/suspended

### 2. BitstringStatusList (W3C VC)

The newer [BitstringStatusList](https://www.w3.org/TR/vc-bitstring-status-list/) uses the same concept with slightly different type names:
- `type`: `"BitstringStatusListEntry"` or `"BitstringStatusList"`

In this implementation, BitstringStatusList **delegates to the same code** as StatusList2021:
```java
public RevocationCheckResult checkBitstringStatusList(...) {
    return checkStatusList2021(...);  // Same mechanism
}
```

---

## Implementation: StatusListServiceImpl

### Feature Flag

```java
private boolean revocationCheckEnabled = true;
```

When disabled, all checks return `RevocationCheckResult.skipped("Revocation checking is disabled")`.

### Main Entry Point: `checkRevocationStatus`

```
credentialStatus
    │
    ├── status is null/blank → SKIPPED
    │
    ├── type is "StatusList2021Entry" or "StatusList2021"
    │   └── checkStatusList2021FromCredentialStatus()
    │       ├── Extract statusListCredential URL
    │       ├── Extract statusListIndex (parse int)
    │       ├── Extract statusPurpose (default: "revocation")
    │       └── checkStatusList2021(url, index, purpose)
    │
    ├── type is "BitstringStatusListEntry" or "BitstringStatusList"
    │   └── checkBitstringStatusListFromCredentialStatus()
    │       └── Same flow as above → delegates to checkStatusList2021()
    │
    └── Unknown type → UNKNOWN("Unsupported status type: ...")
```

### Fetch and Decode Pipeline

```
1. Check cache (ConcurrentHashMap)
   └── If cached + not expired → return cached bitstring

2. Fetch status list credential
   └── fetchStatusListCredential(url)
       ├── HTTP GET with Accept: application/vc+ld+json, application/json
       ├── Timeout: 10,000ms (connect + read)
       └── Read response body as UTF-8 string

3. Extract encoded list
   └── extractEncodedList(credentialJson)
       ├── Parse JSON
       ├── If has "vc" key → unwrap (JWT-wrapped credential)
       ├── Get credentialSubject (object or first element of array)
       └── Extract "encodedList" string

4. Decode status list
   └── decodeStatusList(encodedList)
       ├── Base64 decode → compressed bytes
       └── GZIP decompress → raw bitstring

5. Cache the result
   └── statusListCache.put(url, new CachedStatusList(bitstring))

6. Return bitstring
```

### Bit Checking

```java
public boolean isBitSet(byte[] bitstring, int index) {
    int byteIndex = index / 8;
    int bitIndex = index % 8;
    int mask = 1 << (7 - bitIndex);     // MSB first
    return (bitstring[byteIndex] & mask) != 0;
}
```

**Bit ordering**: MSB first within each byte (matching the W3C StatusList2021 spec).

### Result Interpretation

| Bit Value | Status Purpose | Result |
|---|---|---|
| 0 (not set) | Any | `VALID` ("Credential is not revoked") |
| 1 (set) | `"suspension"` | `SUSPENDED` ("Credential is suspended") |
| 1 (set) | Other / `"revocation"` | `REVOKED` ("Credential is revoked") |

---

## Caching

### Cache Implementation

```java
private final Map<String, CachedStatusList> statusListCache = new ConcurrentHashMap<>();
```

| Setting | Value |
|---|---|
| Backend | `ConcurrentHashMap<String, CachedStatusList>` |
| Key | Status list credential URL |
| Value | Decoded bitstring + creation timestamp |
| TTL | 5 minutes (`CACHE_TTL_MS = 300,000`) |
| Eviction | Lazy (checked on read, no background cleanup) |
| Max size | Unbounded ⚠️ |

### Cache Entry

```java
private static class CachedStatusList {
    private final byte[] bitstring;
    private final long createdAt;

    boolean isExpired() {
        return System.currentTimeMillis() - createdAt > CACHE_TTL_MS;
    }
}
```

---

## HTTP Behavior

`fetchStatusListCredential(url)`:
- Method: `GET`
- Accept: `application/vc+ld+json, application/json`
- Connect timeout: 10,000ms
- Read timeout: 10,000ms
- Buffer: 4096 bytes
- On non-200: throws `RevocationCheckException.networkError()`
- `@SuppressFBWarnings("URLCONNECTION_SSRF_FD")` — acknowledges SSRF risk

---

## How It Integrates with VCVerificationService

```java
// In VCVerificationServiceImpl.isRevoked():
RevocationCheckResult result = statusListService.checkRevocationStatus(status);

if (result.getStatus() == RevocationCheckResult.Status.SKIPPED ||
    result.getStatus() == RevocationCheckResult.Status.UNKNOWN) {
    return false;  // Treat as not revoked
}

return result.getStatus() == RevocationCheckResult.Status.REVOKED ||
       result.getStatus() == RevocationCheckResult.Status.SUSPENDED;
```

**Key behavior**: `SKIPPED` and `UNKNOWN` are treated as **not revoked**. Only explicit `REVOKED` or `SUSPENDED` status returns `true`.

---

## WSO2 IS Storage Integration

The `StatusListServiceImpl` does **not** use WSO2 IS storage directly. It:
- Fetches status lists via **HTTP** from external issuer endpoints
- Caches decoded bitstrings in **in-memory** `ConcurrentHashMap`
- Has no database interaction

The revocation check feature flag (`revocationCheckEnabled`) is set programmatically — it is not read from `identity.xml`. The config key `OpenID4VP.RevocationCheckEnabled` exists in `OpenID4VPConstants` but is consumed by `OpenID4VPUtil` in the common module, not by `StatusListServiceImpl` directly.

---

## Code Review Notes

| Issue | Severity | Details |
|---|---|---|
| **Unbounded cache** | High | `statusListCache` has no maximum size limit. A malicious issuer could force the verifier to cache thousands of status lists, causing OOM. Should use `OpenID4VPConstants.Defaults.DEFAULT_MAX_CACHE_SIZE`. |
| **No cache eviction** | Medium | Expired entries are only evicted on read (lazy). No background cleanup thread. Stale entries accumulate until read or `clearCache()`. |
| **SSRF via status list URL** | Medium | `fetchStatusListCredential` makes HTTP requests to arbitrary URLs from the credential's `statusListCredential` field. An attacker could craft a VC with an internal URL (e.g., `http://localhost:8080/admin`) to probe internal services. |
| **No status list credential verification** | Medium | The fetched status list credential JSON is parsed but its **signature is not verified**. An attacker who controls the URL could serve a forged status list that marks all credentials as valid. |
| **Cached bitstring is not defensively copied** | Low | `getBitstring()` returns the raw array reference. If the caller modifies it, the cache is corrupted. |
| **`extractEncodedList` only supports `encodedList`** | Low | BitstringStatusList uses `encodedList` field but older specs or custom implementations might use different field names. The method doesn't check for alternatives. |
| **No validation of bitstring minimum size** | Info | Commented-out code for minimum bitstring size validation. The spec recommends a minimum of 16KB (131,072 bits) to prevent status list fingerprinting. |
| **HTTP timeout is 10s** | Info | `HTTP_TIMEOUT_MS = 10000`. This is on the high side for a synchronous verification flow. Consider 5s or making it configurable. |
