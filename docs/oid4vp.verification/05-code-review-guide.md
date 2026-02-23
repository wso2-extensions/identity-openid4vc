# 05 — Code Review Guide

---

## Overview

This document aggregates all code review findings across the `oid4vp.verification` module. Items are grouped by severity and category.

---

## Critical Issues

### 1. Non-DID/Non-URL Issuers Skip Signature Verification

**File**: `VCVerificationServiceImpl.java` → `verifyJwtSignature()`

```java
// For non-DID, non-URL issuers we cannot verify without additional configuration
return true;
```

If the issuer field is neither a DID nor a URL (e.g., a plain string like `"MyIssuer"`), the signature verification is **silently skipped** and returns `true`. This means a credential with a non-standard issuer identifier will always pass signature verification regardless of whether the signature is valid.

**Recommendation**: Return `false` or throw `CredentialVerificationException("Cannot verify signature for non-DID, non-URL issuer")`.

---

### 2. Ed25519 Linked Data Signature Hashes Document Before Verification

**File**: `SignatureVerifier.java` → `verifyEd25519Signature()`

```java
byte[] documentHash = hashDocument(document, "SHA-256");
Signature sig = Signature.getInstance("EdDSA");
sig.initVerify(publicKey);
sig.update(documentHash);  // ← feeding hash, not raw document
return sig.verify(signatureBytes);
```

Ed25519 (RFC 8032) **internally performs SHA-512** on the input. The Ed25519Signature2020 proof suite specifies a specific canonicalization + hashing process. Pre-hashing with SHA-256 produces an incorrect verification input — signatures from spec-compliant issuers will likely **fail to verify**.

**Recommendation**: Feed the canonicalized document directly to `sig.update()` without pre-hashing, or implement the full [Ed25519Signature2020](https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/) algorithm.

---

### 3. VCVerificationServiceImpl Is a 1637-Line God Class

**File**: `VCVerificationServiceImpl.java`

This single class handles:
- Credential parsing (JWT, SD-JWT, JSON-LD)
- Signature verification routing
- Expiration checking
- Revocation status checking
- JWKS URI resolution via HTTP
- SD-JWT full verification pipeline
- Presentation parsing
- Claims vs. PD constraint checking
- Nonce verification
- Date parsing utilities

**Recommendation**: Decompose into focused classes:
- `VCParser` — credential/presentation parsing
- `SdJwtVerifier` — SD-JWT specific logic
- `JwksResolver` — JWKS URI discovery
- `VCVerificationServiceImpl` — orchestration only

---

## High Severity Issues

### 4. Unbounded Status List Cache

**File**: `StatusListServiceImpl.java`

```java
private final Map<String, CachedStatusList> statusListCache = new ConcurrentHashMap<>();
```

No maximum size. An attacker could craft VCs pointing to thousands of different status list URLs, causing the cache to grow without bound until OOM.

**Recommendation**: Use a bounded cache (LRU) or use `OpenID4VPConstants.Defaults.DEFAULT_MAX_CACHE_SIZE` (1000).

---

### 5. Status List Credential Is Not Signature-Verified

**File**: `StatusListServiceImpl.java` → `fetchAndDecodeStatusList()`

The fetched status list credential JSON is parsed for its `encodedList` field, but its **cryptographic signature is never verified**. An attacker who controls the status list URL (via DNS poisoning, MITM, or crafted VC) could serve a forged status list.

**Recommendation**: Verify the status list credential's JWT signature or JSON-LD proof before trusting its contents.

---

### 6. SD-JWT KB Verification Assumes EC Key Type

**File**: `VCVerificationServiceImpl.java` → `verifySdJwtToken()`

```java
com.nimbusds.jose.jwk.JWK holderKey = com.nimbusds.jose.jwk.JWK.parse(jwkMap);
com.nimbusds.jose.JWSVerifier verifier = 
    new DefaultJWSVerifierFactory()
        .createJWSVerifier(kbJwt.getHeader(), holderKey.toECKey().toPublicKey());
```

`holderKey.toECKey()` will throw a `ClassCastException` if the holder's key is RSA or OKP (EdDSA). The `DefaultJWSVerifierFactory` already handles all key types — just pass the generic key.

**Recommendation**: 
```java
PublicKey holderPublicKey = holderKey.toPublicKey();  // Generic
```

---

## Medium Severity Issues

### 7. SSRF via Status List and JWKS URLs

**Files**: `StatusListServiceImpl.java`, `VCVerificationServiceImpl.java`

Both `fetchStatusListCredential()` and `fetchJson()` make HTTP requests to URLs derived from untrusted credential fields. An attacker could:
- Probe internal services (`http://localhost:8080/admin`)
- Scan internal networks (`http://10.0.0.1:22`)
- Exfiltrate data via DNS queries

Both methods have `@SuppressFBWarnings("URLCONNECTION_SSRF_FD")` annotations, acknowledging the risk.

**Recommendation**: Implement URL allowlisting or at minimum block private/internal IP ranges (RFC 1918, RFC 4193, loopback, link-local).

---

### 8. Revocation Check Failure Is Silently Swallowed

**File**: `VCVerificationServiceImpl.java` → `verifyCredentialInternal()`

```java
try {
    if (isRevoked(credential)) { ... }
} catch (CredentialVerificationException e) {
    // Continue without failing - revocation check is optional
}
```

If the revocation check endpoint is down or returns an error, the credential passes as if it were valid. No indication is provided in the result.

**Recommendation**: At minimum, set a flag on the result DTO (e.g., `revocationCheckSkipped = true`) so the consuming service can make an informed decision.

---

### 9. Custom Base58 Decoder

**File**: `SignatureVerifier.java` → `base58Decode()`

Hand-rolled Base58 implementation using `BigInteger` arithmetic. Crypto primitives should use well-tested libraries.

**Recommendation**: Use `org.bitcoinj.core.Base58` or BouncyCastle's implementation.

---

### 10. `extractAlgorithmFromHeader` Uses String Manipulation

**File**: `SignatureVerifier.java`

```java
if (headerJson.contains("\"alg\"")) {
    int start = headerJson.indexOf("\"alg\"") + 6;
    // Manual string index arithmetic...
}
```

Fragile string-based JSON parsing. Breaks with whitespace variations, different key ordering, or escaped characters.

**Recommendation**: Use `JsonParser.parseString(headerJson).getAsJsonObject().get("alg").getAsString()`.

---

### 11. No VP Token Size Validation in Submission Validator

**File**: `VPSubmissionValidator.java`

The common module defines `MAX_VP_TOKEN_SIZE = 1MB` in `SecurityUtils`, but `VPSubmissionValidator` doesn't check it. A wallet could submit an extremely large VP token.

**Recommendation**: Add `SecurityUtils.isValidVPTokenSize()` check in `validateVPToken()`.

---

### 12. `SimpleDateFormat` Usage

**File**: `VCVerificationServiceImpl.java` → `parseDate()`

Creates new `SimpleDateFormat` instances per call (5 formats × N calls). While thread-safe by fresh creation, it's inefficient.

**Recommendation**: Use `java.time.format.DateTimeFormatter` (immutable, thread-safe) or `java.time.Instant.parse()`.

---

## Low Severity Issues

### 13. `removeCRLF` Duplicated in Two Classes

**Files**: `VCVerificationServiceImpl.java`, `SignatureVerifier.java`

Both have identical `removeCRLF()` methods. Should use `LogSanitizer.sanitize()` from the common module.

---

### 14. `processDisclosures` Swallows All Exceptions

**File**: `VCVerificationServiceImpl.java`

```java
try { ... } catch (Exception e) { }  // Empty catch block
```

Malformed SD-JWT disclosures are silently ignored. At minimum, log a debug message.

---

### 15. Incomplete `validateSubmissionMatchesDefinition`

**File**: `VPSubmissionValidator.java`

Only checks `definition_id` match. Does not verify that all required input descriptors from the PD have corresponding entries in the descriptor map.

---

### 16. JSONPath Validation Is Minimal

**File**: `VPSubmissionValidator.java` → `isValidJsonPath()`

```java
return path.startsWith("$") || path.startsWith("@");
```

Only checks the first character. `$[invalid_syntax!!!` would pass.

---

### 17. `parseJwtPart` Returns Double for Integer Claims

**File**: `VCVerificationServiceImpl.java`

Gson deserializes all JSON numbers as `Double`. The `exp` claim is extracted as:
```java
long exp = ((Number) payload.get("exp")).longValue();
```

Works but could lose precision for very large numbers.

---

### 18. `Bundle-RequiredExecutionEnvironment` Is `JavaSE-11` but Compiler Target Is 21

**File**: `pom.xml`

```xml
<Bundle-RequiredExecutionEnvironment>JavaSE-11</Bundle-RequiredExecutionEnvironment>
<!-- but -->
<source>21</source>
<target>21</target>
```

---

## Informational / Positive Patterns

| Pattern | Where | Assessment |
|---|---|---|
| Constructor injection for testability | `VCVerificationServiceImpl` (3 constructors) | ✅ Good — enables mocking |
| Timing-safe comparison for nonce/audience | `verifySdJwtToken()` uses `MessageDigest.isEqual()` | ✅ Prevents timing attacks |
| CRLF injection prevention in logs | Multiple methods sanitize before logging | ✅ Prevents log injection |
| Private constructor on utility class | `VPSubmissionValidator` | ✅ Correct static utility pattern |
| Lazy format auto-detection | `detectFormat()` | ✅ Handles generic `application/json` input |
| SpotBugs annotations | Explicit `@SuppressFBWarnings` with documented reasons | ✅ Good security documentation |
| `RemoteJWKSet` caching | `ExtendedJWKSValidator` | ✅ Nimbus handles JWKS caching automatically |
| Cached Gson instance | `private static final Gson GSON` | ✅ Avoids per-call creation |
| Comprehensive format support | JWT, SD-JWT, JSON-LD, VP arrays | ✅ Covers all OID4VP formats |

---

## Test Coverage Assessment

| Test File | Lines | Tests | Coverage |
|---|---|---|---|
| `VCVerificationServiceTest.java` | 122 | 5 tests | Parsing (JWT, SD-JWT, JSON-LD), expiry |
| `SignatureVerifierTest.java` | 73 | 3 tests | Input validation only |
| `VPSubmissionValidatorTest.java` | 78 | 7 tests | Null/missing field validation |

**Total**: 15 tests across 273 lines.

### Coverage Gaps

| Area | Tested | Gap |
|---|---|---|
| Credential parsing | ✅ | — |
| Expiration checking | ✅ | — |
| JWT signature verification | ❌ | No valid signature test vectors |
| SD-JWT full verification | ❌ | Not tested at all |
| JSON-LD signature verification | ❌ | Not tested at all |
| Revocation checking | ❌ | Not tested at all |
| JWKS URI resolution | ❌ | Not tested at all |
| VP presentation parsing | ❌ | Not tested |
| Nonce verification | ❌ | Not tested |
| PD constraint checking | ❌ | Not tested |
| `ExtendedJWKSValidator` | ❌ | No tests at all |
| `StatusListServiceImpl` | ❌ | No tests at all |
| Error handling paths | Partial | Only null/missing params |

**Recommendation**: Add integration tests with valid test vectors for each credential format. The existing tests only cover input validation and parsing — no actual cryptographic verification is tested.

---

## Security Checklist

| Check | Status | Notes |
|---|---|---|
| JWT signature verification (RSA) | ✅ | Via Nimbus `RSASSAVerifier` |
| JWT signature verification (EC) | ✅ | Via Nimbus `ECDSAVerifier` |
| JWT signature verification (EdDSA) | ⚠️ | JCA fallback, untested |
| SD-JWT issuer signature | ✅ | Delegates to JWT path |
| SD-JWT disclosure integrity | ✅ | SHA-256 digest matching |
| SD-JWT key binding (nonce) | ✅ | Timing-safe comparison |
| SD-JWT key binding (audience) | ✅ | Timing-safe comparison |
| SD-JWT sd_hash verification | ✅ | SHA-256 integrity check |
| JSON-LD Ed25519 signatures | ❌ | Pre-hashing bug (see #2) |
| Revocation (StatusList2021) | ⚠️ | Works but status list not verified |
| VP token format validation | ✅ | Comprehensive format detection |
| Input size limits | ⚠️ | Not enforced in validator |
| SSRF protection | ❌ | No URL allowlisting |
| Log injection | ✅ | CRLF removal |
| Timing attacks | ✅ | `MessageDigest.isEqual()` |
| Error information leakage | ✅ | Exceptions don't leak internal details |

---

## Dependency Risk Assessment

| Dependency | Risk | Notes |
|---|---|---|
| Nimbus JOSE+JWT | Low | Industry-standard JWT library, well-maintained |
| Gson | Low | Mature JSON library, used throughout WSO2 IS |
| json-path 2.4.0 | Medium | Version is from 2018. Current is 2.9+. Known CVEs in older versions. **Embedded in bundle**. |
| json-smart 2.3 | Medium | Transitive dependency. Known CVEs in older versions. **Embedded in bundle**. |
| Custom Base58 | Medium | Hand-rolled crypto primitive. Should use proven library. |

**Recommendation**: Upgrade `json-path` and `json-smart` to latest stable versions.
