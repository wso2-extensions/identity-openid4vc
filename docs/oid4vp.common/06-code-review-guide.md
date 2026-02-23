# 06 — Code Review Guide

---

## Overview

This document aggregates all code review findings across the `oid4vp.common` module. Items are grouped by severity and category.

---

## Critical Issues (fixed)

### 1. Hardcoded ngrok URL in Production Code

**File**: `OpenID4VPUtil.java` → `getBaseUrl()`

```java
// Fallback — development leftover
return "https://masked-unprofitably-ardith.ngrok-free.dev";
```

**Impact**: If `OpenID4VP.ServerUrl` is not configured in `identity.xml`, the system silently falls back to an external ngrok tunnel URL. This would:
- Route VP tokens to an uncontrolled external endpoint
- Expose authentication data over an untrusted channel
- Break silently in production

**Recommendation**: Remove the hardcoded fallback. Throw `IllegalStateException` if the server URL is not configured:
```java
String serverUrl = IdentityUtil.getProperty("OpenID4VP.ServerUrl");
if (StringUtils.isBlank(serverUrl)) {
    throw new IllegalStateException("OpenID4VP.ServerUrl must be configured in identity.xml");
}
return serverUrl;
```

---

### 2. Private Key Material in Raw byte[]

**File**: `DIDKey.java`

Private keys are stored as `byte[]` with defensive cloning. While the cloning prevents accidental mutation, the raw bytes remain in heap memory and are subject to:
- Heap dump exposure
- GC-delayed cleanup (no zeroing after use)
- No encryption at rest in memory

**Recommendation**: Use `java.security.KeyStore` for private key storage. If byte arrays are needed, zero them after use with `Arrays.fill(key, (byte) 0)`.

---

## High Severity Issues (fixed)

### 3. DIDDocumentException Breaks Exception Hierarchy

**File**: `DIDDocumentException.java`

```java
public class DIDDocumentException extends Exception {  // Should extend VPException
```

All other domain exceptions extend `VPException`, but `DIDDocumentException` extends `Exception` directly. This means:
- `catch (VPException e)` blocks won't catch DID document errors
- No `errorCode` field available for structured error responses
- Inconsistent error handling patterns

**Recommendation**: Change to `extends VPException` with an appropriate error code.

---

### 4. VPRequest Has Both Builder and Public Setters

**File**: `VPRequest.java`

The class uses a Builder pattern (suggesting immutability) but also has public setters. This creates confusion:
- Callers may mutate objects after construction via Builder
- Thread safety is compromised
- The Builder pattern's value is undermined

**Recommendation**: Either remove setters (make fully immutable via Builder) or remove Builder (use mutable POJO pattern consistently).

---

## Medium Severity Issues

### 5. Duplicate URL Validation Logic

**Files**: `SecurityUtils.java`, `URLValidator.java`

Two separate URL validation approaches:
| Method | Logic |
|---|---|
| `SecurityUtils.isValidUrl()` | URI parse + length check |
| `URLValidator.isValidURL()` | URI parse + scheme whitelist + host check |
| `SecurityUtils.isSafeRedirectUri()` | HTTPS-only + no fragments |
| `URLValidator.isValidRedirectUri()` | Whitelist-based matching |

**Recommendation**: Consolidate into a single `URLValidator` class. `SecurityUtils` should delegate to it.

---

### 6. Permissive CORS Configuration

**File**: `CORSUtil.java`

Reflects any `Origin` header with `Access-Control-Allow-Credentials: true`. The SpotBugs suppressions acknowledge this:
```java
@SuppressFBWarnings("PERMISSIVE_CORS")
```

While justified for OID4VP wallet interactions, this is overly permissive for a production identity server.

**Recommendation**: Make allowed origins configurable via `identity.xml`. Default to restrictive and require explicit opt-in.

---

### 7. Signing Algorithm Default Mismatch

**Files**: `OpenID4VPConstants.Defaults`, `OpenID4VPUtil.java`

The default signing algorithm in constants is `EdDSA`, but the `PresentationDefinitionUtil.buildInputDescriptor()` hardcodes `ES256` and `ES384`:
```java
// In OpenID4VPConstants.Defaults
DEFAULT_SIGNING_ALGORITHM = "EdDSA"

// In PresentationDefinitionUtil
algArray.add("ES256");
algArray.add("ES384");
// No EdDSA!
```

**Recommendation**: Align the algorithms or make the PD builder configurable.

---

### 8. Inconsistent DTO Validation

Some DTOs have `isValid()` methods, others don't:

| DTO | Has Validation |
|---|---|
| `VPSubmissionDTO` | ✅ `isValid()` |
| `VPRequestCreateDTO` | ✅ `isValid()` |
| `PresentationSubmissionDTO` | ✅ `isValid()` |
| `DescriptorMapDTO` | ✅ `isValid()` |
| `AuthorizationDetailsDTO` | ❌ |
| `VPResultDTO` | ❌ |
| `VCVerificationResultDTO` | ❌ |
| `ErrorDTO` | ❌ |
| `PresentationDefinitionResponseDTO` | ❌ |

**Recommendation**: Add validation to all DTOs that are deserialized from external input. At minimum, `AuthorizationDetailsDTO` needs validation (it's constructed from query parameters).

---

### 9. No Null Safety on Gson Deserialization

**Across all DTOs**

Gson silently sets missing fields to `null`. No `@NonNull` annotations or post-deserialization validation is applied except where `isValid()` exists.

**Recommendation**: Add a common `validate()` method or use a validation framework (Bean Validation / JSR 380).

---

### 10. Error Code Strings Are Not Constants

**Files**: `DIDResolutionException.java`, `RevocationCheckException.java`

Error codes are hardcoded strings in static factory methods:
```java
return new DIDResolutionException("UNSUPPORTED_METHOD", "...", null, null, method);
return new RevocationCheckException("NETWORK_ERROR", "...", cause, url, -1, null);
```

**Recommendation**: Define these as constants in `OpenID4VPConstants.ErrorCodes` or use an enum.

---

## Low Severity Issues

### 11. PresentationDefinitionResponseDTO Is 400+ Lines

Single file contains 7 nested inner classes. Hard to navigate and maintain.

**Recommendation**: Extract inner DTOs to separate files in a `dto.pd` sub-package.

---

### 12. Gson Instance Creation Per Call

**Files**: `PresentationDefinitionUtil.java`, `VPStatusResponseDTO.java`

Multiple places create `new Gson()` or `new GsonBuilder().create()` per method call.

**Recommendation**: Cache as `private static final Gson GSON = new Gson()`.

---

### 13. VCVerificationResultDTO Duplicates credentialType

Has both `credentialType` (String) and `credentialTypes` (String[]). The singular is always `credentialTypes[0]`.

**Recommendation**: Remove `credentialType` and add `getPrimaryType()` convenience method.

---

### 14. Date Fields Use java.util.Date

**Files**: `VerifiableCredential.java`, `VerifiablePresentation.java`

Uses mutable `java.util.Date` with defensive copying (`new Date(date.getTime())`).

**Recommendation**: Migrate to `java.time.Instant` which is immutable and doesn't need defensive copies.

---

### 15. SecurityUtils.DID_PATTERN Trailing Wildcard

```java
DID_PATTERN = "^did:[a-z]+:[a-zA-Z0-9._%-]+.*$"
```

The `.*` at the end allows any characters after the method-specific identifier. This may be intentional for DID method flexibility (e.g., paths, queries, fragments in DIDs) but could also accept malformed DIDs.

---

### 16. CORSUtil Allows Unnecessary HTTP Methods

Allows `PUT` and `DELETE` in `Access-Control-Allow-Methods`, but OID4VP only needs `GET`, `POST`, and `OPTIONS`.

---

### 17. No Private Constructors on Utility Classes

`SecurityUtils`, `OpenID4VPUtil`, `PresentationDefinitionUtil`, `CORSUtil`, `URLValidator`, `LogSanitizer` — all have all-static methods but no private constructors to prevent instantiation.

---

### 18. Defensive Copying Creates GC Pressure

`DIDDocument`, `VerifiableCredential`, `VerifiablePresentation` create new `ArrayList<>` / `HashMap<>` copies in every getter call. Correct for thread safety but generates garbage on hot paths.

**Recommendation**: Use `Collections.unmodifiableList()` with lazy caching if performance becomes an issue.

---

## Informational / Positive Patterns

| Pattern | Where | Assessment |
|---|---|---|
| Builder pattern | VPRequest, VPSubmission, PresentationDefinition, TrustedVerifier, RevocationCheckResult, VCVerificationResultDTO, VPStatusResponseDTO | ✅ Good for complex construction |
| Static factory methods on exceptions | DIDResolutionException, RevocationCheckException | ✅ Readable, self-documenting |
| Defensive deep copy on JsonObject | AuthorizationDetailsDTO, VPRequestCreateDTO | ✅ Prevents mutation bugs |
| Copy constructors on PD inner DTOs | All PresentationDefinitionResponseDTO inner classes | ✅ Full deep copy chain |
| SecureRandom for cryptographic values | SecurityUtils, OpenID4VPUtil | ✅ Correct CSPRNG usage |
| Constant-time comparison | SecurityUtils.constantTimeEquals() | ✅ Prevents timing attacks |
| CRLF injection check in CORS | CORSUtil.isOriginAllowed() | ✅ Prevents HTTP response splitting |
| Base64URL without padding | SecurityUtils.generateNonce/State | ✅ URL-safe tokens |
| VP token size limit | SecurityUtils.isValidVPTokenSize() (1MB) | ✅ DoS protection |
| `@SerializedName` throughout DTOs | All DTOs | ✅ Clean JSON mapping |

---

## Security Checklist

| Check | Status | Notes |
|---|---|---|
| Nonce generation (CSPRNG) | ✅ | SecureRandom, 32 bytes |
| State generation (CSPRNG) | ✅ | SecureRandom, 16 bytes |
| Timing-safe comparison | ✅ | `constantTimeEquals()` |
| Input validation (DID, URL, nonce, state) | ✅ | Regex + length limits |
| VP token size limit | ✅ | 1 MB max |
| JWT structure validation | ✅ | `isWellFormedJWT()` |
| Redirect URI safety | ⚠️ | Two overlapping validators |
| CORS security | ⚠️ | Permissive, reflects any origin |
| Log injection prevention | ✅ | LogSanitizer + SecurityUtils |
| Private key storage | ❌ | Raw byte[] in DIDKey |
| Hardcoded secrets/URLs | ❌ | ngrok URL in getBaseUrl() |
| Error code consistency | ⚠️ | Hardcoded strings, no enum |
| Multi-tenancy isolation | ✅ | `tenantId` on all persistent models |

---

## Dependency Review

| Dependency | Version | Purpose | Risk |
|---|---|---|---|
| `com.google.code.gson` | (from parent) | JSON serialization | Low — widely used, stable |
| `org.wso2.carbon.identity.core` | (from parent) | `IdentityUtil` config | Low — WSO2 internal |
| `commons-lang3` | (from parent) | `StringUtils` | Low — Apache standard |
| `javax.servlet-api` | (provided) | HTTP request/response | Low — standard API |
| `slf4j-api` | (from parent) | Logging | Low — standard API |

No external VC/DID-specific libraries — all W3C VC/DID model parsing is custom-built. This is a deliberate design choice that gives full control but increases maintenance burden.
