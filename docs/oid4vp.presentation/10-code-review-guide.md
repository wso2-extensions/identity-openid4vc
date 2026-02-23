# 10 — Code Review Guide

> Consolidated review findings from all documentation files (01–09).
> Organized by severity: **Critical → High → Medium → Low**.

---

## Critical Issues

### C-1: No VP Token Signature Verification

**File**: `VPResponseHandler.java`
**Impact**: An attacker can craft arbitrary VP tokens with fake claims.

The handler **parses** the JWT and extracts claims but never verifies the signature. There is a `// TODO` comment acknowledging this gap:

```java
// TODO: Verify the VP token signature
SignedJWT signedJWT = SignedJWT.parse(vpToken);
// proceeds directly to claim extraction
```

**Fix**: Use `nimbus-jose-jwt`'s `JWSVerifier` with the wallet's public key (resolved from DID) to verify the VP's signature. Also verify each nested VC's signature against the issuer's key.

---

### C-2: No Servlet Authentication / Authorization

**Files**: All 8 servlet classes in `servlet/` package
**Impact**: Any HTTP client can access all endpoints without authentication.

The servlets are registered via `HttpService.registerServlet()` without filters or guards. Endpoints like `/presentation-definitions` (CRUD) and `/vc-verification` should require admin or service-account authentication.

**Fix**: Add servlet filters, or use WSO2 IS's built-in authentication framework for REST endpoints. At minimum, admin-facing endpoints should require OAuth2 Bearer tokens.

---

### C-3: No Cluster / HA Support

**Files**: `VPRequestCache.java`, `VPStatusListenerCache.java`, `WalletDataCache.java`, `LongPollingManager.java`
**Impact**: Fails in multi-node deployments. If the wallet submits to node B but the browser polls node A, authentication never completes.

All VP request state is stored in JVM-local `ConcurrentHashMap` instances. There is no replication, no shared database backing for VP requests, and `CountDownLatch`-based long polling is inherently single-JVM.

**Fix**: Use a distributed cache (Hazelcast, Redis, or WSO2 IS's built-in distributed caching) for VP request state. Replace `CountDownLatch` with a pub/sub mechanism for cross-node notifications.

---

### C-4: Hardcoded Demo DID

**File**: `OpenID4VPAuthenticator.java`
**Impact**: All requests use the same ngrok-based DID in production if not overridden.

```java
private static final String DEFAULT_VERIFIER_DID = "did:web:xxxx-xxx.ngrok-free.app";
```

This DID is used as the `client_id` and issuer of the authorization request JWT. If the IDP's authenticator config doesn't explicitly set `verifierDID`, this demo value is used.

**Fix**: Make `verifierDID` a required field. Fail fast if not configured.

---

## High-Priority Issues

### H-1: Mutable State in Authenticator Singleton

**File**: `OpenID4VPAuthenticator.java`
**Impact**: Race conditions with concurrent authentication requests.

`OpenID4VPAuthenticator` is registered as a singleton OSGi service but implements `StatusCallback` with instance-level state for claim storage. If multiple users authenticate simultaneously, their claims can overlap.

**Fix**: Move per-request state to the authentication context (`AuthenticatorFlowStatus`) or a cache keyed by `sessionDataKey`.

---

### H-2: Double Notification on VP Submission

**File**: `VPSubmissionServlet.java`
**Impact**: Listeners may receive duplicate callbacks.

The servlet calls both:
1. `StatusNotificationService.notifyVPSubmitted()` — general listeners
2. `VPStatusListenerCache.notifyListeners()` — long-polling listeners

If a listener is registered in both, it receives two callbacks.

**Fix**: Consolidate notification into a single service. Have `StatusNotificationService` be the sole notification point and let it delegate to `VPStatusListenerCache` internally.

---

### H-3: No Input Validation on `state` Parameter

**File**: `VPSubmissionServlet.java`
**Impact**: Potential cache poisoning or DoS.

The `state` parameter from the wallet's `direct_post` is used directly as a cache key without format validation. An attacker could inject extremely long strings or special characters.

**Fix**: Validate that `state` is a valid UUID format before using it as a lookup key.

---

### H-4: SQL Injection Risk in DAO

**File**: `PresentationDefinitionDAOImpl.java`
**Impact**: Low (parameterized queries are used), but pattern is fragile.

The DAO uses `PreparedStatement` with `?` placeholders, which is correct. However, the `tenantId` is passed as an `int` and set directly. If future modifications add string concatenation, injection becomes possible.

**Fix**: Add a code review note to enforce parameterized queries. Consider using an ORM or query builder.

---

### H-5: Destructive Reads in WalletDataCache

**File**: `WalletDataCache.java`
**Impact**: If a cache read fails (e.g., network timeout between read and processing), data is permanently lost.

The `get*()` methods remove entries from the cache after reading (`map.remove(key)`). If the caller fails to process the data, it cannot be re-read.

**Fix**: Use a two-phase approach: read without removing, then explicitly delete after successful processing.

---

## Medium-Priority Issues

### M-1: Two Data Holder Singletons

**Files**: `OpenID4VCPresentationDataHolder.java`, `VPServiceDataHolder.java`
**Impact**: Confusion about which data holder to use. Risk of state inconsistency.

| Data Holder | Pattern | Fields |
|---|---|---|
| `OpenID4VCPresentationDataHolder` | Eager singleton | VPRequestService, PDService, AppMgmtService |
| `VPServiceDataHolder` | DCL singleton | All above + RealmService, VCVerificationService, DIDDocumentService |

**Fix**: Merge into one data holder. `VPServiceDataHolder` is the superset; deprecate and remove the other.

---

### M-2: Hardcoded Cache TTLs

**Files**: `VPRequestCache.java` (300s), `WalletDataCache.java` (300s for tokens, 600s for submissions)
**Impact**: Cannot tune performance without code changes.

**Fix**: Read TTLs from `openid4vp.properties` configuration. Fallback to defaults if not configured.

---

### M-3: Empty Catch Blocks / Silent Failures

**Files**: `VPServiceRegistrationComponent.java`, `VPServletRegistrationComponent.java`, various servlets
**Impact**: Activation failures, servlet errors, or configuration problems are silently swallowed.

Example in `VPServiceRegistrationComponent`:
```java
try {
    // entire activation logic
} catch (Throwable e) {
    // empty or minimal logging
}
```

**Fix**: Log at ERROR level with full stack trace. For activation failures, consider throwing to prevent bundle activation.

---

### M-4: Presentation Definition Validation is Shallow

**File**: `PresentationDefinitionServiceImpl.java`
**Impact**: Invalid PDs can be stored in the database and cause failures at authentication time.

Validation only checks that the JSON parses and contains an `input_descriptors` array. It doesn't validate:
- Required fields per OID4VP spec (`id`, `format`)
- JSON Path syntax in `constraints.fields[].path`
- Format support against configured VP formats

**Fix**: Add comprehensive OID4VP spec-compliant validation.

---

### M-5: StatusTransitionManager Not Enforced

**File**: `StatusTransitionManager.java` and all status update sites
**Impact**: Invalid state transitions can occur (e.g., EXPIRED → VP_SUBMITTED).

The state machine rules exist in `StatusTransitionManager` but are never called. Status is updated directly on `VPRequest` objects.

**Fix**: Route all status updates through `StatusTransitionManager.transitionStrict()`.

---

### M-6: TrustedVerifierService is In-Memory Only

**File**: `TrustedVerifierServiceImpl.java`
**Impact**: Trusted verifier configuration is lost on restart. Not used in the auth flow.

The service maintains a `ConcurrentHashMap` of trusted verifiers but has no DB backing. It's also not invoked from any authentication code path.

**Fix**: Either implement DB persistence and integrate into the auth flow, or remove the dead code.

---

### M-7: Duplicate Claim Extraction Logic

**Files**: `OpenID4VPAuthenticator.java`, `VPResponseHandler.java`
**Impact**: Maintenance burden. Bug fixes must be applied in two places.

Both classes contain logic to extract `credentialSubject` claims from VP tokens, with slightly different approaches.

**Fix**: Consolidate claim extraction into `VPResponseHandler` and have the authenticator delegate to it.

---

### M-8: DELETE Endpoint Returns 405

**File**: `VPDefinitionServlet.java`
**Impact**: Cannot delete Presentation Definitions via REST API.

`doDelete()` explicitly returns `405 Method Not Allowed`. Deletion only happens via IDP lifecycle listener.

**Fix**: Either implement DELETE or document why it's disabled (e.g., referential integrity with IDPs).

---

## Low-Priority Issues

### L-1: No Pagination for Presentation Definition List

**File**: `VPDefinitionServlet.java`, `PresentationDefinitionDAOImpl.java`
**Impact**: `getAllPresentationDefinitions()` returns all rows. Performance degrades with scale.

**Fix**: Add `LIMIT` / `OFFSET` support.

---

### L-2: UUID.randomUUID() for Security Tokens

**Files**: Various (nonce, state, requestId generation)
**Impact**: `UUID.randomUUID()` uses `SecureRandom` on most JVMs but this is not guaranteed by the spec.

**Fix**: Use `SecureRandom` explicitly for security-sensitive values (nonce, state).

---

### L-3: Commented-Out ZXing Code in QRCodeUtil

**File**: `QRCodeUtil.java`
**Impact**: Dead code clutter.

**Fix**: Remove or implement.

---

### L-4: Static `sanitize()` Duplication

**Files**: `OpenID4VPIdentityProviderMgtListener.java`, various servlets
**Impact**: Same CRLF-injection sanitizer repeated in multiple files.

**Fix**: Move to a shared utility class in `oid4vp.common`.

---

### L-5: `wallet_login.jsp` Hardcoded Polling Interval

**File**: `wallet_login.jsp`
**Impact**: Cannot tune polling interval without modifying the JSP.

**Fix**: Read from a server-provided config value or make it a JSP parameter.

---

### L-6: Error Messages Leak Internal Details

**Files**: Various servlets
**Impact**: Error responses include class names, stack traces, or internal IDs.

**Fix**: Return generic error messages to the client. Log detailed errors server-side.

---

## Reviewer Checklist

### Security
- [ ] VP token signature verification implemented
- [ ] Servlet authentication/authorization added
- [ ] Input validation on all external parameters
- [ ] No information leakage in error responses
- [ ] CRLF injection protection on all logged values
- [ ] `state`, `nonce` generated with `SecureRandom`
- [ ] Demo/hardcoded values removed

### Thread Safety
- [ ] Authenticator singleton doesn't hold per-request state
- [ ] Cache operations are atomic (check-then-act patterns)
- [ ] `volatile` flag in `VPStatusListenerCache` doesn't race
- [ ] `CountDownLatch` properly handles spurious wakeups

### Architecture
- [ ] Single data holder class
- [ ] Single notification path for VP submission
- [ ] `StatusTransitionManager` enforced at all status update sites
- [ ] Claim extraction consolidated in one place
- [ ] Dead code removed (`TrustedVerifierService` if unused, ZXing comments)

### Clustering / HA
- [ ] VP request state in distributed cache or database
- [ ] Long-polling works across nodes
- [ ] Cache TTLs configurable from properties

### Spec Compliance (OID4VP)
- [ ] Presentation Definition validated per spec
- [ ] `direct_post` response mode fully implemented
- [ ] `client_id_scheme` handling (currently assumes `did`)
- [ ] VP token formats: JWT, JSON-LD, SD-JWT support
- [ ] Error responses follow OID4VP error codes

### Storage
- [ ] Presentation Definition CRUD fully functional (including DELETE)
- [ ] VP Request lifecycle managed (creation, submission, expiry, cleanup)
- [ ] Orphaned cache entries cleaned up
- [ ] Database connections properly closed (try-with-resources)

### Testing
- [ ] Unit tests for `VPResponseHandler` claim extraction
- [ ] Unit tests for `StatusTransitionManager` transitions
- [ ] Integration test for full auth flow
- [ ] Test concurrent VP submissions
- [ ] Test cache expiry and cleanup

---

## Summary Table

| Severity | Count | Key Themes |
|---|---|---|
| **Critical** | 4 | No signature verification, no auth on servlets, no HA, hardcoded DID |
| **High** | 5 | Mutable singleton state, double notification, missing input validation |
| **Medium** | 8 | Duplicate data holders, hardcoded TTLs, unenforced state machine |
| **Low** | 6 | No pagination, dead code, log sanitizer duplication |
| **Total** | **23** | — |
