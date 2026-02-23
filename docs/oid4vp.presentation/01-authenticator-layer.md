# 01 — Authenticator Layer

## File: `OpenID4VPAuthenticator.java` (~1156 lines)

### What It Is

A **WSO2 IS Federated Authenticator** that enables "Login with Wallet" for any Service Provider configured in the Identity Server. It extends `AbstractApplicationAuthenticator` and implements both `FederatedApplicationAuthenticator` and `VPStatusListenerCache.StatusCallback`.

### Class Hierarchy

```
AbstractApplicationAuthenticator
  └── OpenID4VPAuthenticator
        implements FederatedApplicationAuthenticator
        implements VPStatusListenerCache.StatusCallback
```

### How WSO2 IS Discovers It

1. `VPServiceRegistrationComponent` (OSGi SCR) instantiates `OpenID4VPAuthenticator` and registers it as an `ApplicationAuthenticator` OSGi service.
2. The IS authentication framework discovers it via the service registry.
3. When an admin creates a "Digital Credentials" IDP connection, they select `OpenID4VPAuthenticator` as the federated authenticator.

---

## Lifecycle Flow

### 1. `initiateAuthenticationRequest()`

Called when the user clicks "Login" on a SP that's configured with this authenticator.

```
Browser → IS → OpenID4VPAuthenticator.initiateAuthenticationRequest()
```

**Steps:**

1. **Read IDP config properties** — `presentationDefinition`, `ResponseMode`, `TimeoutSeconds`, `ClientId`, `DIDMethod`, `SubjectClaim`
2. **Build Client ID** — calls `buildClientId()` which uses `DIDProvider` to generate a DID (e.g., `did:web:example.com`)
3. **Create VP Request** — via `VPRequestServiceImpl.createVPRequest()`:
   - Generates `requestId`, `transactionId`, `nonce`
   - Resolves the Presentation Definition from the IDP config (by ID or inline)
   - Signs the request as a JWT using the configured DID method's signing key
   - Stores the VPRequest in `VPRequestCache`
4. **Generate QR Code Content** — `QRCodeUtil.generateRequestUriQRContent(requestUri, clientId)` produces an `openid4vp://authorize?client_id=…&request_uri=…` URI
5. **Store context** — saves `requestId` and `sessionDataKey` in `WalletDataCache`
6. **Redirect to JSP** — redirects to `wallet_login.jsp` with query params: `requestId`, `sessionDataKey`, `qrContent`, `timeout`

### 2. `process()` Override

The authenticator overrides `process()` to intercept specific request patterns:

| Condition | Action |
|---|---|
| `poll=true` query param | Register as `StatusCallback` listener on `VPStatusListenerCache`, wait via `CountDownLatch`, redirect back with status |
| `status=success` | Call `processAuthenticationResponse()` |
| `status=failed` | Throw `AuthenticationFailedException` |
| `status=expired` | Throw with "VP request expired" message |
| Default | Delegate to `super.process()` |

### 3. `processAuthenticationResponse()`

Called after the VP has been submitted by the wallet and the poll redirect indicates success.

**Steps:**

1. **Get VP Submission** — first from the instance variable `currentSubmission` (set by callback), then falls back to `WalletDataCache.getSubmission(requestId)`
2. **Extract format** — parses `presentation_submission` JSON to find `descriptor_map[0].format` (e.g., `"vc+sd-jwt"`, `"jwt_vp_json"`)
3. **Verify VP Token**:
   - **SD-JWT path**: calls `VCVerificationService.verifySdJwtToken(vpToken)` → returns `Map<String, Object>` of disclosed claims
   - **Legacy JWT/JSON-LD path**: calls `verifyVPToken(vpToken, nonce, clientId)` → extracts claims manually
4. **Extract username** — priority: `email` → `username` → `sub` from verified claims
5. **Map claims** — `mapVerifiedClaimsToLocal()` uses the IDP's `ClaimMapping[]` to translate wallet claims to IS local claim URIs
6. **Create AuthenticatedUser** — builds `AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(username)` with mapped attributes

---

## Claim Mapping Deep-Dive

### `mapVerifiedClaimsToLocal(verifiedClaims, claimMappings)`

Given a `Map<String, Object>` of verified claims from the VP and the IDP's `ClaimMapping[]` array:

1. For each `ClaimMapping`:
   - Get `remoteClaim.getClaimUri()` (what the wallet sends, e.g., `"email"`)
   - Get `localClaim.getClaimUri()` (IS internal, e.g., `"http://wso2.org/claims/emailaddress"`)
2. Attempt to match against verified claims:
   - **Direct match**: `verifiedClaims.get(remoteClaim)` — e.g., claim key `"email"` matches directly
   - **credentialSubject prefix**: `verifiedClaims.get("credentialSubject." + remoteClaim)` — for claims nested under `credentialSubject`
   - **vc.credentialSubject prefix**: `verifiedClaims.get("vc.credentialSubject." + remoteClaim)` — for JWT VCs where claims are under `vc.credentialSubject`

### `extractClaimsFromVP(vpToken)`

For legacy (non-SD-JWT) verification:

1. Splits JWT, decodes payload
2. Looks for `vp.verifiableCredential[0]` (takes first VC)
3. Decodes the nested VC JWT
4. Extracts `vc.credentialSubject` claims
5. Supports **dotted path navigation** via `hasNestedValue()` / `getNestedValue()` — e.g., `"degree.type"` navigates `{ "degree": { "type": "BachelorDegree" } }`

---

## Configuration Properties (per IDP)

| Property Name | Description | Example |
|---|---|---|
| `presentationDefinition` | ID of the Presentation Definition stored in DB | `"abc-123-def"` |
| `ResponseMode` | OAuth response mode | `"direct_post"` |
| `TimeoutSeconds` | How long to wait for wallet response | `"120"` |
| `ClientId` | Verifier's client ID / DID | `"did:web:example.com"` |
| `DIDMethod` | Which DID method to use for signing | `"web"`, `"key"`, `"jwk"` |
| `SubjectClaim` | Which claim to use as the authenticated username | `"email"` |

---

## StatusCallback Interface

The authenticator implements `VPStatusListenerCache.StatusCallback`:

```java
interface StatusCallback {
    void onStatusChange(String status);     // Called when status changes
    void onTimeout();                       // Called when poll times out
    void onSubmissionReceived(VPSubmission); // Direct processing path
}
```

When `onSubmissionReceived()` fires, the authenticator stores the `VPSubmission` in an instance variable and releases the `CountDownLatch`, allowing `process()` to redirect with `status=success`.

---

## Code Review Notes

| Issue | Details |
|---|---|
| **Instance variable for submission** | `currentSubmission` is an instance field, but authenticators may be shared across threads. If two users authenticate simultaneously, one user's submission could overwrite another's. |
| **Hardcoded Client ID** | `buildClientId()` has a fallback to an ngrok demo DID — must be removed before production. |
| **Empty catch blocks** | Several catch blocks silently swallow exceptions (e.g., in claim extraction). Should at minimum log at debug level. |
| **Thread safety** | The authenticator is registered as a singleton OSGi service but maintains mutable instance state (`currentSubmission`, `currentLatch`). This is a concurrency bug. |
| **ClaimMapping iteration** | `mapVerifiedClaimsToLocal()` iterates all claim mappings for each call but doesn't handle the case where a remote claim maps to multiple local claims. |
| **SD-JWT vs legacy branching** | The format detection relies on string matching (`"sd-jwt"` in format string). A more robust approach would use an enum or constant. |
