# 06 — Service Layer

The service layer provides business logic interfaces and implementations. Three service interfaces, three implementations.

---

## 1. VPRequestService / VPRequestServiceImpl

### Purpose
Manages the full lifecycle of VP authorization requests: creation, retrieval, status management, JWT generation, and expiry.

### Key Method: `createVPRequest(VPRequestCreateDTO, tenantId)`

This is the entry point for creating a new VP request. Called by both `VPRequestServlet` (API) and `OpenID4VPAuthenticator` (auth flow).

**Flow:**

```
1. Validate input (clientId required, presentation def required)
2. Generate requestId (UUID), transactionId, nonce
3. Resolve Presentation Definition:
   a. If inline PD provided in DTO → validate and use
   b. If presentationDefinitionId provided → fetch from DB via PresentationDefinitionService
4. Extract _internal config from PD JSON (did_method, signing_algorithm) if present
   → Remove _internal before passing to wallet (spec compliance)
5. Default: did_method="web", signingAlgorithm="EdDSA"
6. Calculate expiresAt = now + configured expiry
7. Build VPRequest model object
8. buildRequestObjectJwt() → sign the request as JWT
9. Store in cache via VPRequestDAOImpl
10. Build response DTO with requestUri, authorizationDetails, etc.
```

### JWT Request Object Generation: `buildRequestObjectJwt(vpRequest, didMethod, signingAlgorithm)`

This is the **production JWT builder** (as opposed to `VPRequestBuilder` which is a placeholder).

**Libraries used:**
- **Nimbus JOSE JWT** — `JWSObject`, `JWSSigner`, `JWTClaimsSet`, `JWSHeader`
- **DID Provider SPI** — `DIDProviderFactory.getProvider(didMethod)` → `DIDProvider`

**Steps:**
1. Get `DIDProvider` for the configured method (web/key/jwk)
2. Get DID string: `provider.getDID(tenantId, baseUrl, signingAlgorithm)`
3. Get key ID: `provider.getSigningKeyId(tenantId, baseUrl, signingAlgorithm)`
4. Build JWT claims:
   - `iss` = DID
   - `response_type` = `vp_token`
   - `response_mode` = `direct_post`
   - `response_uri` = submission endpoint URL
   - `nonce`, `state` (requestId), `client_id`
   - `presentation_definition` = PD JSON as a Map
   - `client_metadata` with `vp_formats` (SD-JWT, LDP VP)
   - `exp` = now + 10 minutes
5. Build JWS header:
   - `alg` from `provider.getSigningAlgorithm(signingAlgorithm)`
   - `kid` = keyId
   - `typ` = `oauth-authz-req+jwt`
6. Sign: `provider.getSigner(tenantId, signingAlgorithm)` → `jwsObject.sign(signer)`
7. Return `jwsObject.serialize()`

### `getRequestJwt(requestId, tenantId)`

Returns the pre-generated JWT stored in the `VPRequest`. If missing (shouldn't happen), regenerates it as a fallback.

### `getVPRequestById(requestId, tenantId)`

Fetches from cache. If the `VPRequest` has a `presentationDefinitionId` but no inline `presentationDefinition`, it lazy-loads from the DB.

---

## 2. PresentationDefinitionService / PresentationDefinitionServiceImpl

### Purpose
CRUD operations for Presentation Definitions. Wraps the DAO layer with validation logic.

### Key Methods

| Method | Logic |
|---|---|
| `createPresentationDefinition()` | Validates name + JSON required, validates JSON structure via `PresentationDefinitionUtil.isValidPresentationDefinition()`, generates UUID if missing, checks for duplicate ID |
| `getPresentationDefinitionById()` | Delegates to DAO, throws `PresentationDefinitionNotFoundException` if null |
| `updatePresentationDefinition()` | Verify exists, validate new JSON if provided, merge with existing fields (preserves existing values for null fields), preserves `resourceId` |
| `deletePresentationDefinition()` | Verify exists, then delete |
| `getClaimsFromPresentationDefinition()` | Parses PD JSON → extracts `input_descriptors[].constraints.fields[].path` and `name` → returns `InputDescriptorClaimsDTO` list |

### Claims Extraction Detail

The `getClaimsFromPresentationDefinition()` method is important for the IDP configuration UI. It:

1. Parses the Presentation Definition JSON
2. Iterates `input_descriptors` array
3. For each descriptor, iterates `constraints.fields` array
4. For each field:
   - Gets `path[0]` (first JSONPath, e.g., `$.credentialSubject.email`)
   - Gets `name` (explicit) or derives from path (e.g., `email` from `$.credentialSubject.email`)
5. Returns a list of `InputDescriptorClaimsDTO` with per-descriptor claim lists

### Inner DTOs

```java
class InputDescriptorClaimsDTO {
    String inputDescriptorId;    // e.g., "identity_credential"
    List<ClaimDTO> claims;       // List of claims in this descriptor
}

class ClaimDTO {
    String name;     // e.g., "email"
    String path;     // e.g., "$.credentialSubject.email"
}
```

---

## 3. TrustedVerifierService / TrustedVerifierServiceImpl

### Purpose
Manages a registry of trusted external verifiers. Controls which entities are allowed to request credential presentations.

### Storage
**Entirely in-memory** — three `ConcurrentHashMap`s:

```
verifierStore:   tenant → { verifierId → TrustedVerifier }
didIndex:        tenant → { did → verifierId }
clientIdIndex:   tenant → { clientId → verifierId }
```

### Verification Modes

**Strict Mode** (`isStrictVerificationEnabled()`):
- When **enabled**: Only pre-registered verifiers can make requests
- When **disabled** (default): Any verifier with a valid DID is trusted

**Redirect URI Validation** (`getRedirectUriValidationMode()`):

| Mode | Behavior |
|---|---|
| `STRICT` | Must match pre-registered URI exactly |
| `RELAXED` (default) | Must match verifier's organization domain (or subdomain) |
| `DISABLED` | No validation |

### Key Methods

| Method | Purpose |
|---|---|
| `isVerifierTrusted(did, tenant)` | Quick check — returns `true` if not strict mode, or if verifier exists and is active |
| `addTrustedVerifier(verifier, tenant)` | Generates UUID, sets timestamps, stores in all three maps |
| `updateTrustedVerifier(id, verifier, tenant)` | Updates indexes if DID/clientId changed, preserves creation time |
| `removeTrustedVerifier(id, tenant)` | Removes from all three maps |
| `validateVerifierRequest(did, credTypes, tenant)` | Checks if verifier is active and allows all requested credential types |
| `validateRedirectUri(did, uri, tenant)` | Domain matching based on configured mode |

### Code Review Notes

| Issue | Details |
|---|---|
| **No persistence** | All verifier data is lost on server restart. In production, this needs a database-backed implementation. |
| **Not used in auth flow** | The `VPSubmissionServlet` calls `VCVerificationService.verifyJWTVCIssuer()` for **issuer** trust, not `TrustedVerifierService` for **verifier** trust. This service appears to be scaffolding for future use. |
| **Thread safety** | `ConcurrentHashMap.computeIfAbsent()` is used correctly for atomic map updates. |
| **URI validation** | `validateRedirectUri()` in RELAXED mode uses `URI.getHost()` comparison, which is a good basic check but doesn't handle edge cases like IP addresses or internationalized domain names. |
