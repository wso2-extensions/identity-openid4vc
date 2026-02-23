# 04 — Handler Layer

The handler layer contains two classes that encapsulate the core OID4VP protocol logic: building authorization requests and processing VP responses.

---

## 1. VPRequestBuilder (282 lines)

### Purpose
Constructs OpenID4VP authorization request objects in three formats:

| Method | Output | When Used |
|---|---|---|
| `buildAuthorizationRequestJson()` | Plain JSON string | By-value mode |
| `buildAuthorizationRequestJwt()` | Signed JWT string | Signed request mode |
| `buildAuthorizationDetails()` | `AuthorizationDetailsDTO` | Frontend DTO for QR generation |

### Authorization Request Structure (JSON)

Per the OID4VP spec, the authorization request contains:

```json
{
  "client_id": "did:web:example.com",
  "response_type": "vp_token",
  "nonce": "n-0S6_WzA2Mj",
  "response_mode": "direct_post",
  "response_uri": "https://example.com/openid4vp/v1/response",
  "state": "<requestId>",
  "presentation_definition": { ... },
  "client_metadata": {
    "client_name": "...",
    "logo_uri": "...",
    "vp_formats": {
      "jwt_vp_json": { "alg": ["ES256", "RS256"] },
      "ldp_vp": { "proof_type": ["Ed25519Signature2020", "JsonWebSignature2020"] }
    }
  }
}
```

### JWT Authorization Request

When `buildAuthorizationRequestJwt()` is called:

1. **Header**: `{ "alg": "RS256", "typ": "oauth-authz-req+jwt", "kid": "<keyId>" }`
2. **Payload**: Same fields as JSON, plus standard JWT claims (`iss`, `aud`, `iat`, `exp`, `jti`)
   - `iss` = client_id (verifier's DID)
   - `aud` = `"https://self-issued.me/v2"` (per SIOP v2 spec)
3. **Signature**: Uses `sign()` method which loads a private key from `IdentityUtil.getProperty("OpenID4VP.SigningKey")`

### Client Metadata

The `buildClientMetadata()` method constructs:
- `client_name` from `OpenID4VP.VerifierName` config
- `logo_uri` from `OpenID4VP.LogoUri` config
- `vp_formats` advertising supported VP formats (hardcoded: `jwt_vp_json` + `ldp_vp`)

### ⚠️ Note on `VPRequestBuilder` vs `VPRequestServiceImpl`

**This class is largely superseded.** The actual JWT request object generation used in production is in `VPRequestServiceImpl.buildRequestObjectJwt()`, which uses the Nimbus JOSE library and the `DIDProvider` SPI for signing. `VPRequestBuilder` uses raw JCA (`Signature` class) and is a placeholder/alternative implementation.

### Code Review Notes

| Issue | Details |
|---|---|
| **Placeholder signing** | `sign()` loads a raw Base64-encoded private key from config — no HSM, no KeyStore. The comment says "placeholder". |
| **Empty signature fallback** | If no signing key is configured, returns empty string `""` instead of throwing. This produces an invalid JWT. |
| **Hardcoded VP formats** | `buildClientMetadata()` hardcodes supported formats. Should be configurable. |
| **Response URI construction** | `buildResponseUri()` uses `IdentityUtil.getServerURL()` which may not work behind a reverse proxy without proper config. |

---

## 2. VPResponseHandler (533 lines)

### Purpose
Processes VP submissions from wallets. Parses the VP token, validates its structure, and extracts verified claims.

### ValidationResult (Inner Class)

```java
class ValidationResult {
    VCVerificationStatus status;     // SUCCESS, INVALID, EXPIRED
    String errorCode;
    String errorDescription;
    Map<String, String> verifiedClaims;
    List<String> validatedCredentialIds;
    String presentationId;
    
    boolean isValid() { return SUCCESS.equals(status); }
}
```

### Main Entry: `processSubmission(VPSubmissionDTO, VPRequest)`

```
1. Null check → VPSubmissionValidationException
2. Error response from wallet? → handleErrorResponse()
3. Validate state param matches requestId
4. Get vp_token
5. Is JWT format? (3 dot-separated parts)
   ├── YES → processJwtVPToken()
   └── NO  → processJsonVPToken()
```

### JWT VP Processing (`processJwtVPToken`)

1. Split into 3 parts, Base64URL-decode header and payload
2. **Validate JWT claims** via `validateJwtClaims()`:
   - `nonce` matches the original request's nonce
   - `aud` matches the verifier's client_id (supports both string and array format)
   - `exp` is not in the past
3. Extract VP object from `payload.vp` (or treat payload as VP directly)
4. Extract `verifiableCredential` array
5. Process each credential via `processCredentials()`
6. ⚠️ **TODO**: JWT signature verification is not implemented

### JSON-LD VP Processing (`processJsonVPToken`)

1. Parse as `JsonObject`
2. Validate `type` contains `"VerifiablePresentation"`
3. Validate `proof`:
   - `proof.challenge` matches nonce
   - `proof.domain` matches client_id
   - ⚠️ **TODO**: Cryptographic proof verification not implemented
4. Extract `verifiableCredential` array
5. Process each credential

### Credential Processing

For each credential in the `verifiableCredential` array:

| Format | Detection | Processing |
|---|---|---|
| **JWT VC** | `JsonPrimitive` (string) | Decode JWT, extract `vc.credentialSubject` claims |
| **JSON-LD VC** | `JsonObject` | Direct field access on `credentialSubject` |

### Claim Extraction (`extractClaims`)

Recursive JSON traversal:
- Primitives → stored as `key=value`
- Nested objects → stored with dot prefix: `address.street=123 Main St`
- Arrays → stored as JSON string: `types=["A","B"]`

### Code Review Notes

| Issue | Severity | Details |
|---|---|---|
| **No signature verification** | 🔴 Critical | Both JWT and JSON-LD paths have `// TODO: Verify signature` comments. Without signature verification, a malicious wallet could submit forged VPs. |
| **Empty catch blocks** | 🟡 Medium | `processCredentials()` and `processJwtCredential()` catch and silently ignore all exceptions. A corrupted credential is simply skipped. |
| **Single-credential focus** | 🟡 Medium | While the code iterates all credentials, the `ValidationResult.verifiedClaims` map is a flat namespace. Multiple credentials with the same claim key will overwrite each other. |
| **No presentation_submission validation** | 🟡 Medium | The handler ignores `presentation_submission` entirely. Per spec, this JSON describes how credentials map to input descriptors and should be validated. |
| **Redundancy with authenticator** | 🟡 Medium | `VPResponseHandler` and `OpenID4VPAuthenticator.extractClaimsFromVP()` both parse and extract claims from VPs. This is duplicated logic. |
| **Multi-subject support** | 🟢 Low | `processJsonCredential()` handles `credentialSubject` as both object and array (multiple subjects), which is good spec compliance. |
