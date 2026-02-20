# 01 — Constants (`OpenID4VPConstants.java`)

> Single file, ~340 lines, 14 static inner classes. Private constructor prevents instantiation.

---

## Inner Class Map

| Inner Class | Constants | Purpose |
|---|---|---|
| `Protocol` | 10 | OID4VP protocol values: response types, modes, client_id schemes |
| `RequestParams` | 16 | HTTP request parameter names (`client_id`, `nonce`, `state`, `vp_token`, etc.) |
| `ResponseParams` | 5 | HTTP response parameter names |
| `ErrorCodes` | 11 | OAuth 2.0 + OID4VP-specific error codes |
| `VCFormats` | 8 | VC/VP format identifiers (`jwt_vp`, `ldp_vc`, `vc+sd-jwt`, `mso_mdoc`) |
| `JWTClaims` | 10 | Standard JWT claim names (`iss`, `sub`, `aud`, `nonce`, `vp`, `vc`) |
| `HTTP` | 5 | Content types and auth headers |
| `Endpoints` | 7 | API path segments (`/vp-request`, `/response`, `/request-uri`, etc.) |
| `ConfigKeys` | 18 | `identity.xml` property keys under `OpenID4VP.*` namespace |
| `Defaults` | 7 | Default config values (300s expiry, 1000 max cache, EdDSA algorithm) |
| `PresentationDef` | 10 | DIF Presentation Exchange field names |
| `PresentationSubmission` | 6 | Submission JSON field names |
| `CacheKeys` | 5 | Cache key prefixes (`VP_REQUEST_`, `VP_SUBMISSION_`, etc.) |
| `Verification` | 17 | VC content types, proof types, JWT algorithms, status types |
| `DID` | 16 | DID methods, document properties, verification method types |
| `Revocation` | 12 | Status list types, purposes, cache settings, min bitstring size |
| `TrustedVerifier` | 9 | Trust levels, verifier statuses, redirect URI modes |
| `Logging` | 2 | Component ID and log prefix |

---

## Key Constant Groups

### Protocol Constants
```java
RESPONSE_TYPE_VP_TOKEN     = "vp_token"
RESPONSE_MODE_DIRECT_POST  = "direct_post"
CLIENT_ID_SCHEME_DID       = "did"
OPENID4VP_SCHEME           = "openid4vp://"
```

### Configuration Keys (read via `IdentityUtil.getProperty()`)
```java
VP_REQUEST_EXPIRY_SECONDS           = "OpenID4VP.VPRequestExpirySeconds"
SIGNING_ALGORITHM                   = "OpenID4VP.SigningAlgorithm"
ENABLE_REQUEST_URI                  = "OpenID4VP.EnableRequestUri"
LONG_POLLING_TIMEOUT_SECONDS        = "OpenID4VP.LongPollingTimeoutSeconds"
SIGNATURE_VERIFICATION_ENABLED      = "OpenID4VP.Verification.SignatureVerificationEnabled"
DID_SUPPORTED_METHODS               = "OpenID4VP.DID.SupportedMethods"
DID_UNIVERSAL_RESOLVER_URL          = "OpenID4VP.DID.UniversalResolverUrl"
BASE_URL                            = "OpenID4VP.BaseUrl"
```

### Defaults
```java
VP_REQUEST_EXPIRY_SECONDS   = 300        // 5 minutes
CACHE_ENTRY_EXPIRY_SECONDS  = 300
MAX_CACHE_ENTRIES           = 1000
SIGNING_ALGORITHM           = "EdDSA"
LONG_POLLING_TIMEOUT_SECONDS = 60
SUPPORTED_VC_FORMATS        = [jwt_vp_json, jwt_vc_json, ldp_vp, ldp_vc, vc+sd-jwt]
```

### Supported VC Formats
```java
JWT_VP, JWT_VP_JSON, JWT_VC, JWT_VC_JSON    // JWT-based
LDP_VP, LDP_VC                              // JSON-LD + Linked Data Proofs
VC_SD_JWT                                    // Selective Disclosure JWT
MSO_MDOC                                    // Mobile Document (ISO 18013-5)
```

---

## Code Review Notes

| Issue | Severity | Details |
|---|---|---|
| **Default `SIGNING_ALGORITHM = "EdDSA"`** | Medium | But `VPRequestServiceImpl` in the presentation module uses RS256. Mismatch between constant default and actual usage. |
| **`Defaults.SUPPORTED_VC_FORMATS`** uses `Arrays.asList` | Low | Returns a fixed-size list. `Collections.unmodifiableList` wrapping is correct but the pattern is verbose for Java 21. Could use `List.of()`. |
| **`mso_mdoc` format declared** | Info | Format constant exists but no implementation supports it anywhere. |
| **Dual context keys in `RequestParams`** | Info | Both `VP_TOKEN = "vp_token"` and `OPENID4VP_VP_TOKEN = "openid4vp_vp_token"` exist. The latter is for internal context storage, which could be confusing. |
