# 02 — VCVerificationService (Main Verification Engine)

This document covers `VCVerificationService.java` (interface, ~225 lines) and `VCVerificationServiceImpl.java` (implementation, 1637 lines) — the central verification engine.

---

## Interface: VCVerificationService

15 methods across 5 categories:

### Single Credential Verification
| Method | Input | Output |
|---|---|---|
| `verify(vcString, contentType)` | Raw VC string + MIME type | `VCVerificationResultDTO` |
| `verify(vcString, contentType, vcIndex)` | + position index | `VCVerificationResultDTO` |
| `verifyCredential(credential)` | Parsed `VerifiableCredential` | `VCVerificationResultDTO` |

### Presentation Verification
| Method | Input | Output |
|---|---|---|
| `verifyVPToken(vpToken)` | Raw VP token string | `List<VCVerificationResultDTO>` |
| `verifyPresentation(presentation)` | Parsed `VerifiablePresentation` | `List<VCVerificationResultDTO>` |

### Individual Checks
| Method | Input | Output |
|---|---|---|
| `verifySignature(credential)` | `VerifiableCredential` | `boolean` |
| `isExpired(credential)` | `VerifiableCredential` | `boolean` |
| `isRevoked(credential)` | `VerifiableCredential` | `boolean` |

### Parsing
| Method | Input | Output |
|---|---|---|
| `parseCredential(vcString, contentType)` | Raw string + MIME type | `VerifiableCredential` |
| `parsePresentation(vpToken)` | VP token string | `VerifiablePresentation` |

### Content Type Support
| Method | Returns |
|---|---|
| `isContentTypeSupported(contentType)` | `boolean` |
| `getSupportedContentTypes()` | `String[]` |

### Issuer-Specific Verification
| Method | Purpose |
|---|---|
| `verifyJWTVCIssuer(vcJwt, tenantDomain)` | JWT VC issuer verification |
| `verifyJSONLDVCIssuer(vcJsonObject, tenantDomain)` | JSON-LD VC issuer verification |

### SD-JWT Verification
| Method | Purpose |
|---|---|
| `verifySdJwtToken(vpToken, nonce, audience, pdJson)` | Full SD-JWT verification pipeline |
| `verifyClaimsAgainstDefinition(claims, pdJson)` | Verify claims against PD constraints |

---

## Implementation: VCVerificationServiceImpl

### Dependencies (Constructor Injection)

```java
private final DIDResolverService didResolverService;
private final SignatureVerifier signatureVerifier;
private final StatusListService statusListService;
private final ExtendedJWKSValidator extendedJWKSValidator;
```

Three constructors:
1. **No-arg** — creates all dependencies with `new` (for production use)
2. **DIDResolverService** — for custom DID resolution
3. **DIDResolverService + StatusListService** — for full testability

---

## Supported Content Types

```java
"application/vc+ld+json"     // JSON-LD VC
"application/jwt"            // JWT (generic)
"application/vc+jwt"         // JWT VC (specific)
"application/vc+sd-jwt"      // SD-JWT VC
"application/json"           // Generic JSON (auto-detected)
```

---

## Core Verification Flow

### `verifyCredentialInternal(credential, vcIndex)`

The main verification pipeline, executed for each VC:

```
1. Check Expiration
   └── credential.getExpirationDate() != null && isExpired(credential)
       → Return VCVerificationStatus.EXPIRED

2. Verify Signature
   └── verifySignature(credential)
       ├── isJwt()   → verifyJwtSignature(credential)
       ├── isSdJwt() → verifySdJwtSignature(credential)
       └── isJsonLd() → verifyJsonLdSignature(credential)
       → If fails: Return VCVerificationStatus.INVALID

3. Check Revocation (optional)
   └── credential.hasCredentialStatus()
       └── isRevoked(credential)
           └── statusListService.checkRevocationStatus()
           → If revoked: Return VCVerificationStatus.REVOKED
           → If error: Silently continue (revocation check is optional)

4. Return VCVerificationStatus.SUCCESS
```

**Important**: Revocation check failure does NOT fail the overall verification. This is a deliberate design choice — if the status list endpoint is unreachable, the credential still passes.

---

## Credential Parsing

### Format Auto-Detection (`detectFormat`)

| Input Pattern | Detected Format |
|---|---|
| 3 dot-separated parts, not starting with `{` | JWT |
| Contains `~`, first part is JWT | SD-JWT |
| Starts with `{` | JSON-LD |
| Default | JSON-LD |

### JWT Credential Parsing (`parseJwtCredential`)

Extracts from JWT payload:
| JWT Claim | Model Field |
|---|---|
| `iss` | `issuer`, `issuerId` |
| `sub` | `credentialSubjectId` |
| `jti` | `id` |
| `exp` | `expirationDate` (seconds → Date) |
| `iat` / `nbf` | `issuanceDate` (seconds → Date) |
| `vc` | Nested VC object (type, credentialSubject) |

**Quote stripping**: If the input starts and ends with `"`, it's unquoted via Gson. This handles incorrect JSON serialization.

### SD-JWT Credential Parsing (`parseSdJwtCredential`)

```
<issuer-jwt>~<disclosure1>~<disclosure2>~...~<kb-jwt>
```

1. Split on `~`
2. Parse first part as JWT credential
3. Set format to `SD_JWT`
4. Collect middle parts as disclosures
5. If last part is JWT format (3 dots), treat as Key Binding JWT
6. Process disclosures: decode Base64URL → parse `[salt, name, value]` → add to `credentialSubject`

### JSON-LD Credential Parsing (`parseJsonLdCredential`)

Manually parses JSON fields:
- `@context` (array or string)
- `type` (array or string)
- `id`
- `issuer` (string or object with `id` + `name`)
- `issuanceDate` / `validFrom`
- `expirationDate` / `validUntil`
- `credentialSubject` (object → map)
- `credentialStatus` (StatusList2021 fields)
- `proof` (type, verificationMethod, proofValue, jws, etc.)

### Date Parsing

Tries 5 ISO 8601 formats sequentially:
```java
"yyyy-MM-dd'T'HH:mm:ss'Z'"
"yyyy-MM-dd'T'HH:mm:ssXXX"
"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
"yyyy-MM-dd'T'HH:mm:ss.SSSXXX"
"yyyy-MM-dd"
```

All use `UTC` timezone. Returns `null` on parse failure (does not throw).

---

## Signature Verification Routing

### JWT Path (`verifyJwtSignature`)

```
Parse JWT header → extract alg, kid
        │
        ├── Issuer is DID (starts with "did:")
        │   ├── kid is full DID URL with fragment (#)
        │   │   └── didResolverService.getPublicKeyFromReference(kid)
        │   └── kid is not DID URL
        │       └── didResolverService.getPublicKey(issuer, null)
        │   └── signatureVerifier.verifyJwtSignature(raw, publicKey, alg)
        │
        ├── Issuer is URL (starts with "http")
        │   └── resolveJwksUri(issuer)
        │       ├── Try .well-known/openid-credential-issuer
        │       ├── Fallback: .well-known/openid-configuration
        │       ├── Fallback: authorization_servers[0] → OIDC discovery
        │       └── extendedJWKSValidator.validateSignature(raw, jwksUri, alg)
        │
        └── Non-DID, non-URL issuer → return true (cannot verify)
```

**JWKS URI Resolution** (`resolveJwksUri`):
1. Fetch `{issuer}/.well-known/openid-credential-issuer` — look for `jwks_uri`
2. If not found: try `{issuer}/.well-known/openid-configuration`
3. If metadata has `authorization_servers`: try first server's OIDC discovery for `jwks_uri`
4. If nothing works: return `null` → throws `CredentialVerificationException`

### SD-JWT Path (`verifySdJwtSignature`)

1. Extract the issuer JWT (first part before `~`)
2. Create a temporary `VerifiableCredential` with JWT format
3. Delegate to `verifyJwtSignature()` — only the issuer JWT's signature is verified at this stage

### JSON-LD Path (`verifyJsonLdSignature`)

1. Extract `proof.verificationMethod` (e.g., `did:web:example.com#key-1`)
2. Extract DID from verification method (before `#`)
3. Get public key: `didResolverService.getPublicKey(did, verificationMethod)`
4. Get proof value from `proofValue` or `jws`
5. Delegate to `signatureVerifier.verifyLinkedDataSignature()`

---

## Full SD-JWT Verification (`verifySdJwtToken`)

This is the complete SD-JWT VC verification pipeline called by the presentation module:

```
1. Split SD-JWT on "~"
   ├── parts[0] = issuer JWT
   ├── parts[1..n-1] = disclosures
   └── parts[n] = Key Binding JWT (if last part has dots)

2. Verify Issuer JWT Signature
   └── verifySignature(credential) — same as above

3. Verify Time Claims
   ├── exp: not expired
   └── nbf: not before "not valid yet"

4. Verify Disclosures against _sd digests
   ├── Hash each disclosure with SHA-256(Base64URL)
   ├── Match against _sd array in issuer JWT claims
   └── Decode matched disclosures: [salt, name, value]
       → Build verifiedClaims map

5. Verify Key Binding JWT (if present)
   ├── Check nonce matches (timing-safe MessageDigest.isEqual)
   ├── Check audience matches (timing-safe)
   ├── Verify sd_hash (SHA-256 of issuer-jwt~disclosures~)
   ├── Extract cnf.jwk from issuer JWT
   └── Verify KB-JWT signature using holder's public key

6. Verify Claims Against Presentation Definition
   └── verifyClaimsAgainstDefinition() — JSONPath evaluation

7. Return verified claims map
```

### Claims Against Definition (`verifyClaimsAgainstDefinition`)

Uses **JsonPath** library to evaluate PD constraints:
1. Parse Presentation Definition JSON
2. For each input descriptor's `constraints.fields`:
   - Try each JSONPath in `field.path[]`
   - If none resolve to a value → throw `CredentialVerificationException`

---

## Presentation Parsing

### JWT VP (`parseJwtPresentation`)

```
Payload claims:
  iss → holder
  nonce → nonce
  jti → id
  vp.verifiableCredential → List<VerifiableCredential>
```

Nested credentials can be JWT strings or JSON-LD objects embedded in the `vp` claim.

### JSON-LD VP (`parseJsonLdPresentation`)

```
Fields:
  id → id
  holder → holder
  verifiableCredential → Array of JWT strings or JSON-LD objects
  proof → presentation proof
```

---

## HTTP Client Behavior

`fetchJson()` for JWKS/metadata resolution:
- **Connect timeout**: 5000ms
- **Read timeout**: 5000ms
- Validates URL scheme (`http`/`https` only) and host (not null)
- Returns `null` on non-200 responses (does not throw)

---

## Code Review Notes

| Issue | Severity | Details |
|---|---|---|
| **1637 lines in single class** | High | God class. Should be decomposed: parsing → `VCParser`, SD-JWT → `SdJwtVerifier`, JWKS resolution → `JwksResolver`, etc. |
| **Non-DID, non-URL issuer returns `true`** | High | `verifyJwtSignature()` returns `true` if the issuer is neither a DID nor a URL. This silently skips signature verification for unknown issuer formats. |
| **Revocation check failure is silently swallowed** | Medium | `catch (CredentialVerificationException e) { // Continue without failing }`. Consider at least setting a warning flag on the result DTO. |
| **`SimpleDateFormat` is not thread-safe** | Medium | `parseDate()` creates new `SimpleDateFormat` instances per call. While thread-safe by creation, it's inefficient. Use `java.time.format.DateTimeFormatter` (immutable, thread-safe). |
| **SD-JWT `sd_hash` verification uses string comparison** | Medium | `hashSd()` returns a Base64URL string, compared via `MessageDigest.isEqual` on UTF-8 bytes. This is correct for timing safety but the hash itself could use direct byte comparison. |
| **`holderKey.toECKey().toPublicKey()`** | Medium | In SD-JWT KB verification, assumes the holder key is always EC. Will throw `ClassCastException` for RSA or OKP (EdDSA) keys. Should use `DefaultJWSVerifierFactory` with generic key. |
| **`processDisclosures` swallows all exceptions** | Medium | Empty `catch (Exception e) {}` block. Malformed disclosures are silently ignored — could hide data corruption. |
| **`removeCRLF` duplicated from SignatureVerifier** | Low | Both classes have identical `removeCRLF()` methods. Use `LogSanitizer.sanitize()` from common. |
| **`parseJwtPart` uses Gson unchecked cast** | Low | `GSON.fromJson(decoded, Map.class)` returns raw `Map` with `Double` for numbers (Gson default). Integer claims like `exp` become `Double` then `long` cast — works but fragile. |
| **Nimbus `SignedJWT.parse()` called multiple times** | Low | In `verifyJwtSignature`, the JWT is parsed once in the service (`parseJwtPart`) and again in `SignatureVerifier` (`SignedJWT.parse`). Redundant parsing. |
| **No input validation on JWKS/metadata URLs** | Medium | `resolveJwksUri` fetches from any URL derived from the issuer field. No SSRF protection beyond scheme check. The `@SuppressFBWarnings("URLCONNECTION_SSRF_FD")` acknowledges this. |
