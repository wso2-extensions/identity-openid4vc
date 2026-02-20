# 02 — Domain Models

---

## Model Inventory

| Model | Lines | Pattern | Serializable | Key Role |
|---|---|---|---|---|
| `VPRequest` | ~250 | Builder (private constructor) | ✅ | Authorization request state |
| `VPRequestStatus` | ~70 | Enum | — | ACTIVE → VP_SUBMITTED → COMPLETED/EXPIRED |
| `VPSubmission` | ~220 | Builder (private constructor) | ✅ | Wallet's VP token + verification state |
| `VCVerificationStatus` | ~80 | Enum | — | SUCCESS, INVALID, EXPIRED, REVOKED, ERROR |
| `PresentationDefinition` | ~150 | Builder (private constructor) | ✅ | DB-backed credential requirements |
| `DIDDocument` | ~370 | POJO + inner classes | — | W3C DID Document with VerificationMethod, Service |
| `DIDKey` | ~100 | POJO | — | Key material (pub/priv byte arrays) |
| `VerifiableCredential` | ~480 | POJO + inner classes + enum | — | W3C VC Data Model (all formats) |
| `VerifiablePresentation` | ~350 | POJO + enum | — | VP container for multiple VCs |
| `TrustedIssuer` | ~110 | POJO | — | Trusted credential issuer metadata |
| `TrustedVerifier` | ~360 | Builder + enums | — | Trusted verifier entity with trust levels |
| `RevocationCheckResult` | ~260 | Builder + factory methods + enum | — | Revocation status check result |

---

## 1. VPRequest

The core authorization request state object. Created when the verifier initiates an OID4VP flow.

**Fields**:
- `requestId` — UUID, primary identifier
- `transactionId` — Optional external correlation ID
- `clientId` — Verifier's DID (used as `client_id` in the authorization request)
- `nonce` — Cryptographic nonce for replay protection
- `presentationDefinitionId` — Reference to stored PD
- `presentationDefinition` — Inline PD JSON (alternative to reference)
- `responseUri` — Where the wallet sends the VP (`direct_post` endpoint)
- `responseMode` — `direct_post` or `direct_post.jwt`
- `requestJwt` — Signed authorization request JWT
- `status` — `VPRequestStatus` enum
- `expiresAt` — Expiry timestamp (millis)
- `tenantId` — WSO2 IS multi-tenancy support
- `didMethod` — DID method used for signing (e.g., `web`, `jwk`)
- `signingAlgorithm` — JWT signing algorithm

**Pattern**: Immutable-ish — has a `Builder` with private constructor, but also has public setters (breaking the immutability guarantee).

---

## 2. VPRequestStatus (Enum)

```
ACTIVE          → Request created, waiting for wallet
VP_SUBMITTED    → Wallet submitted VP token
EXPIRED         → TTL exceeded
COMPLETED       → Verification finished
CANCELLED       → Request invalidated
```

Has `fromValue(String)` for deserialization from string.

---

## 3. VPSubmission

Records what the wallet submitted and the verification result.

**Fields**:
- `submissionId`, `requestId`, `transactionId` — Correlation
- `vpToken` — The raw VP token (JWT string or JSON-LD)
- `presentationSubmission` — JSON describing how VCs map to input descriptors
- `error`, `errorDescription` — If the wallet returned an error instead of VP
- `verificationStatus` — `VCVerificationStatus` enum
- `verificationResult` — Detailed result JSON
- `submittedAt` — Timestamp
- `tenantId`

**Convenience methods**: `hasError()`, `hasVpToken()`

---

## 4. PresentationDefinition

Maps to the `IDN_PRESENTATION_DEFINITION` database table.

**Fields**:
- `definitionId` — UUID, primary key
- `resourceId` — Links to the IDP's `resourceId` in WSO2 IS
- `name`, `description` — Human-readable metadata
- `definitionJson` — Full PD JSON string (DIF Presentation Exchange format)
- `tenantId` — Multi-tenancy

**Storage**: Persisted via JDBC in `PresentationDefinitionDAOImpl` (in the presentation module).

---

## 5. DIDDocument

Full W3C DID Core spec representation. Rich model with two inner classes:

### DIDDocument.VerificationMethod
Represents a public key entry:
- `id` — Full key ID (e.g., `did:web:example.com#key-1`)
- `type` — Key type (`JsonWebKey2020`, `Ed25519VerificationKey2020`, etc.)
- `controller` — DID that controls this key
- `publicKeyJwk` / `publicKeyJwkMap` — JWK format
- `publicKeyMultibase` / `publicKeyBase58` / `publicKeyBase64` / `publicKeyHex` / `publicKeyPem` — Alternative formats

**Convenience methods**: `isJsonWebKey()`, `isEd25519Key()`, `isEcdsaSecp256k1Key()`, `getKeyIdFragment()`, `hasPublicKey()`

### DIDDocument.Service
Service endpoint entries:
- `id`, `type`, `serviceEndpoint`, `serviceEndpointMap`

### DIDDocument Lookups
- `findVerificationMethod(methodId)` — Exact match, then fragment match
- `getFirstAssertionMethod()` — For signing (falls back to first verificationMethod)
- `getFirstAuthenticationMethod()` — For authentication
- `getVerificationMethodMap()` — Map keyed by ID + fragment
- `findServiceByType(serviceType)` — Service lookup

---

## 6. DIDKey

Lightweight key material holder:
- `keyId`, `tenantId`, `algorithm`
- `publicKey`, `privateKey` — Raw `byte[]` (defensive copies in getters/setters)
- `createdAt`

---

## 7. VerifiableCredential

Comprehensive W3C VC Data Model implementation supporting **all three formats**:

### Format Enum
```java
JSON_LD("ldp_vc"), JWT("jwt_vc"), JWT_JSON("jwt_vc_json"), SD_JWT("vc+sd-jwt")
```

### Core Fields
- `id`, `context[]`, `type[]`, `issuer`, `issuerId`, `issuerName`
- `issuanceDate`, `expirationDate`
- `credentialSubject` — `Map<String, Object>` of claims
- `credentialSubjectId` — The holder's identifier

### Inner Class: CredentialStatus
For revocation checking:
- `id`, `type`, `statusPurpose`, `statusListIndex`, `statusListCredential`
- `isStatusList2021()` — Type check helper

### Inner Class: Proof
For JSON-LD credentials:
- `type`, `created`, `verificationMethod`, `proofPurpose`, `proofValue`, `jws`, `challenge`, `domain`
- `isEd25519()`, `isJsonWebSignature()` — Type check helpers

### Format-Specific Fields
- **JWT**: `jwtHeader`, `jwtPayload`, `jwtSignature`, `jwtClaims`
- **SD-JWT**: `disclosures[]`, `keyBindingJwt`

### Verification Flags
- `signatureVerified`, `expirationChecked`, `revocationChecked`

### Convenience Methods
- `getPrimaryType()` — First non-`VerifiableCredential` type
- `isExpired()`, `isNotYetValid()`
- `getClaim(name)`, `getStringClaim(name)` — Credential subject access
- `isJsonLd()`, `isJwt()`, `isSdJwt()` — Format checks

---

## 8. VerifiablePresentation

Container for one or more VCs:

### Format Enum
```java
JSON_LD("ldp_vp"), JWT("jwt_vp"), JWT_JSON("jwt_vp_json")
```

### Fields
- `id`, `context[]`, `type[]`, `holder`, `issuanceDate`, `nonce`
- `verifiableCredentials` — `List<VerifiableCredential>`
- `proof` — Reuses `VerifiableCredential.Proof`
- JWT fields: `jwtHeader`, `jwtPayload`, `jwtSignature`, `jwtClaims`
- Verification: `signatureVerified`, `holderBindingVerified`

### Key Methods
- `getCredentialCount()`, `getCredential(index)`
- `getJwtSubject()`, `getJwtAudience()`, `getJwtNonce()` — Extract from JWT claims
- `areAllCredentialsVerified()` — Check all VCs have verified signatures
- `hasExpiredCredential()`, `getFirstExpiredCredential()` — Expiry checks
- `getAllCredentialTypes()`, `getAllIssuers()` — Aggregate across VCs

---

## 9. TrustedIssuer

Simple entity for recording which DID-identified issuers are trusted:
- `issuerDid`, `tenantDomain`, `tenantId`, `addedBy`, `addedTimestamp`, `description`, `active`

---

## 10. TrustedVerifier

Rich entity with **two enums** and a **Builder**:

### TrustLevel Enum
```java
BASIC → STANDARD → ELEVATED → FULL
```

### VerifierStatus Enum
```java
ACTIVE, SUSPENDED, REVOKED, PENDING
```

### Fields
- Identity: `id`, `did`, `clientId`, `name`, `description`
- Organization: `organizationName`, `organizationUrl`, `logoUrl`
- Permissions: `allowedRedirectUris[]`, `allowedCredentialTypes[]`, `allowedScopes[]`
- Trust: `trustLevel`, `status`, `createdAt`, `updatedAt`, `expiresAt`
- `metadata` — `Map<String, Object>` for extensibility

### Key Methods
- `isActive()` — Checks both status and expiry
- `allowsCredentialType(type)` — Empty list = allow all
- `allowsRedirectUri(uri)` — Empty list = allow all

---

## 11. RevocationCheckResult

Result of checking a credential's revocation status:

### Status Enum
```java
VALID, REVOKED, SUSPENDED, UNKNOWN, SKIPPED
```

### Factory Methods
```java
RevocationCheckResult.valid()
RevocationCheckResult.revoked(purpose)
RevocationCheckResult.suspended(purpose)
RevocationCheckResult.unknown(message)
RevocationCheckResult.skipped(reason)
```

### Fields
- `status`, `statusPurpose`, `statusListCredentialUrl`, `statusIndex`, `message`
- `checkedAt` — Auto-set to `System.currentTimeMillis()`
- `cached` — Whether result came from cache

### Convenience Methods
- `isValid()` — True for VALID or SKIPPED
- `isRevoked()`, `isSuspended()`, `isRevokedOrSuspended()`

---

## Code Review Notes

| Issue | Severity | Details |
|---|---|---|
| **`VPRequest` has Builder + public setters** | Medium | Breaks immutability. Either remove setters or remove Builder. |
| **Defensive copies create garbage** | Low | Every getter on `DIDDocument`, `VerifiableCredential`, `VerifiablePresentation` creates `new ArrayList<>()` / `new HashMap<>()`. Fine for correctness but generates GC pressure on hot paths. |
| **`DIDKey` stores private key in `byte[]`** | High | Private keys should be in a `KeyStore` or at minimum zeroed after use. The `clone()` pattern is correct but the raw bytes are still in memory. |
| **`VerifiableCredential` is a mega-class** | Medium | 480+ lines, supports 3 formats with format-specific fields. Consider subclassing or composition per format. |
| **`TrustedVerifier.Builder.build()` leaks reference** | Low | `@SuppressFBWarnings("EI_EXPOSE_REP")` — the builder returns the internal object, not a copy. |
| **Date fields in `VerifiableCredential`** | Low | Uses `java.util.Date` instead of `java.time.Instant`. Defensive copies with `new Date(date.getTime())` are correct but `Instant` is immutable and doesn't need this. |
