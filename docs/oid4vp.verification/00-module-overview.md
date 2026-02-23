# 00 — OID4VP Verification Module Overview

---

## Purpose

The `oid4vp.verification` module is responsible for **verifying Verifiable Credentials (VCs) and Verifiable Presentations (VPs)** submitted by digital wallets. It handles:

1. **Cryptographic signature verification** — JWT (RSA, EC, EdDSA), JSON-LD (Linked Data Proofs), SD-JWT
2. **Credential expiration checking** — `exp` / `expirationDate` / `validUntil`
3. **Revocation status checking** — StatusList2021, BitstringStatusList
4. **VP token format validation** — Structure validation for all supported formats
5. **Presentation submission validation** — DIF Presentation Exchange compliance
6. **SD-JWT verification** — Disclosure verification, Key Binding JWT verification, `sd_hash` integrity

---

## Package Structure

```
org.wso2.carbon.identity.openid4vc.oid4vp.verification/
├── jwt/
│   └── ExtendedJWKSValidator.java          // JWKS-based JWT signature validation
├── service/
│   ├── StatusListService.java              // Revocation checking interface
│   ├── VCVerificationService.java          // Main verification interface
│   └── impl/
│       ├── StatusListServiceImpl.java      // StatusList2021 + BitstringStatusList
│       └── VCVerificationServiceImpl.java  // Main verification engine (1637 lines)
├── util/
│   ├── SignatureVerifier.java              // Low-level crypto signature verification
│   └── VPSubmissionValidator.java          // VP submission structural validation
└── test/
    ├── service/impl/
    │   └── VCVerificationServiceTest.java  // Parsing + expiry tests
    └── util/
        ├── SignatureVerifierTest.java       // Input validation tests
        └── VPSubmissionValidatorTest.java   // Submission validation tests
```

---

## File Inventory

| File | Lines | Role |
|---|---|---|
| `VCVerificationServiceImpl.java` | 1637 | Main verification engine — parsing, signature, expiry, revocation, SD-JWT |
| `VCVerificationService.java` | ~225 | Service interface with 15 methods |
| `SignatureVerifier.java` | 576 | Low-level signature verification (JWT, JSON-LD, ECDSA, EdDSA) |
| `VPSubmissionValidator.java` | 517 | VP submission structural validation |
| `StatusListServiceImpl.java` | 441 | StatusList2021/Bitstring revocation checking with caching |
| `StatusListService.java` | ~100 | Revocation service interface |
| `ExtendedJWKSValidator.java` | ~95 | JWKS-based JWT validation via Nimbus |

**Total**: ~3,591 lines of production code + ~273 lines of test code.

---

## Dependencies

| Dependency | Version | Purpose | Scope |
|---|---|---|---|
| `oid4vp.common` | project | DTOs, models, exceptions, constants | compile |
| `oid4vp.did` | project | DID resolution for public key retrieval | compile |
| `com.google.code.gson` | parent | JSON parsing/serialization | compile |
| `org.wso2.orbit.com.nimbusds:nimbus-jose-jwt` | parent | JWT parsing, JWKS fetching, signature verification | compile |
| `com.jayway.jsonpath:json-path` | 2.4.0 | JSONPath evaluation for PD constraint checking | **embedded** |
| `net.minidev:json-smart` | 2.3 | JSON parsing (JsonPath dependency) | **embedded** |
| `commons-lang3` | parent | String utilities | compile |
| `slf4j-api` | parent | Logging | compile |
| `testng` | parent | Unit testing | test |
| `mockito-core` + `mockito-testng` | parent | Mocking | test |

### Embedded Dependencies (Important!)

The OSGi bundle **embeds** `json-path`, `json-smart`, `accessors-smart`, and `asm` inside the JAR:

```xml
<Embed-Dependency>
    json-path,
    json-smart,
    accessors-smart,
    asm
</Embed-Dependency>
```

This means these libraries ship inside the bundle rather than being resolved via OSGi imports. This is necessary because `json-path` is not available as an OSGi bundle in the WSO2 IS runtime.

---

## OSGi Configuration

```xml
<Export-Package>
    org.wso2.carbon.identity.openid4vc.oid4vp.verification.*;version="${identity.oid4vc.pkg.version}"
</Export-Package>
<Import-Package>
    org.wso2.carbon.identity.openid4vc.oid4vp.common.*;version="${identity.oid4vc.pkg.version}",
    org.wso2.carbon.identity.openid4vc.oid4vp.did.*;version="${identity.oid4vc.pkg.version}",
    org.osgi.service.component; version="[1.2.0, 2.0.0)",
    *;resolution:=optional
</Import-Package>
<DynamicImport-Package>*</DynamicImport-Package>
```

- All verification packages are exported
- Imports common + DID modules explicitly
- `*;resolution:=optional` — all other imports are optional
- `DynamicImport-Package: *` — resolves runtime class loading for embedded dependencies

**Note**: `Bundle-RequiredExecutionEnvironment` says `JavaSE-11` but the compiler is set to Java 21. This is an inconsistency.

---

## Cross-Module Dependencies

```
┌────────────────────────┐
│   oid4vp.presentation  │ ← uses verification services
│     (Servlet layer)    │
└───────────┬────────────┘
            │ calls
            ▼
┌────────────────────────┐
│  oid4vp.verification   │ ← THIS MODULE
│  (Service + Util)      │
├────────────────────────┤
│  VCVerificationService │──── SignatureVerifier
│  StatusListService     │──── ExtendedJWKSValidator
│  VPSubmissionValidator │
└───────────┬────────────┘
            │ imports
            ▼
┌────────────────────────┐     ┌────────────────────┐
│    oid4vp.common       │     │    oid4vp.did       │
│  (Models, DTOs, Exc.)  │     │  (DID Resolution)   │
└────────────────────────┘     └────────────────────┘
```

---

## Verification Flow (High Level)

```
Wallet submits VP token
        │
        ▼
VPSubmissionValidator.validateSubmission()     ← structural validation
        │
        ▼
VCVerificationService.verifyVPToken()
        │
        ├── parsePresentation()                ← detect format, parse JWT/JSON-LD VP
        │
        ├── for each VC in VP:
        │   │
        │   ├── 1. Check expiration            ← isExpired()
        │   │
        │   ├── 2. Verify signature            ← verifySignature()
        │   │   ├── JWT → verifyJwtSignature()
        │   │   │   ├── DID issuer → DIDResolverService.getPublicKey()
        │   │   │   │                 → SignatureVerifier.verifyJwtSignature()
        │   │   │   └── URL issuer → resolveJwksUri() → ExtendedJWKSValidator
        │   │   ├── SD-JWT → extract issuer JWT → verifyJwtSignature()
        │   │   └── JSON-LD → extract proof → DIDResolverService
        │   │                 → SignatureVerifier.verifyLinkedDataSignature()
        │   │
        │   └── 3. Check revocation            ← isRevoked()
        │       └── StatusListService.checkRevocationStatus()
        │           └── fetch + decode bitstring → check bit
        │
        └── return List<VCVerificationResultDTO>
```
