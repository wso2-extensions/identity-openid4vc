# 00 — OID4VP Common Module Overview

> **Module**: `org.wso2.carbon.identity.openid4vc.oid4vp.common`
> **Packaging**: OSGi `bundle`
> **Java**: 21 (compile), 11 (bundle execution environment)
> **Role**: Shared kernel for all OID4VP modules — models, DTOs, constants, exceptions, and utilities

---

## 1. Purpose

This is the **foundational dependency** for every other OID4VP module (`oid4vp.presentation`, `oid4vp.did`, `oid4vp.verification`). It contains:

- **Constants** — Protocol strings, config keys, defaults, cache key prefixes
- **Models** — Domain objects: `VPRequest`, `VPSubmission`, `DIDDocument`, `VerifiableCredential`, `VerifiablePresentation`, etc.
- **DTOs** — Serializable transfer objects for REST APIs and inter-module communication
- **Exceptions** — Typed exception hierarchy rooted at `VPException`
- **Utilities** — Security, CORS, URL validation, Presentation Definition parsing, log sanitization

---

## 2. Package Structure

```
org.wso2.carbon.identity.openid4vc.oid4vp.common/
├── constant/
│   └── OpenID4VPConstants.java          ← All protocol/config/format constants
├── dto/
│   ├── AuthorizationDetailsDTO.java     ← Authorization request by-value
│   ├── DescriptorMapDTO.java            ← Presentation submission mapping
│   ├── ErrorDTO.java                    ← Standard error responses + ErrorCode enum
│   ├── PathNestedDTO.java               ← Nested credential path
│   ├── PresentationDefinitionResponseDTO.java  ← Full PD response (nested DTOs)
│   ├── PresentationSubmissionDTO.java   ← Wallet's submission descriptor
│   ├── VCVerificationResultDTO.java     ← Per-VC verification result
│   ├── VPRequestCreateDTO.java          ← VP request creation input
│   ├── VPRequestResponseDTO.java        ← VP request creation response
│   ├── VPRequestStatusDTO.java          ← Status check response
│   ├── VPResultDTO.java                 ← Full VP verification result
│   ├── VPStatusResponseDTO.java         ← Polling status response
│   └── VPSubmissionDTO.java             ← Wallet VP token submission
├── exception/
│   ├── VPException.java                 ← Base exception (errorCode + message)
│   ├── CredentialVerificationException.java
│   ├── DIDDocumentException.java
│   ├── DIDResolutionException.java
│   ├── PresentationDefinitionNotFoundException.java
│   ├── RevocationCheckException.java
│   ├── VPRequestExpiredException.java
│   ├── VPRequestNotFoundException.java
│   ├── VPSubmissionValidationException.java
│   ├── VPSubmissionWalletErrorException.java
│   └── VPTokenExpiredException.java
├── model/
│   ├── DIDDocument.java                 ← W3C DID Document + VerificationMethod + Service
│   ├── DIDKey.java                      ← Key material (pub/priv bytes)
│   ├── PresentationDefinition.java      ← DB-backed PD entity
│   ├── RevocationCheckResult.java       ← Revocation status check result
│   ├── TrustedIssuer.java               ← Trusted credential issuer
│   ├── TrustedVerifier.java             ← Trusted verifier entity
│   ├── VCVerificationStatus.java        ← Enum: SUCCESS, INVALID, EXPIRED, REVOKED, ERROR
│   ├── VerifiableCredential.java        ← W3C VC Data Model (JWT + JSON-LD + SD-JWT)
│   ├── VerifiablePresentation.java      ← W3C VP container
│   ├── VPRequest.java                   ← Authorization request state
│   ├── VPRequestStatus.java             ← Enum: ACTIVE, VP_SUBMITTED, EXPIRED, COMPLETED, CANCELLED
│   └── VPSubmission.java                ← Wallet's submission record
└── util/
    ├── CORSUtil.java                    ← CORS header management
    ├── LogSanitizer.java                ← CRLF injection prevention for logs
    ├── OpenID4VPUtil.java               ← ID generation, config reads, URL builders
    ├── PresentationDefinitionUtil.java  ← PD JSON validation, parsing, building
    ├── SecurityUtils.java               ← Crypto, validation, hashing, timing-safe compare
    └── URLValidator.java                ← URL scheme validation, redirect URI checking
```

---

## 3. Dependencies

| Dependency | Usage |
|---|---|
| `com.google.code.gson` | JSON serialization for DTOs (via `@SerializedName`), PD parsing |
| `org.wso2.carbon.identity.core` | `IdentityUtil.getProperty()` — reads `identity.xml` / `openid4vp.properties` config |
| `org.apache.commons:commons-lang3` | `StringUtils` for null-safe string operations |
| `javax.servlet-api` (provided) | `HttpServletRequest`/`HttpServletResponse` in `CORSUtil` |
| `org.slf4j:slf4j-api` | Logging |

---

## 4. OSGi Bundle Configuration

```xml
<Export-Package>
    org.wso2.carbon.identity.openid4vc.oid4vp.common.*;version="${identity.oid4vc.pkg.version}"
</Export-Package>
<DynamicImport-Package>*</DynamicImport-Package>
```

- **Everything is exported** — this is a shared library bundle
- No `Private-Package` — no internal classes hidden from consumers
- No embedded JARs — Gson is imported from the OSGi runtime

---

## 5. How Other Modules Use This

```
┌──────────────────────┐     ┌──────────────────────┐
│ oid4vp.presentation  │     │ oid4vp.verification  │
│                      │     │                      │
│ Uses: VPRequest,     │     │ Uses: VerifiableCred,│
│ VPSubmission, DTOs,  │     │ DIDDocument,         │
│ PD model, constants, │     │ RevocationCheckResult│
│ exceptions, utils    │     │ VCVerificationStatus │
└──────────┬───────────┘     └──────────┬───────────┘
           │                            │
           ▼                            ▼
┌─────────────────────────────────────────────────┐
│            oid4vp.common                         │
│  constants + models + DTOs + exceptions + utils  │
└─────────────────────────────────────────────────┘
           ▲
           │
┌──────────┴───────────┐
│ oid4vp.did           │
│                      │
│ Uses: DIDDocument,   │
│ DIDKey, DID consts,  │
│ DIDResolutionExc     │
└──────────────────────┘
```

---

## 6. WSO2 IS Integration Points

| Integration | How |
|---|---|
| **Configuration** | `IdentityUtil.getProperty()` reads from `identity.xml` → `<OpenID4VP>` section |
| **Multi-tenancy** | `tenantId` field on `PresentationDefinition`, `VPRequest`, `VPSubmission`, `DIDKey`, `TrustedIssuer` |
| **Servlet API** | `CORSUtil` works with `HttpServletRequest`/`HttpServletResponse` from OSGi HttpService |
| **DB storage** | `PresentationDefinition` model maps to `IDN_PRESENTATION_DEFINITION` table (in `oid4vp.presentation` DAO) |

---

## 7. File Count & Line Estimates

| Package | Files | Purpose |
|---|---|---|
| `constant` | 1 | ~340 lines — 14 inner classes of constants |
| `model` | 12 | ~2,200 lines — Domain objects with builders |
| `dto` | 13 | ~2,500 lines — API transfer objects with Gson annotations |
| `exception` | 11 | ~700 lines — Typed exception hierarchy |
| `util` | 6 | ~1,200 lines — Security, CORS, validation, PD parsing |
| **Total** | **43** | **~7,000 lines** |
