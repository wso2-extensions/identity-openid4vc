# OID4VP Common Module

**Package:** `org.wso2.carbon.identity.openid4vc.oid4vp.common`

## Purpose

Foundation layer providing shared kernel components used across all OID4VP modules. This module has **no dependencies** on other OID4VP modules.

## Package Structure

| Package | Description |
|---------|-------------|
| `constant` | Protocol constants, endpoint paths, error codes, config keys |
| `dto` | Data Transfer Objects for API communication |
| `exception` | Custom exception hierarchy |
| `model` | Domain entities |
| `util` | Shared utility classes |

## Key Classes

### Constants (`OpenID4VPConstants`)
Defines all constants organized into inner classes:
- `Protocol` – response types, response modes
- `RequestParams` / `ResponseParams` – HTTP parameter names
- `ErrorCodes` – spec-defined error codes
- `VCFormats` – `jwt_vp`, `ldp_vp`, `vc+sd-jwt`, etc.
- `Endpoints` – API paths (`/vp-request`, `/response`, etc.)
- `ConfigKeys` – `deployment.toml` property keys
- `HTTP` – content types, headers

### Models
| Class | Description |
|-------|-------------|
| `VPRequest` | Represents a Verifiable Presentation request |
| `VPSubmission` | Wallet's response containing `vp_token` and `presentation_submission` |
| `VPRequestStatus` | Enum: `CREATED`, `PENDING`, `VP_SUBMITTED`, `COMPLETED`, `EXPIRED`, `CANCELLED` |
| `PresentationDefinition` | DIF Presentation Exchange definition |
| `DIDDocument` / `DIDKey` | DID Document and key models |
| `VerifiableCredential` | Parsed VC with format, issuer, subject, proof |
| `VerifiablePresentation` | Parsed VP with format, holder, credentials |
| `TrustedIssuer` / `TrustedVerifier` | Trust framework models |
| `RevocationCheckResult` | Status list revocation result |

### DTOs
| Class | Description |
|-------|-------------|
| `VPRequestCreateDTO` | Input for creating VP requests |
| `VPRequestResponseDTO` | Response after VP request creation |
| `VPSubmissionDTO` | Wallet submission data |
| `PresentationSubmissionDTO` | DIF Presentation Submission with `descriptor_map` |
| `DescriptorMapDTO` | Format + path for each credential in the VP |
| `VCVerificationResultDTO` | Verification result with status and details |

### Exceptions
| Class | Description |
|-------|-------------|
| `VPException` | Base exception |
| `CredentialVerificationException` | VC/VP verification failure |
| `DIDResolutionException` | DID resolution failure |
| `VPRequestNotFoundException` | VP request not found |
| `VPSubmissionValidationException` | Invalid wallet submission |

### Utilities
| Class | Description |
|-------|-------------|
| `SecurityUtils` | Safe redirect URI validation, input sanitization |
| `CORSUtil` | CORS header management |
| `LogSanitizer` | CRLF injection prevention |
| `URLValidator` | URL validation |
| `PresentationDefinitionUtil` | Presentation definition JSON helpers |
