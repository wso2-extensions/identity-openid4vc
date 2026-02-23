# 03 — Data Transfer Objects (DTOs)

---

## DTO Inventory

| DTO | Inner Classes | Serialization | Validation | Role |
|---|---|---|---|---|
| `AuthorizationDetailsDTO` | — | Gson | — | By-value authorization request |
| `VPRequestCreateDTO` | — | Gson | `isValid()` | VP request creation input |
| `VPRequestResponseDTO` | — | Gson | `isByReference()` | VP request creation output |
| `VPRequestStatusDTO` | — | Gson | `getStatusEnum()` | Status poll response |
| `VPSubmissionDTO` | — | Gson | `isValid()` | Wallet VP token submission |
| `PresentationSubmissionDTO` | — | Gson | `isValid()` | Submission descriptor mapping |
| `DescriptorMapDTO` | — | Gson | `isValid()` | Single descriptor-to-path mapping |
| `PathNestedDTO` | — | Gson | — | Nested credential path |
| `PresentationDefinitionResponseDTO` | **6 inner DTOs** | Gson | — | Full PD response (DIF PE format) |
| `VPResultDTO` | — | Gson | `isAllSuccess()` | Complete VP verification result |
| `VCVerificationResultDTO` | — | Gson | — | Per-credential verification result |
| `VPStatusResponseDTO` | — | — | — | Status + `toJson()` |
| `ErrorDTO` | `ErrorCode` enum | Gson | — | Standard error response |

---

## OID4VP Request Flow DTOs

### 1. VPRequestCreateDTO

Input DTO for creating a new VP request. Mirrors the verifier-side API.

**Fields**:
| Field | Annotation | Type | Purpose |
|---|---|---|---|
| `clientId` | `@SerializedName("client_id")` | String | Verifier's DID or client ID |
| `transactionId` | `@SerializedName("transaction_id")` | String | Optional external transaction ref |
| `presentationDefinitionId` | `@SerializedName("presentation_definition_id")` | String | Reference to stored PD |
| `presentationDefinition` | `@SerializedName("presentation_definition")` | JsonObject | Inline PD (alternative) |
| `nonce` | — | String | Auto-generated if null |
| `responseMode` | `@SerializedName("response_mode")` | String | `direct_post` or `direct_post.jwt` |
| `didMethod` | `@SerializedName("did_method")` | String | DID method for signing |
| `signingAlgorithm` | `@SerializedName("signing_algorithm")` | String | JWT signing algorithm |

**Validation** (`isValid()`): Requires `clientId` AND (`presentationDefinitionId` OR inline `presentationDefinition`).

**Convenience**: `hasInlinePresentationDefinition()` — True if `presentationDefinition != null`.

### 2. AuthorizationDetailsDTO

Represents a **by-value** authorization request — all parameters inline in the URL or request body.

**Fields**:
| Field | Annotation | Default |
|---|---|---|
| `clientId` | `@SerializedName("client_id")` | — |
| `responseType` | `@SerializedName("response_type")` | `"vp_token"` |
| `responseMode` | `@SerializedName("response_mode")` | `"direct_post"` |
| `responseUri` | `@SerializedName("response_uri")` | — |
| `nonce` | — | — |
| `state` | — | — |
| `presentationDefinition` | `@SerializedName("presentation_definition")` | JsonObject |

**Deep Copying**: Both the copy constructor and `setPresentationDefinition()` perform `deepCopy()` on the Gson `JsonObject`, preventing mutation of shared references.

### 3. VPRequestResponseDTO

Output DTO for VP request creation. Supports two modes:

- **By-value**: Contains an `AuthorizationDetailsDTO` with all parameters inline
- **By-reference**: Contains a `requestUri` pointing to a signed JWT (JAR)

**Check**: `isByReference()` — True when `requestUri != null`.

### 4. VPRequestStatusDTO

Simple poll response:
- `status` (String) — The raw status string
- `requestId` — Correlation ID

**Conversion**: `getStatusEnum()` → `VPRequestStatus.fromValue(status)`

---

## OID4VP Submission Flow DTOs

### 5. VPSubmissionDTO

What the wallet sends to the verifier's `response_uri`.

**Fields**:
| Field | Annotation | Type |
|---|---|---|
| `vpToken` | `@SerializedName("vp_token")` | String |
| `presentationSubmission` | `@SerializedName("presentation_submission")` | JsonObject |
| `state` | — | String |
| `error` | — | String |
| `errorDescription` | `@SerializedName("error_description")` | String |

**Validation** (`isValid()`): Enforces OID4VP spec — either:
- `vp_token` + `presentation_submission` are both present, OR
- `error` is present (wallet error response)

Cannot have both `vp_token` and `error` simultaneously.

### 6. PresentationSubmissionDTO

Maps input descriptors to credential locations in the VP token:
- `id` — Submission ID
- `definitionId` (`definition_id`) — Must match the PD's `id`
- `descriptorMap` (`descriptor_map`) — `List<DescriptorMapDTO>`

**Validation** (`isValid()`): Requires non-empty `definitionId` and at least one descriptor map entry.

### 7. DescriptorMapDTO

Maps a single input descriptor to a credential in the VP:
- `id` — Matches `InputDescriptor.id`
- `format` — Credential format (e.g., `jwt_vp_json`)
- `path` — JSONPath to the credential (e.g., `$`)
- `pathNested` — `PathNestedDTO` for nested credentials

**Validation** (`isValid()`): Requires `id`, `format`, and `path`.

### 8. PathNestedDTO

For JWT VP tokens where the actual VC is embedded:
- `format` — Format of the nested credential (e.g., `jwt_vc_json`)
- `path` — JSONPath to the nested VC (e.g., `$.vp.verifiableCredential[0]`)

Has a copy constructor for defensive copying.

---

## Presentation Definition DTOs

### 9. PresentationDefinitionResponseDTO

The most complex DTO — represents a full DIF Presentation Exchange definition. Contains **6 nested inner DTO classes**.

#### Class Hierarchy:
```
PresentationDefinitionResponseDTO
├── id, name, purpose, format
├── inputDescriptors: List<InputDescriptorDTO>
│   ├── id, name, purpose, group
│   ├── format: FormatDTO
│   │   ├── ldp_vc, ldp_vp, jwt_vc, jwt_vp,
│   │   │   jwt_vc_json, jwt_vp_json, vc_sd_jwt: FormatDetailDTO
│   │   │       ├── proofType: List<String>
│   │   │       └── alg: List<String>
│   ├── constraints: ConstraintsDTO
│   │   ├── limitDisclosure: String ("required"|"preferred")
│   │   └── fields: List<FieldDTO>
│   │       ├── path: List<String>  (JSONPath)
│   │       ├── filter: FilterDTO
│   │       │   ├── type, pattern, const_
│   │       │   ├── enum_, minimum, maximum
│   │       │   └── not: FilterDTO (recursive)
│   │       ├── optional: Boolean
│   │       └── predicate: String
│   └── group: String
└── submissionRequirements: List<SubmissionRequirementDTO>
    ├── rule: String ("all"|"pick")
    ├── count, min, max: Integer
    ├── from: String
    └── fromNested: List<SubmissionRequirementDTO> (recursive)
```

#### FormatDTO
Maps credential format identifiers to their acceptable algorithms/proof types:
```java
@SerializedName("ldp_vc")   FormatDetailDTO ldpVc;
@SerializedName("ldp_vp")   FormatDetailDTO ldpVp;
@SerializedName("jwt_vc")   FormatDetailDTO jwtVc;
@SerializedName("jwt_vp")   FormatDetailDTO jwtVp;
@SerializedName("jwt_vc_json") FormatDetailDTO jwtVcJson;
@SerializedName("jwt_vp_json") FormatDetailDTO jwtVpJson;
@SerializedName("vc+sd-jwt")  FormatDetailDTO vcSdJwt;
```

#### FilterDTO
JSON Schema-like filter for credential fields. Notable: `const_` with `@SerializedName("const")` works around Java reserved word. Recursive via `not` field.

#### All inner classes have copy constructors for full deep copying.

---

## Verification Result DTOs

### 10. VPResultDTO

Full VP verification result:
- `transactionId`, `requestId`
- `status` — Overall status string
- `overallResult` — Boolean: all VCs passed
- `holder` — VP holder DID
- `vcCount` — Number of VCs
- `vcVerificationResults` — `List<VCVerificationResultDTO>`
- `error`, `errorDetails`

**Method**: `isAllSuccess()` — Checks `overallResult && all VCVerificationResultDTOs have SUCCESS`.

### 11. VCVerificationResultDTO

Per-credential verification result. Uses **Builder pattern**.

**Fields**:
| Field | Type | Purpose |
|---|---|---|
| `vcIndex` | int | Position in VP |
| `verificationStatus` | String | SUCCESS, INVALID, etc. |
| `credentialType` | String | Primary type |
| `credentialTypes` | String[] | All types |
| `issuer` | String | Issuer DID |
| `issuerId` | String | Issuer ID (may differ) |
| `subject` | String | Subject DID |
| `issuanceDate` | String | ISO 8601 |
| `expirationDate` | String | ISO 8601 |
| `credentialId` | String | VC ID |
| `format` | String | JWT, JSON-LD, etc. |
| `signatureValid` | Boolean | Signature check |
| `expired` | Boolean | Expiry check |
| `revoked` | Boolean | Revocation check |
| `error` | String | Error code |
| `errorDetails` | String | Error message |

### 12. VPStatusResponseDTO

Serializable status response with `toJson()` method (uses Gson):
- `requestId`, `status`, `tokenReceived` (boolean), `expired` (boolean)
- `error`, `errorDescription`, `transactionId`, `expiresIn` (seconds)

---

## Error DTOs

### 13. ErrorDTO

Standard OID4VP error response:
- `error` — Error type string
- `errorDescription` — Human-readable message
- `errorCode` — Optional numeric/string code

### ErrorCode Enum (Inner)

| Value | Description |
|---|---|
| `INVALID_REQUEST` | Malformed request |
| `INVALID_CLIENT` | Unknown client/verifier |
| `INVALID_TOKEN` | Invalid VP token |
| `MISSING_PARAMETER` | Required parameter missing |
| `PRESENTATION_DEFINITION_NOT_FOUND` | PD ID not found |
| `VP_REQUEST_NOT_FOUND` | Request ID not found |
| `VP_SUBMISSION_NOT_FOUND` | Submission not found |
| `INVALID_TRANSACTION_ID` | Bad transaction correlation |
| `VP_REQUEST_EXPIRED` | Request TTL exceeded |
| `VERIFICATION_FAILED` | VP/VC verification failed |
| `INTERNAL_ERROR` | Server-side error |
| `INVALID_VP_TOKEN` | Structurally invalid VP |

---

## Gson Serialization Pattern

All DTOs use `@SerializedName` for JSON field mapping. This ensures snake_case JSON field names map to camelCase Java fields:

```java
@SerializedName("client_id")
private String clientId;

@SerializedName("presentation_definition")
private JsonObject presentationDefinition;
```

### JsonObject Deep Copying

Several DTOs handle Gson's `JsonObject` (mutable reference type) defensively:

```java
// In AuthorizationDetailsDTO
public void setPresentationDefinition(JsonObject pd) {
    this.presentationDefinition = pd != null ? pd.deepCopy() : null;
}
```

This prevents callers from mutating the DTO's internal state after construction.

---

## Code Review Notes

| Issue | Severity | Details |
|---|---|---|
| **`PresentationDefinitionResponseDTO` is 400+ lines** | Medium | 7 nested classes in one file. Consider separate files per inner class. |
| **No `@JsonAdapter` or custom deserializers** | Info | All deserialization relies on Gson defaults + `@SerializedName`. Works but fragile for complex nested structures. |
| **`FilterDTO.const_` rename workaround** | Low | `@SerializedName("const")` — acceptable pattern, should be documented. |
| **Inconsistent `isValid()` coverage** | Medium | Some DTOs have validation (`VPSubmissionDTO`, `VPRequestCreateDTO`), others don't. Consider adding to `AuthorizationDetailsDTO`. |
| **`VCVerificationResultDTO` duplicates `credentialType` + `credentialTypes`** | Low | Redundant — `credentialType` is always `credentialTypes[0]`. |
| **No null safety on Gson deserialization** | Medium | If a JSON response is missing fields, Gson silently sets them to `null`. No `@NonNull` annotations or post-deserialization validation except where `isValid()` exists. |
| **`VPStatusResponseDTO.toJson()` creates new `Gson()` per call** | Low | Should cache a static `Gson` instance for performance. |
| **Deep copy in copy constructors** | Good | Defensive copying is thorough in `PresentationDefinitionResponseDTO` and its nested classes. |
