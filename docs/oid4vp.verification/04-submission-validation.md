# 04 — VP Submission Validation

This document covers `VPSubmissionValidator.java` (517 lines) — the structural validation layer for wallet VP submissions.

---

## Purpose

`VPSubmissionValidator` validates the **structure and format** of VP submissions received from wallets before cryptographic verification begins. It enforces:
- OID4VP protocol requirements
- VP token format correctness (JWT, SD-JWT, JSON-LD)
- Presentation submission descriptor compliance (DIF Presentation Exchange)
- JSONPath validity for descriptor paths

All methods are `static` — this is a pure utility class with a private constructor.

---

## Supported VP Token Formats

```java
private static final Set<String> SUPPORTED_FORMATS = new HashSet<>();
static {
    SUPPORTED_FORMATS.add("jwt_vp");
    SUPPORTED_FORMATS.add("jwt_vp_json");
    SUPPORTED_FORMATS.add("ldp_vp");
    SUPPORTED_FORMATS.add("vc+sd-jwt");
    SUPPORTED_FORMATS.add("mso_mdoc");
}
```

---

## Validation Methods

### 1. `validateSubmission(VPSubmissionDTO dto)`

Top-level validation entry point for the entire wallet submission:

```
dto is null? → FAIL

state is blank? → FAIL ("state parameter is required")

Has error field?
├── YES → validateErrorResponse(dto)
│         └── Validate error code format
└── NO
    ├── vpToken is blank? → FAIL ("vp_token is required")
    ├── validateVPToken(dto.getVpToken())
    └── presentationSubmission != null?
        └── validatePresentationSubmissionJson(json)
```

**Note**: `state` is **always required** (even for error responses). This is per the OID4VP spec — the wallet must echo back the state to correlate with the original request.

### 2. `validateErrorResponse(VPSubmissionDTO dto)`

Validates wallet error responses against known OID4VP error codes:

```java
"invalid_request"
"unauthorized_client"
"access_denied"
"server_error"
"user_cancelled"
"credential_not_available"
"vp_formats_not_supported"
```

Also allows **extensible error codes** matching `^[a-z_]+$`.

### 3. `validateVPToken(String vpToken)`

Detects and validates the VP token format:

```
Token starts with "[" → validateVPTokenArray()
Token starts with "{" → validateJsonLdVP()
Token contains "~"    → validateSdJwtVP()
Token is JWT format   → validateJwtVP()
None of the above     → FAIL ("VP token format is not recognized")
```

### 4. Format-Specific Validators

#### `validateJwtVP(String jwt)`
- Must have exactly 3 dot-separated parts
- Each part must be valid Base64URL: `^[A-Za-z0-9_-]*$`

#### `validateSdJwtVP(String sdJwt)`
- Split on `~`
- First part must be valid JWT format (3 dots)

#### `validateJsonLdVP(String vpJson)`
- Must be valid JSON (parseable by Gson)
- Must have `"type"` field
- Type must contain `"VerifiablePresentation"` (in array or as string)

#### `validateVPTokenArray(String vpTokenArray)`
- Parse as JSON array
- Array must not be empty
- Each element:
  - String primitive → recursively `validateVPToken()`
  - JSON object → `validateJsonLdVP()`
  - Other → FAIL

### 5. `validatePresentationSubmission(PresentationSubmissionDTO submission)`

Validates the DIF Presentation Exchange submission descriptor:

```
submission is null? → FAIL

submission.id is blank? → FAIL

submission.definition_id is blank? → FAIL

descriptor_map is null/empty? → FAIL

For each descriptor_map[i]:
├── descriptor is null? → FAIL
├── id is blank? → FAIL
├── format is blank? → FAIL
├── path is blank? → FAIL
└── isValidJsonPath(path)?
    └── Must start with "$" or "@"
```

### 6. `validateSubmissionMatchesDefinition(submission, definition)`

Cross-references the submission against the presentation definition:
- `submission.definition_id` must equal `definition.definitionId`
- (No further input descriptor matching is implemented — see review notes)

### 7. `getValidationErrors(VPSubmissionDTO dto)`

Non-throwing alternative that returns a `List<String>` of error messages:
- `null` dto → `["Submission cannot be null"]`
- Missing state → `["state parameter is required"]`
- Missing both vp_token and error → `["Either vp_token or error is required"]`

---

## Validation Flow Diagram

```
Wallet POST to /response
        │
        ▼
VPSubmissionValidator.validateSubmission(dto)
        │
        ├── Validate state parameter
        │
        ├── Error response?
        │   └── Validate error code
        │
        ├── Validate vp_token format
        │   ├── JWT: 3 parts, Base64URL
        │   ├── SD-JWT: first part is JWT
        │   ├── JSON-LD: valid JSON with VP type
        │   └── Array: validate each element
        │
        └── Validate presentation_submission
            ├── Has id, definition_id
            └── Each descriptor has id, format, path (valid JSONPath)
```

---

## Library Usage

| Library | Usage |
|---|---|
| **Gson** (`JsonParser`, `JsonObject`) | JSON parsing for JSON-LD VP validation and presentation submission |
| **Apache Commons Lang** (`StringUtils`) | Null/blank string checks (`isBlank`, `isNotBlank`) |
| **oid4vp.common DTOs** | `VPSubmissionDTO`, `PresentationSubmissionDTO`, `DescriptorMapDTO` |
| **oid4vp.common constants** | `OpenID4VPConstants.VCFormats`, `OpenID4VPConstants.ErrorCodes` |

---

## Code Review Notes

| Issue | Severity | Details |
|---|---|---|
| **`validateSubmissionMatchesDefinition` is incomplete** | Medium | Only checks `definition_id` match. Does not verify that all required input descriptors have corresponding descriptor map entries. The comment says "Additional validation can be added here." |
| **JSONPath validation is minimal** | Low | `isValidJsonPath()` only checks if the path starts with `$` or `@`. Doesn't validate JSONPath syntax (e.g., `$[0].credentialSubject` vs `$[invalid`). |
| **Base64URL regex is permissive** | Low | `^[A-Za-z0-9_-]*$` — allows empty strings and doesn't check padding. An empty JWT part passes validation. |
| **`isJwtFormat` doesn't validate Base64URL parts** | Low | Only checks for exactly 3 dot-separated parts. Doesn't validate that each part is Base64URL encoded. (This is done separately in `validateJwtVP` but not in the detection logic.) |
| **No VP token size limit check** | Medium | Unlike `SecurityUtils.isValidVPTokenSize()` (1MB), the submission validator doesn't enforce a size limit. A wallet could submit an extremely large VP token. |
| **`SUPPORTED_FORMATS` set is defined but not used for validation** | Info | The set is populated with format constants but no method checks incoming formats against it. It's only used as a reference. |
| **Error code validation allows any `[a-z_]+`** | Low | Extensible error codes are good per spec, but this also accepts meaningless codes like `"_"` or `"a"`. |
| **No presentation_submission required for JWT VP** | Info | The OID4VP spec requires `presentation_submission` for VP tokens. The validator only validates it if present but doesn't require it. |
| **Thread safety** | Good | All methods are static with no mutable state. The `GSON` instance is thread-safe. |
| **Private constructor** | Good | Unlike the common module utilities, this class correctly has a private constructor preventing instantiation. |
