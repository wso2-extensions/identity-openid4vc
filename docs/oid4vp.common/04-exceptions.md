# 04 — Exception Hierarchy

---

## Hierarchy Diagram

```
java.lang.Exception
├── VPException  (base, adds errorCode)
│   ├── CredentialVerificationException      (+verificationStatus, vcIndex)
│   ├── DIDResolutionException               (+did, method; static factories)
│   ├── PresentationDefinitionNotFoundException (+definitionId)
│   ├── RevocationCheckException             (+statusListUrl, statusIndex, statusType; static factories)
│   ├── VPRequestExpiredException            (+requestId, expiredAt)
│   ├── VPRequestNotFoundException           (+requestId)
│   ├── VPSubmissionValidationException      (simple)
│   ├── VPSubmissionWalletErrorException     (+walletError, walletErrorDescription)
│   └── VPTokenExpiredException              (simple)
│
└── DIDDocumentException  ⚠️ NOT under VPException
```

---

## Base Exception: VPException

```java
public class VPException extends Exception {
    private final String errorCode;

    public VPException(String message)
    public VPException(String errorCode, String message)
    public VPException(String message, Throwable cause)
    public VPException(String errorCode, String message, Throwable cause)
}
```

All domain exceptions extend this **except** `DIDDocumentException` (see issue below).

---

## Exception Reference

### 1. CredentialVerificationException

**When thrown**: A specific VC within a VP fails verification.

**Extra fields**:
- `verificationStatus` — `VCVerificationStatus` enum (INVALID, EXPIRED, REVOKED, ERROR)
- `vcIndex` — Position of the failing VC in the VP

**Constructors**:
```java
CredentialVerificationException(String message, VCVerificationStatus status)
CredentialVerificationException(String message, VCVerificationStatus status, int vcIndex)
CredentialVerificationException(String message, Throwable cause, VCVerificationStatus status)
```

---

### 2. DIDResolutionException

**When thrown**: Resolving a DID to a DID Document fails.

**Extra fields**:
- `did` — The DID being resolved
- `method` — The DID method (e.g., `web`, `jwk`, `key`)

**Static Factory Methods** (preferred over constructors):
```java
DIDResolutionException.unsupportedMethod(String method)
DIDResolutionException.networkError(String did, Throwable cause)
DIDResolutionException.invalidDocument(String did, String reason)
DIDResolutionException.keyNotFound(String did, String keyId)
DIDResolutionException.invalidFormat(String did)
```

Each factory sets appropriate error codes:
- `UNSUPPORTED_METHOD`
- `NETWORK_ERROR`
- `INVALID_DOCUMENT`
- `KEY_NOT_FOUND`
- `INVALID_FORMAT`

---

### 3. PresentationDefinitionNotFoundException

**When thrown**: A referenced Presentation Definition ID does not exist in the database.

**Extra field**: `definitionId` — The PD ID that was not found.

```java
PresentationDefinitionNotFoundException(String definitionId)
PresentationDefinitionNotFoundException(String definitionId, Throwable cause)
```

---

### 4. RevocationCheckException

**When thrown**: Checking a credential's revocation status fails.

**Extra fields**:
- `statusListUrl` — URL of the StatusList2021 credential
- `statusIndex` — Index within the status list bitstring
- `statusType` — Type of status check (e.g., `StatusList2021`)

**Static Factory Methods**:
```java
RevocationCheckException.networkError(String url, Throwable cause)
RevocationCheckException.invalidStatusList(String url, String reason)
RevocationCheckException.unsupportedStatusType(String statusType)
RevocationCheckException.invalidIndex(String url, int index, String reason)
RevocationCheckException.decodingError(String url, Throwable cause)
```

Error codes:
- `NETWORK_ERROR`
- `INVALID_STATUS_LIST`
- `UNSUPPORTED_STATUS_TYPE`
- `INVALID_INDEX`
- `DECODING_ERROR`

---

### 5. VPRequestExpiredException

**When thrown**: A VP request is accessed after its TTL.

**Extra fields**:
- `requestId` — The expired request's ID
- `expiredAt` — When it expired (millis timestamp)

---

### 6. VPRequestNotFoundException

**When thrown**: A VP request ID does not exist.

**Extra field**: `requestId`

---

### 7. VPSubmissionValidationException

**When thrown**: The wallet's VP submission fails structural validation (e.g., missing `vp_token` and no error).

No extra fields — uses the base `VPException` error code + message.

---

### 8. VPSubmissionWalletErrorException

**When thrown**: The wallet explicitly returned an error instead of a VP token.

**Extra fields**:
- `walletError` — Error code from the wallet (e.g., `user_cancelled`)
- `walletErrorDescription` — Human-readable error from wallet

---

### 9. VPTokenExpiredException

**When thrown**: The VP token itself (JWT) has expired (`exp` claim in the past).

No extra fields — uses the base `VPException` error code + message.

---

### 10. DIDDocumentException ⚠️

**When thrown**: Parsing or processing a DID Document fails.

```java
public class DIDDocumentException extends Exception {  // ← NOT VPException!
    public DIDDocumentException(String message)
    public DIDDocumentException(String message, Throwable cause)
}
```

---

## Exception Usage Pattern

### In Service Layer (Presentation Module)
```java
try {
    DIDDocument doc = didResolver.resolve(clientId);
} catch (DIDResolutionException e) {
    // Has did, method, errorCode available for structured error response
    throw new VPException(e.getErrorCode(), "Failed to resolve verifier DID", e);
}
```

### In Endpoint Layer
```java
try {
    result = vpService.processSubmission(submissionDTO);
} catch (VPRequestNotFoundException e) {
    return Response.status(404).entity(new ErrorDTO(
        ErrorDTO.ErrorCode.VP_REQUEST_NOT_FOUND.getCode(),
        "Request not found: " + e.getRequestId()
    )).build();
} catch (VPRequestExpiredException e) {
    return Response.status(400).entity(new ErrorDTO(
        ErrorDTO.ErrorCode.VP_REQUEST_EXPIRED.getCode(),
        "Request expired at: " + e.getExpiredAt()
    )).build();
}
```

---

## Code Review Notes

| Issue | Severity | Details |
|---|---|---|
| **`DIDDocumentException` extends `Exception`, not `VPException`** | High | Breaks the exception hierarchy. Catching `VPException` won't catch DID document errors. Should extend `VPException` with an appropriate error code. |
| **No shared error code constants** | Medium | Error codes are hardcoded strings in static factories (e.g., `"NETWORK_ERROR"`, `"INVALID_DOCUMENT"`). Should be constants in `OpenID4VPConstants.ErrorCodes` or an enum. |
| **Factory methods vs constructors inconsistency** | Low | `DIDResolutionException` and `RevocationCheckException` use static factories. Others use direct constructors. Consider standardizing. |
| **`VPException` is not `Serializable`-friendly** | Low | `errorCode` is `final` which is good, but `Exception` implements `Serializable` and the field should ideally have `serialVersionUID` considerations. |
| **`CredentialVerificationException` default vcIndex = -1** | Info | Sentinel value `-1` for unknown index. Consider using `OptionalInt` or a separate constructor without vcIndex. |
| **Missing exception for VP format errors** | Info | No dedicated exception for VP format/parsing errors. Currently uses generic `VPException`. |
