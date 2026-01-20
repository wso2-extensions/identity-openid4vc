# OpenID4VP Exception Package

## Package: `org.wso2.carbon.identity.openid4vc.presentation.exception`

This package contains all custom exceptions for error handling in the OpenID4VP component.

---

## Exception Hierarchy

```
VPException (base)
├── VPRequestNotFoundException
├── VPRequestExpiredException
├── VPSubmissionNotFoundException
├── VPSubmissionValidationException
├── VPSubmissionWalletErrorException
├── VPTokenExpiredException
├── PresentationDefinitionNotFoundException
├── CredentialVerificationException
├── DIDResolutionException
├── DIDDocumentException
└── RevocationCheckException
```

---

## Detailed Exception Documentation

### 1. VPException.java (Base Exception)

**Location:** [VPException.java](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/exception/VPException.java)

**Purpose:** Base exception for all VP-related errors.

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| `errorCode` | String | OAuth2 error code |
| `errorDescription` | String | Human-readable description |

#### Constructors

```java
public VPException(String message)
public VPException(String message, Throwable cause)
public VPException(String errorCode, String errorDescription)
public VPException(String errorCode, String errorDescription, Throwable cause)
```

---

### 2. VPRequestNotFoundException

**Purpose:** Thrown when a VP request ID cannot be found.

| Error Code | HTTP Status |
|------------|-------------|
| `request_not_found` | 404 |

**When Thrown:**
- Polling for a non-existent request
- Wallet fetches invalid request-uri
- Result lookup for unknown request

```java
throw new VPRequestNotFoundException(
    "VP request not found: " + requestId
);
```

---

### 3. VPRequestExpiredException

**Purpose:** Thrown when a VP request has expired.

| Error Code | HTTP Status |
|------------|-------------|
| `expired_request` | 400 |

**When Thrown:**
- Wallet submits to expired request
- Request timeout (default 5 min)

```java
if (request.getExpiresAt().isBefore(Instant.now())) {
    throw new VPRequestExpiredException(
        "VP request has expired: " + requestId
    );
}
```

---

### 4. VPSubmissionNotFoundException

**Purpose:** Thrown when a submission ID cannot be found.

| Error Code | HTTP Status |
|------------|-------------|
| `submission_not_found` | 404 |

**When Thrown:**
- Result lookup for unknown submission

---

### 5. VPSubmissionValidationException

**Purpose:** Thrown when VP submission fails validation.

| Error Code | HTTP Status |
|------------|-------------|
| `invalid_request` | 400 |

**When Thrown:**
- Nonce mismatch
- State mismatch
- Missing required parameter
- Invalid VP structure

```java
if (!vpNonce.equals(expectedNonce)) {
    throw new VPSubmissionValidationException(
        "invalid_request",
        "Nonce does not match the request nonce"
    );
}
```

---

### 6. VPSubmissionWalletErrorException

**Purpose:** Thrown when wallet returns an error response.

| Error Code | HTTP Status |
|------------|-------------|
| (from wallet) | 400 |

**Wallet Error Types:**

| Error | Description |
|-------|-------------|
| `access_denied` | User denied consent |
| `user_cancelled` | User cancelled flow |
| `credential_not_available` | No matching credential |
| `invalid_request` | Wallet couldn't parse request |

```java
if (errorParam != null) {
    throw new VPSubmissionWalletErrorException(
        errorParam,
        errorDescriptionParam
    );
}
```

---

### 7. VPTokenExpiredException

**Purpose:** Thrown when the VP token itself has expired.

| Error Code | HTTP Status |
|------------|-------------|
| `expired_token` | 400 |

**When Thrown:**
- VP JWT `exp` claim is in the past

---

### 8. PresentationDefinitionNotFoundException

**Purpose:** Thrown when a presentation definition cannot be found.

| Error Code | HTTP Status |
|------------|-------------|
| `definition_not_found` | 404 |

**When Thrown:**
- Creating VP request with invalid definition ID
- Definition lookup fails

---

### 9. CredentialVerificationException

**Purpose:** Thrown when VC verification fails.

| Error Code | HTTP Status |
|------------|-------------|
| `invalid_proof` | 400 |

**Verification Failure Reasons:**

| Reason | Description |
|--------|-------------|
| `INVALID_SIGNATURE` | Signature doesn't match |
| `EXPIRED` | VC expiration date passed |
| `REVOKED` | VC in revocation list |
| `UNTRUSTED_ISSUER` | Issuer not trusted |
| `CONSTRAINT_VIOLATION` | Doesn't match constraints |

```java
try {
    signatureVerifier.verify(vcJwt, issuerDid);
} catch (Exception e) {
    throw new CredentialVerificationException(
        "invalid_proof",
        "Signature verification failed: " + e.getMessage(),
        e
    );
}
```

---

### 10. DIDResolutionException

**Purpose:** Thrown when DID document resolution fails.

| Error Code | HTTP Status |
|------------|-------------|
| `did_resolution_failed` | 500 |

**When Thrown:**
- HTTP request to DID document fails
- DID method not supported
- Universal resolver error

```java
try {
    return httpClient.get(url);
} catch (IOException e) {
    throw new DIDResolutionException(
        "Failed to resolve DID: " + did,
        e
    );
}
```

---

### 11. DIDDocumentException

**Purpose:** Thrown when DID document parsing fails.

| Error Code | HTTP Status |
|------------|-------------|
| `invalid_did_document` | 500 |

**When Thrown:**
- Invalid JSON structure
- Missing required fields
- Invalid verification method

---

### 12. RevocationCheckException

**Purpose:** Thrown when revocation status check fails.

| Error Code | HTTP Status |
|------------|-------------|
| `revocation_check_failed` | 500 |

**When Thrown:**
- Status list fetch fails
- Invalid status list format
- Bit index out of range

---

## Error Response Handling

### Servlet Error Handler Pattern

```java
try {
    // Process request
    vpSubmissionService.processSubmission(dto);
    response.setStatus(HttpServletResponse.SC_OK);
    
} catch (VPRequestNotFoundException e) {
    sendError(response, HttpServletResponse.SC_NOT_FOUND, 
        e.getErrorCode(), e.getErrorDescription());
        
} catch (VPSubmissionValidationException e) {
    sendError(response, HttpServletResponse.SC_BAD_REQUEST,
        e.getErrorCode(), e.getErrorDescription());
        
} catch (CredentialVerificationException e) {
    sendError(response, HttpServletResponse.SC_BAD_REQUEST,
        e.getErrorCode(), e.getErrorDescription());
        
} catch (Exception e) {
    sendError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
        "server_error", "Internal server error");
}
```

### Error Response Format

```json
{
  "error": "invalid_request",
  "error_description": "The nonce in the VP does not match the request nonce"
}
```
