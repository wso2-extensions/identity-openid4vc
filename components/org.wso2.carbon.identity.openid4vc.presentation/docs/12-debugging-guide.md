# OpenID4VP Debugging Guide

## 🔍 Key Debug Points by Flow Phase

This guide shows exactly where to set breakpoints for debugging the complete OpenID4VP authentication flow.

---

## Phase 1: Authentication Initiation

When user accesses protected resource and QR code is displayed.

### 🔴 Breakpoints

| Class | Method | Line | What to Check |
|-------|--------|------|---------------|
| [OpenID4VPAuthenticator](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/OpenID4VPAuthenticator.java#L120) | `initiateAuthenticationRequest()` | 120 | Entry point - context, request params |
| [OpenID4VPAuthenticator](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/OpenID4VPAuthenticator.java#L643) | `createVPRequest()` | 643 | Nonce/state generation |
| [OpenID4VPAuthenticator](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/OpenID4VPAuthenticator.java#L691) | `resolvePresentationDefinitionId()` | 691 | Which definition is used |
| [QRCodeUtil](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/util/QRCodeUtil.java) | `generateQRCodeDataURL()` | - | QR code content |

### 📊 Variables to Watch
```
context.getContextIdentifier()
context.getSequenceConfig().getApplicationId()
vpRequest.getId()
vpRequest.getNonce()
vpRequest.getState()
requestUri
qrCodeData
```

---

## Phase 2: Wallet Fetches Request

When wallet scans QR and fetches authorization request.

### 🔴 Breakpoints

| Class | Method | Line | What to Check |
|-------|--------|------|---------------|
| [RequestUriServlet](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/servlet/RequestUriServlet.java) | `doGet()` | - | Request ID from URL |
| [VPRequestServiceImpl](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/VPRequestServiceImpl.java) | `getVPRequest()` | - | Request lookup |
| [VPRequestServiceImpl](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/VPRequestServiceImpl.java) | `buildAuthorizationRequest()` | - | JWT request object |

### 📊 Variables to Watch
```
requestId
vpRequest
presentationDefinition
signedRequestJwt
```

---

## Phase 3: VP Submission (Critical!)

When wallet POSTs VP to `/openid4vp/v1/response`.

### 🔴 Breakpoints

| Class | Method | Line | What to Check |
|-------|--------|------|---------------|
| [VPSubmissionServlet](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/servlet/VPSubmissionServlet.java#L118) | `doPost()` | 118 | **MAIN ENTRY** - raw request |
| [VPSubmissionServlet](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/servlet/VPSubmissionServlet.java#L214) | `parseSubmission()` | 214 | Parse vp_token, state |
| [VPSubmissionServlet](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/servlet/VPSubmissionServlet.java#L313) | `notifyStatusListeners()` | 313 | Status update |
| [VPSubmissionServiceImpl](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/VPSubmissionServiceImpl.java) | `processSubmission()` | - | Validation logic |

### 📊 Variables to Watch
```
vpToken              // Raw VP token (JWT or JSON)
state                // Request ID correlation
presentationSubmission
dto.getVpToken()
dto.getState()
dto.getPresentationSubmission()
```

---

## Phase 4: VC Verification (Most Complex!)

Where signature verification and claims validation happen.

### 🔴 Breakpoints

| Class | Method | Line | What to Check |
|-------|--------|------|---------------|
| [VCVerificationServiceImpl](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/VCVerificationServiceImpl.java#L144) | `verify()` | 144 | Entry for verification |
| [VCVerificationServiceImpl](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/VCVerificationServiceImpl.java#L177) | `verifyCredentialInternal()` | 177 | Core verification |
| [VCVerificationServiceImpl](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/VCVerificationServiceImpl.java#L244) | `verifyVPToken()` | 244 | VP parsing |
| [VCVerificationServiceImpl](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/VCVerificationServiceImpl.java#L290) | `verifySignature()` | 290 | **SIGNATURE CHECK** |
| [VCVerificationServiceImpl](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/VCVerificationServiceImpl.java#L317) | `verifyJwtSignature()` | 317 | JWT signature |
| [VCVerificationServiceImpl](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/VCVerificationServiceImpl.java#L366) | `verifySdJwtSignature()` | 366 | SD-JWT signature |
| [VCVerificationServiceImpl](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/VCVerificationServiceImpl.java#L449) | `isRevoked()` | 449 | Revocation check |

### 📊 Variables to Watch
```
vcString             // Raw VC
credential           // Parsed VerifiableCredential
credential.getIssuer()
credential.getFormat()
credential.getRawJwt()
signatureValid       // Boolean result
```

---

## Phase 5: DID Resolution

When resolving issuer DID to get public key.

### 🔴 Breakpoints

| Class | Method | Line | What to Check |
|-------|--------|------|---------------|
| [DIDResolverServiceImpl](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/DIDResolverServiceImpl.java) | `resolve()` | - | DID string, method |
| [DIDResolverServiceImpl](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/DIDResolverServiceImpl.java) | `resolveDidWeb()` | - | did:web resolution |
| [DIDResolverServiceImpl](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/DIDResolverServiceImpl.java) | `resolveDidKey()` | - | did:key resolution |
| [SignatureVerifier](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/util/SignatureVerifier.java) | `verifySignature()` | - | Actual crypto verify |

### 📊 Variables to Watch
```
did                  // e.g., "did:web:issuer.example.com"
didDocument          // Resolved DID document
verificationMethod   // Public key details
publicKey            // Actual key bytes
algorithm            // EdDSA, ES256, etc.
```

---

## Phase 6: Authentication Completion

When browser polls and user is authenticated.

### 🔴 Breakpoints

| Class | Method | Line | What to Check |
|-------|--------|------|---------------|
| [OpenID4VPAuthenticator](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/OpenID4VPAuthenticator.java#L546) | `handlePollRequest()` | 546 | Status polling |
| [OpenID4VPAuthenticator](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/OpenID4VPAuthenticator.java#L168) | `processAuthenticationResponse()` | 168 | **USER EXTRACTION** |
| [VPStatusPollingServlet](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/servlet/VPStatusPollingServlet.java) | `doGet()` | - | Poll endpoint |
| [LongPollingManager](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/polling/LongPollingManager.java) | `waitForResult()` | - | Wait for submission |

### 📊 Variables to Watch
```
vpRequest.getStatus()           // PENDING, COMPLETED, FAILED
submission                      // VPSubmission object
credentialSubject               // Contains user info
email / username                // Extracted user ID
authenticatedUser               // Final authenticated user
```

---

## Common Debug Scenarios

### ❌ Scenario 1: "VP token format not recognized"
Set breakpoints at:
- `VPSubmissionServlet.parseSubmission()` line 214
- Check `vpToken` raw value and format detection

### ❌ Scenario 2: "Nonce mismatch"
Set breakpoints at:
- `VPSubmissionValidator.validateNonce()`
- Compare `vpNonce` vs `request.getNonce()`

### ❌ Scenario 3: "Signature verification failed"
Set breakpoints at:
- `VCVerificationServiceImpl.verifySignature()` line 290
- `SignatureVerifier.verifySignature()`
- Check `algorithm`, `publicKey`, `signature`

### ❌ Scenario 4: "DID resolution failed"
Set breakpoints at:
- `DIDResolverServiceImpl.resolve()`
- Check `did` string and HTTP response

### ❌ Scenario 5: "User not found"
Set breakpoints at:
- `OpenID4VPAuthenticator.processAuthenticationResponse()` line 168
- Check `credentialSubject` map for email/username

---

## Logging Configuration

Enable debug logging in `log4j2.properties`:

```properties
# OpenID4VP Debug Logging
logger.openid4vp.name = org.wso2.carbon.identity.openid4vc.presentation
logger.openid4vp.level = DEBUG
logger.openid4vp.appenderRef.CARBON_LOGFILE.ref = CARBON_LOGFILE
```

### Key Log Messages to Search

```bash
# Grep for these patterns in wso2carbon.log:
grep "OpenID4VPAuthenticator" wso2carbon.log
grep "VPSubmissionServlet" wso2carbon.log
grep "VCVerificationService" wso2carbon.log
grep "DID resolution" wso2carbon.log
grep "Signature verification" wso2carbon.log
```

---

## Quick Reference: Critical Paths

```
1. INITIATION
   OpenID4VPAuthenticator.initiateAuthenticationRequest()
   └── createVPRequest()
       └── resolvePresentationDefinitionId()

2. WALLET FETCH
   RequestUriServlet.doGet()
   └── VPRequestService.getVPRequest()

3. VP SUBMISSION  ⭐ Most failures here
   VPSubmissionServlet.doPost()
   ├── parseSubmission()
   ├── VPSubmissionService.processSubmission()
   │   └── VCVerificationService.verify()
   │       ├── verifySignature()
   │       │   └── DIDResolverService.resolve()
   │       ├── isExpired()
   │       └── isRevoked()
   └── notifyStatusListeners()

4. COMPLETION
   OpenID4VPAuthenticator.processAuthenticationResponse()
   └── Extract user from credentialSubject
```
