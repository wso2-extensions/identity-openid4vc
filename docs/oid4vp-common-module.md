# OID4VP Common Module

**Artifact ID:** `org.wso2.carbon.identity.openid4vc.oid4vp.common`  
**Package:** `org.wso2.carbon.identity.openid4vc.oid4vp.common`  
**Type:** Foundation/Kernel Module  
**Dependencies:** None (base module)

## Overview

The Common module serves as the foundation layer for the entire OID4VP implementation. It contains shared components that are used across all other modules, ensuring consistency and reusability.

## Module Structure

```
org.wso2.carbon.identity.openid4vc.oid4vp.common/
├── constant/          - Application constants and configuration keys
├── dto/              - Data Transfer Objects for API communication
├── exception/        - Custom exception hierarchy
├── model/            - Domain entities and business objects
└── util/             - Utility classes and helper functions
```

## Components

### 1. Constants (`constant/`)

#### OpenID4VPConstants
Central repository for all application constants.

**Nested Classes:**
- `ConfigKeys` - Configuration property keys
- `ErrorCodes` - Standardized error codes and messages
- `CacheKeys` - Cache key templates
- `Endpoints` - API endpoint paths
- `Defaults` - Default values and timeouts
- `DID` - DID-related constants

**Key Constants:**
```java
// Timeouts
public static final int DEFAULT_TIMEOUT = 300; // 5 minutes
public static final long QR_POLL_INTERVAL = 2000L; // 2 seconds

// Response modes
public static final String DIRECT_POST = "direct_post";

// Cache names
public static final String VP_REQUEST_CACHE = "VPRequestCache";
public static final String WALLET_DATA_CACHE = "WalletDataCache";
```

**Usage:**
```java
import org.wso2.carbon.identity.openid4vc.oid4vp.common.constant.OpenID4VPConstants;

String endpoint = OpenID4VPConstants.Endpoints.VP_RESPONSE;
String errorCode = OpenID4VPConstants.ErrorCodes.VP_EXPIRED;
```

---

### 2. Models (`model/`)

Domain entities representing core business concepts.

#### PresentationDefinition
Defines what credentials the verifier requires.

**Key Fields:**
- `id` - Unique identifier
- `inputDescriptors` - List of credential requirements
- `name`, `purpose` - Human-readable descriptions
- `format` - Supported VC formats (jwt_vc, ldp_vc, etc.)

**Related Models:**
- `InputDescriptor` - Individual credential requirement
- `Constraints` - Field-level constraints
- `Field` - Specific claim requirements

#### VPRequest
Represents an authorization request for a Verifiable Presentation.

**Key Fields:**
- `requestId` - Unique request identifier
- `clientId` - OAuth2 client identifier
- `presentationDefinition` - What credentials are needed
- `nonce`, `state` - Security parameters
- `responseUri` - Where wallet sends VP
- `expiresAt` - Request expiration timestamp

**Lifecycle States:**
```java
ACTIVE → VP_SUBMITTED → COMPLETED
    ↓
  EXPIRED
```

#### VPRequestStatus
Enum representing the lifecycle of a VP request.

**States:**
- `ACTIVE` - Request created, waiting for wallet
- `VP_SUBMITTED` - Wallet submitted VP, processing
- `COMPLETED` - VP verified, authentication successful
- `EXPIRED` - Request timeout exceeded
- `ERROR` - Processing error occurred

#### DIDDocument
Represents a DID Document per W3C DID Core spec.

**Key Fields:**
- `id` - DID identifier (e.g., "did:web:example.com")
- `verificationMethod` - Public keys for signature verification
- `authentication` - Keys for authentication
- `assertionMethod` - Keys for assertions
- `keyAgreement` - Keys for encryption

**DID Methods Supported:**
- `did:web` - Web-based DIDs
- `did:key` - Self-contained cryptographic DIDs
- `did:jwk` - JWK-based DIDs

#### VPSubmission
Represents a wallet's submission of a Verifiable Presentation.

**Key Fields:**
- `requestId` - Correlates to VPRequest
- `vpToken` - The actual VP (JWT or JSON-LD)
- `presentationSubmission` - Mapping to presentation definition
- `submittedAt` - Timestamp
- `claims` - Extracted user claims

#### VCVerificationStatus
Enum for credential verification outcomes.

**Values:**
- `VALID` - VC signature and status are valid
- `INVALID_SIGNATURE` - Cryptographic verification failed
- `REVOKED` - VC has been revoked by issuer
- `EXPIRED` - VC past expiration date
- `ISSUER_NOT_TRUSTED` - Issuer not in trusted list

---

### 3. DTOs (`dto/`)

Lightweight objects for data transfer between layers.

#### VPRequestCreateDTO
Input for creating a new VP request.

**Fields:**
- `presentationDefinitionId` - Which PD to use
- `clientId` - OAuth2 client
- `redirectUri` - Post-authentication redirect
- `customClaims` - Additional claims to request

#### VPRequestResponseDTO
Response returned when VP request is created.

**Fields:**
- `requestId` - Generated request ID
- `authorizationRequest` - Full OpenID4VP authorization request
- `qrCode` - Base64-encoded QR code image
- `expiresIn` - Seconds until expiration

#### VPRequestStatusDTO
Current status of a VP request.

**Fields:**
- `requestId`
- `status` - VPRequestStatus enum
- `message` - Human-readable status
- `expiresAt` - Expiration timestamp

#### PresentationSubmissionDTO
Describes how submitted VPs satisfy the presentation definition.

**Fields:**
- `id` - Submission identifier
- `definitionId` - References presentation definition
- `descriptorMap` - Maps submitted VCs to input descriptors

**Structure:**
```json
{
  "id": "submission-123",
  "definition_id": "pd-456",
  "descriptor_map": [
    {
      "id": "input_1",
      "format": "jwt_vc",
      "path": "$.verifiableCredential[0]"
    }
  ]
}
```

#### AuthorizationDetailsDTO
OpenID4VP authorization details for fine-grained requests.

**Fields:**
- `type` - "openid4vp"
- `presentationDefinition` - Embedded or referenced PD
- `format` - VC formats accepted

#### VCVerificationResultDTO
Result of verifying a Verifiable Credential.

**Fields:**
- `status` - VCVerificationStatus enum
- `vcId` - Credential identifier
- `issuer` - Issuer DID
- `subject` - Subject DID/identifier
- `issuedAt`, `expiresAt` - Timestamps
- `claims` - Extracted claims
- `errorMessage` - If verification failed

---

### 4. Exceptions (`exception/`)

Custom exception hierarchy for standardized error handling.

#### VPException (Base)
Parent class for all OID4VP exceptions.

**Features:**
- Error code
- Error description
- HTTP status code mapping

**Subclasses:**

##### VPRequestNotFoundException
- **Thrown when:** VP request ID not found
- **Error Code:** `VP_REQUEST_NOT_FOUND`
- **HTTP Status:** 404

##### VPRequestExpiredException
- **Thrown when:** VP request past expiration time
- **Error Code:** `VP_REQUEST_EXPIRED`
- **HTTP Status:** 400

##### VPSubmissionValidationException
- **Thrown when:** Submission doesn't match presentation definition
- **Error Code:** `INVALID_VP_SUBMISSION`
- **HTTP Status:** 400

##### VPSubmissionWalletErrorException
- **Thrown when:** Wallet reports an error (user denied, etc.)
- **Error Code:** `WALLET_ERROR`
- **HTTP Status:** 400

##### CredentialVerificationException
- **Thrown when:** VC signature/status verification fails
- **Error Code:** `CREDENTIAL_VERIFICATION_FAILED`
- **HTTP Status:** 401

##### DIDResolutionException
- **Thrown when:** Cannot resolve a DID
- **Error Code:** `DID_RESOLUTION_FAILED`
- **HTTP Status:** 500

##### DIDDocumentException
- **Thrown when:** DID document generation/parsing fails
- **Error Code:** `DID_DOCUMENT_ERROR`
- **HTTP Status:** 500

##### PresentationDefinitionNotFoundException
- **Thrown when:** Referenced PD not found
- **Error Code:** `PD_NOT_FOUND`
- **HTTP Status:** 404

**Usage Example:**
```java
throw new VPRequestExpiredException(
    "VP request expired: " + requestId,
    OpenID4VPConstants.ErrorCodes.VP_REQUEST_EXPIRED
);
```

---

### 5. Utilities (`util/`)

Helper classes providing common functionality.

#### OpenID4VPUtil
General-purpose utility methods.

**Key Methods:**
- `getBaseUrl()` - Get server base URL
- `buildAuthorizationRequest(VPRequest)` - Construct OpenID4VP auth request
- `generateNonce()` - Cryptographically secure nonce
- `validatePresentationSubmission(submission, definition)` - Validate submission matches PD
- `extractClaimsFromVP(vpToken)` - Parse claims from VP

**Usage:**
```java
String authRequest = OpenID4VPUtil.buildAuthorizationRequest(vpRequest);
Map<String, Object> claims = OpenID4VPUtil.extractClaimsFromVP(vpToken);
```

#### QRCodeUtil
QR code generation for OpenID4VP authorization requests.

**Key Methods:**
- `generateQRCode(data, width, height)` - Create QR code image
- `generateQRCodeBase64(data)` - QR code as Base64 string
- `generateAuthorizationQR(VPRequest)` - QR for VP request

**Configuration:**
- Default size: 300x300 pixels
- Error correction: Level M (15%)
- Format: PNG

**Usage:**
```java
String qrBase64 = QRCodeUtil.generateAuthorizationQR(vpRequest);
// Returns: "data:image/png;base64,iVBORw0KG..."
```

#### CORSUtil
CORS (Cross-Origin Resource Sharing) header management.

**Key Methods:**
- `setCORSHeaders(response, request)` - Add CORS headers
- `isPreflightRequest(request)` - Check if OPTIONS request
- `handlePreflightRequest(request, response)` - Handle CORS preflight

**Configured Origins:**
- Allows configured origins (default: `*` for development)
- Methods: GET, POST, OPTIONS
- Headers: Content-Type, Authorization

**Usage:**
```java
CORSUtil.setCORSHeaders(response, request);
```

#### VPSubmissionValidator
Validates VP submissions against presentation definitions.

**Key Methods:**
- `validate(submission, definition)` - Full validation
- `validateDescriptorMapping(descriptorMap, inputDescriptors)` - Check mappings
- `validateConstraints(claims, constraints)` - Verify field constraints

**Validation Rules:**
- All required input descriptors must be satisfied
- Descriptor paths must be valid JSONPath
- Field constraints must be met
- Format must match requested format

**Usage:**
```java
VPSubmissionValidator.validate(submission, presentationDefinition);
// Throws VPSubmissionValidationException if invalid
```

---

## Dependencies

### External Libraries
- **Gson** - JSON serialization/deserialization
- **Apache Commons Lang** - String utilities
- **SLF4J** - Logging facade
- **WSO2 Identity Core** - IdentityUtil for server context

### OSGi Bundles
- Servlet API (provided by container)

---

## Export Packages

All packages are exported for use by dependent modules:

```xml
<Export-Package>
    org.wso2.carbon.identity.openid4vc.oid4vp.common.*;
    version="1.0.0.SNAPSHOT"
</Export-Package>
```

**Exported Packages:**
- `org.wso2.carbon.identity.openid4vc.oid4vp.common.constant`
- `org.wso2.carbon.identity.openid4vc.oid4vp.common.dto`
- `org.wso2.carbon.identity.openid4vc.oid4vp.common.exception`
- `org.wso2.carbon.identity.openid4vc.oid4vp.common.model`
- `org.wso2.carbon.identity.openid4vc.oid4vp.common.util`

---

## Usage Examples

### Creating a VP Request
```java
import org.wso2.carbon.identity.openid4vc.oid4vp.common.model.*;
import org.wso2.carbon.identity.openid4vc.oid4vp.common.dto.*;

VPRequest vpRequest = new VPRequest();
vpRequest.setRequestId(UUID.randomUUID().toString());
vpRequest.setClientId("oauth2-client-123");
vpRequest.setPresentationDefinition(presentationDefinition);
vpRequest.setStatus(VPRequestStatus.ACTIVE);
vpRequest.setExpiresAt(System.currentTimeMillis() + 300000);
```

### Validating a Submission
```java
import org.wso2.carbon.identity.openid4vc.oid4vp.common.util.*;
import org.wso2.carbon.identity.openid4vc.oid4vp.common.exception.*;

try {
    VPSubmissionValidator.validate(submission, presentationDefinition);
    // Submission is valid
} catch (VPSubmissionValidationException e) {
    // Handle validation error
    log.error("Invalid submission: " + e.getMessage());
}
```

### Generating QR Code
```java
import org.wso2.carbon.identity.openid4vc.oid4vp.common.util.QRCodeUtil;

String qrCodeBase64 = QRCodeUtil.generateAuthorizationQR(vpRequest);
// Display in HTML: <img src="${qrCodeBase64}" />
```

---

## Design Patterns

1. **Data Transfer Object (DTO)** - Separate DTOs for API communication
2. **Value Object** - Immutable models where appropriate
3. **Exception Hierarchy** - Consistent error handling
4. **Utility Pattern** - Stateless helper methods
5. **Constant Pool** - Centralized configuration

---

## Best Practices

1. **Immutability** - Models should be immutable where possible
2. **Validation** - Use validators before persisting data
3. **Error Handling** - Always use custom exceptions with error codes
4. **Logging** - Use SLF4J for consistent logging
5. **Constants** - Never hardcode values; use OpenID4VPConstants

---

## Testing

The common module should be thoroughly unit tested:
- Model serialization/deserialization
- Validator logic
- Utility functions
- Exception handling

Test coverage target: >80%
