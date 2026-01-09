# Phase 2 Implementation - OpenID4VP Services and API Layer

## Overview

Phase 2 of the Inji Verifier integration into WSO2 Identity Server focuses on implementing the service layer, REST API endpoints, and authentication integration. This phase builds upon the data models, DAOs, and infrastructure established in Phase 1.

## Implementation Timeline

- **Duration**: 4 weeks (Weeks 5-8)
- **Dependencies**: Phase 1 completion (models, DAOs, utilities)

## Components Implemented

### 1. Service Implementations

#### VPRequestServiceImpl

**Location**: `service/impl/VPRequestServiceImpl.java`

**Purpose**: Business logic for VP authorization requests

**Key Features**:
- Creates VP requests with auto-generated nonce and transaction ID
- Supports both by-reference and by-value request modes
- Cache-first retrieval pattern for performance
- Automatic presentation definition resolution
- Request expiration handling

**Key Methods**:
```java
VPRequestResponseDTO createVPRequest(VPRequestCreateDTO createDTO)
VPRequest getVPRequestById(String requestId)
VPRequest getVPRequestByTransactionId(String transactionId)
void updateVPRequestStatus(String requestId, VPRequestStatus newStatus)
String getRequestJwt(String requestId)
void processExpiredRequests()
```

#### VPSubmissionServiceImpl

**Location**: `service/impl/VPSubmissionServiceImpl.java`

**Purpose**: Handle wallet VP submissions

**Key Features**:
- Processes VP tokens from wallet submissions
- Validates submissions against original requests
- Integrates with VPResponseHandler for token parsing
- Tracks verification status through lifecycle
- Handles error responses from wallets

**Key Methods**:
```java
VPSubmission processVPSubmission(VPSubmissionDTO submissionDTO)
VPSubmission getVPSubmissionById(String submissionId)
VPResultDTO getVPResult(String transactionId)
void updateVerificationResult(String submissionId, VCVerificationStatus status, String claims)
```

#### PresentationDefinitionServiceImpl

**Location**: `service/impl/PresentationDefinitionServiceImpl.java`

**Purpose**: CRUD operations for presentation definitions

**Key Features**:
- Create, read, update, delete presentation definitions
- JSON validation for definition format
- Default definition management
- Tenant-aware operations

**Key Methods**:
```java
PresentationDefinition createPresentationDefinition(String name, String definitionJson, ...)
List<PresentationDefinition> getAllPresentationDefinitions(String tenantDomain)
PresentationDefinition getDefaultPresentationDefinition(String tenantDomain)
void setAsDefault(String definitionId)
```

### 2. REST API Servlets

#### VPRequestServlet

**Location**: `servlet/VPRequestServlet.java`

**Endpoints**:
- `POST /api/identity/openid4vp/v1/vp-request` - Create new VP request
- `GET /api/identity/openid4vp/v1/vp-request/{id}` - Get request JWT
- `GET /api/identity/openid4vp/v1/vp-request/{id}/status` - Poll for status

**Request Body (POST)**:
```json
{
  "clientId": "https://verifier.example.com",
  "presentationDefinitionId": "def-123",
  "responseMode": "direct_post",
  "timeoutSeconds": 300
}
```

**Response**:
```json
{
  "requestId": "req-abc123",
  "transactionId": "txn-xyz789",
  "requestUri": "https://server/api/identity/openid4vp/v1/vp-request/req-abc123",
  "expiresIn": 300,
  "qrCodeContent": "openid4vp://...",
  "status": "PENDING"
}
```

#### VPSubmissionServlet

**Location**: `servlet/VPSubmissionServlet.java`

**Endpoint**: `POST /api/identity/openid4vp/v1/vp-response`

**Purpose**: Receives VP submissions from wallets (direct_post endpoint)

**Supported Content Types**:
- `application/x-www-form-urlencoded`
- `application/json`

**Request Parameters**:
- `vp_token` - The verifiable presentation token (JWT or JSON-LD)
- `presentation_submission` - Mapping of credentials to input descriptors
- `state` - The original request ID
- `error` - Error code (if submission failed)
- `error_description` - Error details

#### VPResultServlet

**Location**: `servlet/VPResultServlet.java`

**Endpoint**: `GET /api/identity/openid4vp/v1/vp-result/{transactionId}`

**Purpose**: Retrieve verification results for a transaction

**Response**:
```json
{
  "transactionId": "txn-xyz789",
  "submissionId": "sub-abc123",
  "verificationStatus": "VALID",
  "presentationId": "pres-123",
  "verifiedClaims": {
    "credentialSubject.id": "did:example:123",
    "credentialSubject.name": "John Doe"
  }
}
```

#### VPDefinitionServlet

**Location**: `servlet/VPDefinitionServlet.java`

**Endpoints**:
- `GET /api/identity/openid4vp/v1/presentation-definitions` - List all
- `GET /api/identity/openid4vp/v1/presentation-definitions/{id}` - Get by ID
- `POST /api/identity/openid4vp/v1/presentation-definitions` - Create
- `PUT /api/identity/openid4vp/v1/presentation-definitions/{id}` - Update
- `DELETE /api/identity/openid4vp/v1/presentation-definitions/{id}` - Delete

### 3. Internal Components

#### VPServiceDataHolder

**Location**: `internal/VPServiceDataHolder.java`

**Purpose**: Singleton holder for OSGi service references

**Services Held**:
- RealmService
- VPRequestService
- VPSubmissionService
- PresentationDefinitionService

#### VPServletRegistrationComponent

**Location**: `internal/VPServletRegistrationComponent.java`

**Purpose**: OSGi component for servlet registration

**Registered Paths**:
- `/api/identity/openid4vp/v1/vp-request`
- `/api/identity/openid4vp/v1/vp-response`
- `/api/identity/openid4vp/v1/vp-result`
- `/api/identity/openid4vp/v1/presentation-definitions`

#### VPServiceRegistrationComponent

**Location**: `internal/VPServiceRegistrationComponent.java`

**Purpose**: OSGi component for service initialization and registration

**Responsibilities**:
- Initialize DAO implementations
- Create service implementations with dependencies
- Register services as OSGi services
- Register OpenID4VPAuthenticator

### 4. Authenticator Integration

#### OpenID4VPAuthenticator

**Location**: `authenticator/OpenID4VPAuthenticator.java`

**Purpose**: WSO2 Identity Server local authenticator for wallet-based authentication

**Configuration Properties**:
| Property | Description | Default |
|----------|-------------|---------|
| PresentationDefinitionId | ID of presentation definition to use | (none) |
| ResponseMode | VP response mode | direct_post |
| TimeoutSeconds | Request timeout | 300 |
| ClientId | Client ID for VP requests | (auto-generated) |
| SubjectClaim | Claim path for subject identifier | credentialSubject.id |

**Authentication Flow**:
1. `initiateAuthenticationRequest()` - Creates VP request, generates QR code, redirects to login page
2. `process()` - Handles polling requests and status callbacks
3. `processAuthenticationResponse()` - Validates VP result, extracts claims, creates authenticated user

### 5. Login Page

#### wallet_login.jsp

**Location**: `resources/authenticationendpoint/wallet_login.jsp`

**Purpose**: User-facing login page with QR code for wallet scanning

**Features**:
- QR code generation using QRCode.js
- Deep link for mobile wallet apps
- Status polling with visual feedback
- Countdown timer for request expiration
- Error handling and retry option
- Responsive design

### 6. Handler Components

#### VPResponseHandler

**Location**: `handler/VPResponseHandler.java`

**Purpose**: Parse and validate VP tokens from wallet submissions

**Supported Formats**:
- JWT VP (jwt_vp_json)
- JSON-LD VP (ldp_vp)

**Validation Steps**:
1. Check for error response
2. Validate state parameter
3. Parse VP token (JWT or JSON)
4. Validate JWT claims (nonce, audience, expiration)
5. Extract verifiable credentials
6. Extract claims from credential subjects

#### VPRequestBuilder

**Location**: `handler/VPRequestBuilder.java`

**Purpose**: Build VP authorization requests

**Output Formats**:
- Plain JSON for by-value requests
- Signed JWT for signed request objects
- Authorization details DTO for frontend

### 7. QR Code Utility

#### QRCodeUtil

**Location**: `util/QRCodeUtil.java`

**Purpose**: Generate QR code content for VP requests

**Methods**:
- `generateRequestUriQRContent()` - OpenID4VP deep link with request_uri
- `generateByValueQRContent()` - Full authorization request
- `generateQRCodeHtml()` - HTML container for QR display
- `generateQRCodeScript()` - JavaScript for QR rendering

## API Endpoints Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/identity/openid4vp/v1/vp-request | Create VP request |
| GET | /api/identity/openid4vp/v1/vp-request/{id} | Get request JWT |
| GET | /api/identity/openid4vp/v1/vp-request/{id}/status | Poll status |
| POST | /api/identity/openid4vp/v1/vp-response | Submit VP (wallet) |
| GET | /api/identity/openid4vp/v1/vp-result/{txnId} | Get result |
| GET | /api/identity/openid4vp/v1/presentation-definitions | List definitions |
| POST | /api/identity/openid4vp/v1/presentation-definitions | Create definition |
| PUT | /api/identity/openid4vp/v1/presentation-definitions/{id} | Update definition |
| DELETE | /api/identity/openid4vp/v1/presentation-definitions/{id} | Delete definition |

## File Structure

```
org.wso2.carbon.identity.openid4vc.presentation/
├── src/main/java/org/wso2/carbon/identity/openid4vc/presentation/
│   ├── authenticator/
│   │   └── OpenID4VPAuthenticator.java
│   ├── handler/
│   │   ├── VPRequestBuilder.java
│   │   └── VPResponseHandler.java
│   ├── internal/
│   │   ├── VPServiceDataHolder.java
│   │   ├── VPServiceRegistrationComponent.java
│   │   └── VPServletRegistrationComponent.java
│   ├── service/
│   │   └── impl/
│   │       ├── PresentationDefinitionServiceImpl.java
│   │       ├── VPRequestServiceImpl.java
│   │       └── VPSubmissionServiceImpl.java
│   ├── servlet/
│   │   ├── VPDefinitionServlet.java
│   │   ├── VPRequestServlet.java
│   │   ├── VPResultServlet.java
│   │   └── VPSubmissionServlet.java
│   └── util/
│       └── QRCodeUtil.java
└── src/main/resources/
    └── authenticationendpoint/
        └── wallet_login.jsp
```

## Configuration

### identity.xml additions

```xml
<OpenID4VP>
    <Enable>true</Enable>
    <RequestTimeoutSeconds>300</RequestTimeoutSeconds>
    <VerifierName>WSO2 Identity Server</VerifierName>
    <LogoUri>https://wso2.com/logo.png</LogoUri>
    <LoginPage>/authenticationendpoint/wallet_login.jsp</LoginPage>
    <QRCode>
        <Size>300</Size>
        <ErrorCorrectionLevel>M</ErrorCorrectionLevel>
    </QRCode>
</OpenID4VP>
```

## Testing

### Unit Tests Required

1. **VPRequestServiceImplTest**
   - Test request creation with various inputs
   - Test status transitions
   - Test expiration handling

2. **VPSubmissionServiceImplTest**
   - Test submission processing
   - Test error handling
   - Test claim extraction

3. **VPResponseHandlerTest**
   - Test JWT VP parsing
   - Test JSON-LD VP parsing
   - Test validation logic

4. **OpenID4VPAuthenticatorTest**
   - Test initiation flow
   - Test polling mechanism
   - Test authentication completion

### Integration Tests Required

1. **End-to-End Flow Test**
   - Create request → Scan QR → Submit VP → Verify → Authenticate

2. **API Tests**
   - Test all REST endpoints
   - Test error responses
   - Test concurrent requests

## Next Steps (Phase 3)

1. **Credential Verification Engine**
   - Implement cryptographic signature verification
   - Add DID resolution
   - Implement revocation checking

2. **Enhanced Security**
   - Add rate limiting
   - Implement request signing
   - Add audit logging

3. **Management Console**
   - Build admin UI for definition management
   - Add request monitoring
   - Add analytics dashboard

## Dependencies

### Maven Dependencies Added

```xml
<dependency>
    <groupId>com.google.code.gson</groupId>
    <artifactId>gson</artifactId>
</dependency>
<dependency>
    <groupId>javax.servlet</groupId>
    <artifactId>javax.servlet-api</artifactId>
</dependency>
<dependency>
    <groupId>org.eclipse.equinox</groupId>
    <artifactId>org.eclipse.equinox.http.helper</artifactId>
</dependency>
```

### OSGi Service Dependencies

- `org.osgi.service.http.HttpService`
- `org.wso2.carbon.user.core.service.RealmService`
- `org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator`

## Summary

Phase 2 implementation provides:

1. **Complete service layer** with business logic for VP requests, submissions, and definitions
2. **REST API endpoints** for all OpenID4VP operations
3. **Authentication integration** via OpenID4VPAuthenticator
4. **User-facing login page** with QR code scanning
5. **VP token handling** for JWT and JSON-LD formats
6. **OSGi integration** for service and servlet registration

Total files created in Phase 2: **14 files**

- Service implementations: 3
- Servlet implementations: 4
- Internal components: 3
- Handler classes: 2
- Utility classes: 1
- JSP pages: 1
