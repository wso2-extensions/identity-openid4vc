# OID4VP Presentation Module

**Artifact ID:** `org.wso2.carbon.identity.openid4vc.oid4vp.presentation`  
**Package:** `org.wso2.carbon.identity.openid4vc.oid4vp.presentation`  
**Type:** Application/Integration Layer  
**Dependencies:** oid4vp.common, oid4vp.did, oid4vp.verification

## Overview

The Presentation module implements the OpenID for Verifiable Presentations (OID4VP) verifier flow in WSO2 Identity Server. It provides the authenticator, HTTP endpoints, business logic, and data access for the complete VP-based authentication workflow.

## Module Structure

```
org.wso2.carbon.identity.openid4vc.oid4vp.presentation/
├── authenticator/     - Federated authenticator implementation
├── servlet/          - HTTP endpoints (VP requests, submissions, status)
├── service/          - Business logic services
│   └── impl/        - Service implementations
├── dao/             - Data access layer
│   └── impl/        - DAO implementations
├── cache/           - In-memory caching
├── polling/         - Long-polling support
├── status/          - Status notification service
├── handler/         - Request/response handlers
├── listener/        - IDP lifecycle listeners
├── util/            - Presentation-specific utilities
└── internal/        - OSGi service components
```

## Core Components

### 1. Authenticator (`authenticator/`)

#### OpenID4VPAuthenticator
Federated authenticator that integrates VP authentication into WSO2 IS.

**Extends:** `AbstractApplicationAuthenticator`  
**Implements:** `FederatedApplicationAuthenticator`

**Configuration:**
```java
@Override
public String getFriendlyName() {
    return "OpenID4VPAuthenticator";
}

@Override
public String getName() {
    return "OpenID4VPAuthenticator";
}
```

**Authentication Flow:**
```java
@Override
public AuthenticatorFlowStatus process(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationContext context)
        throws AuthenticationFailedException {
    
    // 1. Check if this is initial request or callback
    if (context.isLogoutRequest()) {
        return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
    }
    
    String requestId = request.getParameter("request_id");
    
    if (requestId == null) {
        // Initial authentication request
        return initiateAuthenticationRequest(request, response, context);
    } else {
        // Process VP submission callback
        return processAuthenticationResponse(request, response, context);
    }
}
```

**Initiate Authentication:**
```java
private AuthenticatorFlowStatus initiateAuthenticationRequest(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthenticationContext context) throws AuthenticationFailedException {
    
    // 1. Create VP request
    VPRequestService vpRequestService = getVPRequestService();
    
    // 2. Get presentation definition from IDP config
    String presentationDefinitionId = getAuthenticatorConfig(context)
        .getParameterMap()
        .get("presentationDefinitionId");
    
    VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
    createDTO.setPresentationDefinitionId(presentationDefinitionId);
    createDTO.setClientId(context.getContextIdentifier());
    createDTO.setRedirectUri(context.getCallerPath());
    
    // 3. Create request and generate QR code
    VPRequestResponseDTO vpResponse = vpRequestService.createRequest(
        createDTO, 
        context.getTenantDomain()
    );
    
    // 4. Store request ID in context
    context.setProperty("VP_REQUEST_ID", vpResponse.getRequestId());
    
    // 5. Redirect to wallet login page with QR code
    String walletLoginPage = ConfigurationFacade.getInstance()
        .getAuthenticationEndpointURL()
        .replace("authenticationendpoint", "authenticationendpoint")
        + "/wallet_login.jsp";
    
    response.sendRedirect(walletLoginPage + 
        "?sessionDataKey=" + context.getContextIdentifier() +
        "&requestId=" + vpResponse.getRequestId() +
        "&qrCode=" + URLEncoder.encode(vpResponse.getQrCode(), "UTF-8"));
    
    return AuthenticatorFlowStatus.INCOMPLETE;
}
```

**Process VP Submission:**
```java
private AuthenticatorFlowStatus processAuthenticationResponse(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthenticationContext context) throws AuthenticationFailedException {
    
    String requestId = request.getParameter("request_id");
    
    // 1. Get VP submission from cache
    WalletDataCache cache = WalletDataCache.getInstance();
    VPSubmission submission = cache.getValueFromCache(requestId, context.getTenantDomain());
    
    if (submission == null) {
        throw new AuthenticationFailedException("VP submission not found");
    }
    
    // 2. Verify submission is for this request
    if (!requestId.equals(submission.getRequestId())) {
        throw new AuthenticationFailedException("Request ID mismatch");
    }
    
    // 3. Extract claims from verified VP
    Map<String, Object> claims = submission.getClaims();
    
    // 4. Create authenticated user
    AuthenticatedUser authenticatedUser = new AuthenticatedUser();
    authenticatedUser.setUserName(extractUsername(claims));
    authenticatedUser.setTenantDomain(context.getTenantDomain());
    authenticatedUser.setAuthenticatedSubjectIdentifier(
        (String) claims.get("sub")
    );
    
    // 5. Set user attributes
    Map<ClaimMapping, String> userAttributes = new HashMap<>();
    for (Map.Entry<String, Object> entry : claims.entrySet()) {
        ClaimMapping claimMapping = ClaimMapping.build(
            entry.getKey(), entry.getKey(), null, false
        );
        userAttributes.put(claimMapping, String.valueOf(entry.getValue()));
    }
    authenticatedUser.setUserAttributes(userAttributes);
    
    // 6. Complete authentication
    context.setSubject(authenticatedUser);
    
    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
}
```

**Configuration Properties:**
- `presentationDefinitionId` - Which PD to use for authentication
- `claimMappings` - Map VP claims to WSO2 IS user attributes
- `enableQRPolling` - Enable long-polling for status updates
- `timeout` - Request timeout in seconds

---

### 2. Servlets (`servlet/`)

#### VPRequestServlet
Handles VP authorization request creation and status polling.

**Endpoints:**
- `POST /openid4vp/v1/request` - Create VP request
- `GET /openid4vp/v1/request/{requestId}/status` - Poll request status

**Create Request:**
```java
@Override
protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    
    try {
        // 1. Parse request body
        BufferedReader reader = request.getReader();
        VPRequestCreateDTO createDTO = GSON.fromJson(reader, VPRequestCreateDTO.class);
        
        // 2. Validate input
        validateCreateRequest(createDTO);
        
        // 3. Create VP request
        VPRequestService service = getVPRequestService();
        VPRequestResponseDTO vpResponse = service.createRequest(
            createDTO,
            getTenantDomain(request)
        );
        
        // 4. Return response
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_OK);
        GSON.toJson(vpResponse, response.getWriter());
        
    } catch (VPException e) {
        sendErrorResponse(response, e);
    }
}
```

**Status Polling (Long-Polling):**
```java
@Override
protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    
    String requestId = extractRequestId(request.getPathInfo());
    String tenantDomain = getTenantDomain(request);
    
    try {
        // 1. Get current status
        VPRequestService service = getVPRequestService();
        VPRequestStatusDTO status = service.getStatus(requestId, tenantDomain);
        
        // 2. If status is ACTIVE and long-polling enabled, wait for update
        if (status.getStatus() == VPRequestStatus.ACTIVE && 
            isLongPolling(request)) {
            
            LongPollingManager pollingManager = LongPollingManager.getInstance();
            PollingResult result = pollingManager.waitForCompletion(
                requestId, 
                getTimeout(request)
            );
            
            if (result.getStatus() == PollingResult.ResultStatus.COMPLETED) {
                status = service.getStatus(requestId, tenantDomain);
            }
        }
        
        // 3. Return status
        response.setContentType("application/json");
        GSON.toJson(status, response.getWriter());
        
    } catch (VPException e) {
        sendErrorResponse(response, e);
    }
}
```

---

#### VPSubmissionServlet
Receives VP submissions from wallets (direct_post response mode).

**Endpoint:**
- `POST /openid4vp/v1/response` - Receive VP submission

**Process Submission:**
```java
@Override
protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    
    try {
        // 1. Parse form parameters
        String vpToken = request.getParameter("vp_token");
        String presentationSubmission = request.getParameter("presentation_submission");
        String state = request.getParameter("state");  // request ID
        String error = request.getParameter("error");
        
        // 2. Check for wallet errors
        if (error != null) {
            handleWalletError(state, error, request.getParameter("error_description"));
            return;
        }
        
        // 3. Get VP request
        VPRequestService vpService = getVPRequestService();
        VPRequest vpRequest = vpService.getRequest(state, getTenantDomain(request));
        
        // 4. Validate presentation submission
        PresentationSubmissionDTO submissionDTO = GSON.fromJson(
            presentationSubmission, 
            PresentationSubmissionDTO.class
        );
        
        VPSubmissionValidator.validate(
            submissionDTO, 
            vpRequest.getPresentationDefinition()
        );
        
        // 5. Verify VP token
        VCVerificationService verificationService = getVerificationService();
        VCVerificationResultDTO verificationResult = verificationService.verify(
            vpToken,
            detectFormat(vpToken)
        );
        
        if (verificationResult.getStatus() != VCVerificationStatus.VALID) {
            throw new CredentialVerificationException(
                "VP verification failed: " + verificationResult.getStatus()
            );
        }
        
        // 6. Create submission object
        VPSubmission submission = new VPSubmission();
        submission.setRequestId(state);
        submission.setVpToken(vpToken);
        submission.setPresentationSubmission(submissionDTO);
        submission.setSubmittedAt(System.currentTimeMillis());
        submission.setClaims(verificationResult.getClaims());
        
        // 7. Store in cache
        WalletDataCache cache = WalletDataCache.getInstance();
        cache.addToCache(state, submission, getTenantDomain(request));
        
        // 8. Update request status
        vpService.updateStatus(
            state, 
            VPRequestStatus.COMPLETED, 
            getTenantDomain(request)
        );
        
        // 9. Notify waiting long-poll requests
        LongPollingManager.getInstance().notifyCompletion(state);
        
        // 10. Return success response
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        JsonObject result = new JsonObject();
        result.addProperty("status", "success");
        GSON.toJson(result, response.getWriter());
        
    } catch (VPException | CredentialVerificationException e) {
        sendErrorResponse(response, e);
    }
}
```

---

#### WalletStatusServlet
Provides status updates for wallet-side polling.

**Endpoint:**
- `GET /openid4vp/v1/wallet/status/{requestId}` - Get status from wallet perspective

---

#### VPDefinitionServlet
CRUD operations for Presentation Definitions.

**Endpoints:**
- `POST /openid4vp/v1/definitions` - Create PD
- `GET /openid4vp/v1/definitions/{id}` - Get PD
- `PUT /openid4vp/v1/definitions/{id}` - Update PD
- `DELETE /openid4vp/v1/definitions/{id}` - Delete PD
- `GET /openid4vp/v1/definitions` - List PDs

---

#### WellKnownDIDServlet
Serves the verifier's DID document.

**Endpoint:**
- `GET /.well-known/did.json` - DID document for did:web

**Implementation:**
```java
@Override
protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    
    try {
        // 1. Get DID document service
        DIDDocumentService didService = getDIDDocumentService();
        
        // 2. Get domain from request
        String domain = request.getServerName();
        if (request.getServerPort() != 443 && request.getServerPort() != 80) {
            domain += ":" + request.getServerPort();
        }
        
        // 3. Generate DID document
        String didDocument = didService.getDIDDocument(
            domain, 
            getTenantId(request)
        );
        
        // 4. Return as JSON
        response.setContentType("application/did+json");
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write(didDocument);
        
    } catch (DIDDocumentException e) {
        sendErrorResponse(response, e);
    }
}
```

---

### 3. Services (`service/`)

#### VPRequestService
Business logic for VP request lifecycle management.

**Interface:**
```java
public interface VPRequestService {
    VPRequestResponseDTO createRequest(VPRequestCreateDTO createDTO, String tenantDomain);
    VPRequest getRequest(String requestId, String tenantDomain);
    VPRequestStatusDTO getStatus(String requestId, String tenantDomain);
    void updateStatus(String requestId, VPRequestStatus status, String tenantDomain);
    void expireRequest(String requestId, String tenantDomain);
}
```

**Implementation Highlights:**
- Request ID generation (UUID v4)
- Nonce generation (cryptographically secure)
- QR code generation
- Authorization request URL construction
- Expiration handling

---

#### PresentationDefinitionService
Manages Presentation Definitions.

**Interface:**
```java
public interface PresentationDefinitionService {
    String createPresentationDefinition(PresentationDefinition pd, String tenantDomain);
    PresentationDefinition getPresentationDefinition(String id, String tenantDomain);
    List<PresentationDefinition> listPresentationDefinitions(String tenantDomain);
    void updatePresentationDefinition(String id, PresentationDefinition pd, String tenantDomain);
    void deletePresentationDefinition(String id, String tenantDomain);
}
```

---

### 4. Data Access Layer (`dao/`)

#### VPRequestDAO
Database operations for VP requests.

**Schema:**
```sql
CREATE TABLE OID4VP_VP_REQUEST (
    REQUEST_ID VARCHAR(255) PRIMARY KEY,
    CLIENT_ID VARCHAR(255) NOT NULL,
    TENANT_ID INTEGER NOT NULL,
    PRESENTATION_DEFINITION_ID VARCHAR(255) NOT NULL,
    NONCE VARCHAR(255) NOT NULL,
    STATE VARCHAR(255),
    RESPONSE_URI VARCHAR(1024) NOT NULL,
    STATUS VARCHAR(50) NOT NULL,
    CREATED_AT TIMESTAMP NOT NULL,
    EXPIRES_AT TIMESTAMP NOT NULL,
    UPDATED_AT TIMESTAMP
);
```

**Methods:**
```java
public interface VPRequestDAO {
    void createRequest(VPRequest request, int tenantId);
    VPRequest getRequest(String requestId, int tenantId);
    void updateStatus(String requestId, VPRequestStatus status, int tenantId);
    void deleteRequest(String requestId, int tenantId);
    List<VPRequest> getExpiredRequests(int tenantId);
}
```

---

#### PresentationDefinitionDAO
Database operations for Presentation Definitions.

**Schema:**
```sql
CREATE TABLE OID4VP_PRESENTATION_DEFINITION (
    ID VARCHAR(255) PRIMARY KEY,
    TENANT_ID INTEGER NOT NULL,
    NAME VARCHAR(255),
    PURPOSE VARCHAR(1024),
    DEFINITION TEXT NOT NULL,  -- JSON
    CREATED_AT TIMESTAMP NOT NULL,
    UPDATED_AT TIMESTAMP
);
```

---

### 5. Caching (`cache/`)

#### VPRequestCache
In-memory cache for active VP requests (faster than DB).

**Cache Key:** `{tenantDomain}:{requestId}`  
**Expiration:** Configurable (default: 5 minutes)

#### WalletDataCache
Stores VP submissions temporarily.

**Cache Key:** `{tenantDomain}:{requestId}`  
**Expiration:** 2 minutes (short-lived)

#### VPStatusListenerCache
Stores long-polling listeners.

**Cache Key:** `{requestId}`  
**Value:** `CompletableFuture<PollingResult>`

---

### 6. Long-Polling Support (`polling/`)

#### LongPollingManager
Manages long-polling connections for real-time status updates.

**Methods:**
```java
public class LongPollingManager {
    public PollingResult waitForCompletion(String requestId, long timeoutMs);
    public void notifyCompletion(String requestId);
    public void notifyExpiration(String requestId);
}
```

**Implementation:**
```java
public PollingResult waitForCompletion(String requestId, long timeoutMs) {
    CompletableFuture<PollingResult> future = new CompletableFuture<>();
    
    // Store future in cache
    VPStatusListenerCache.getInstance().addToCache(requestId, future);
    
    try {
        // Wait for completion or timeout
        return future.get(timeoutMs, TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
        return new PollingResult(PollingResult.ResultStatus.TIMEOUT);
    } finally {
        VPStatusListenerCache.getInstance().clearCacheEntry(requestId);
    }
}

public void notifyCompletion(String requestId) {
    CompletableFuture<PollingResult> future = 
        VPStatusListenerCache.getInstance().getValueFromCache(requestId);
    
    if (future != null) {
        future.complete(new PollingResult(PollingResult.ResultStatus.COMPLETED));
    }
}
```

---

### 7. Listeners (`listener/`)

#### OpenID4VPIdentityProviderMgtListener
Listens to IDP lifecycle events to manage embedded presentation definitions.

**Events:**
- `onIdPCreate` - Store PD from IDP config
- `onIdPUpdate` - Update PD
- `onIdPDelete` - Clean up PD

---

## Complete Authentication Flow

```
User → SP → WSO2 IS
              ↓
1. OpenID4VPAuthenticator.initiateAuthenticationRequest()
   ├→ Create VPRequest via VPRequestService
   ├→ Load PresentationDefinition from IDP config
   ├→ Generate QR code (authorization request URL)
   └→ Redirect to wallet_login.jsp with QR
              ↓
2. User scans QR with wallet
              ↓
3. Wallet:
   ├→ Parses authorization request
   ├→ Fetches presentation definition
   ├→ Selects matching VCs
   ├→ Creates VP
   └→ POSTs to VPSubmissionServlet (direct_post)
              ↓
4. VPSubmissionServlet.doPost()
   ├→ Validate presentation_submission
   ├→ Verify VP signature (VCVerificationService)
   ├→ Check VC status (not revoked)
   ├→ Extract claims
   ├→ Store VPSubmission in WalletDataCache
   ├→ Update VPRequest status to COMPLETED
   └→ Notify LongPollingManager
              ↓
5. wallet_login.jsp (polling):
   ├→ Long-poll VPRequestServlet.doGet()
   └→ Receives COMPLETED status
              ↓
6. Page redirects back to authenticator
              ↓
7. OpenID4VPAuthenticator.processAuthenticationResponse()
   ├→ Retrieve VPSubmission from cache
   ├→ Extract claims
   ├→ Create AuthenticatedUser
   └→ Set user attributes
              ↓
8. Authentication complete → Redirect to SP
```

---

## Configuration

### Authenticator Configuration (IDP)
```json
{
  "authenticatorId": "OpenID4VPAuthenticator",
  "properties": {
    "presentationDefinitionId": "pd-drivers-license",
    "claimMappings": {
      "given_name": "http://wso2.org/claims/givenname",
      "family_name": "http://wso2.org/claims/lastname",
      "email": "http://wso2.org/claims/emailaddress"
    },
    "timeout": "300",
    "enableQRPolling": "true"
  }
}
```

### Application Properties
```properties
# VP request timeout (seconds)
openid4vp.request.timeout=300

# QR polling interval (ms)
openid4vp.qr.poll.interval=2000

# Long-polling timeout (ms)
openid4vp.longpoll.timeout=60000

# Enable debug logging
openid4vp.debug=false
```

---

## Testing

### Unit Tests
- Authenticator flow logic
- Service methods
- DAO operations
- Validation logic

### Integration Tests
- End-to-end VP flow
- Long-polling mechanism
- Database persistence
- Cache operations

### E2E Tests
- Real wallet integration
- QR code scanning
- Multi-tenant scenarios

Test coverage target: >80%

---

## Monitoring & Observability

### Metrics
- VP requests created
- Successful authentications
- Failed verifications
- Average request duration
- Cache hit/miss ratios

### Logging
```java
if (log.isDebugEnabled()) {
    log.debug("VP request created: " + requestId);
}

if (log.isTraceEnabled()) {
    log.trace("VP claims: " + GSON.toJson(claims));
}
```

---

## Security Considerations

1. **Request Expiration** - Enforce timeout on all VP requests
2. **Nonce Validation** - Prevent replay attacks
3. **CORS** - Properly configure CORS for wallet interactions
4. **Rate Limiting** - Limit request creation per client
5. **Input Validation** - Sanitize all user inputs
6. **Claim Sanitization** - Remove sensitive data from logs
7. **Cache Security** - Clear cache entries after use
8. **HTTPS Only** - Enforce HTTPS for all endpoints
