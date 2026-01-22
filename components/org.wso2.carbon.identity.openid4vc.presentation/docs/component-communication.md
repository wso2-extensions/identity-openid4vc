# OpenID4VP Component Communication Architecture

This document explains how each internal component in the `org.wso2.carbon.identity.openid4vc.presentation` module communicates with other components.

---

## High-Level Architecture

```mermaid
graph TB
    subgraph "External Actors"
        BROWSER[Browser/Client]
        WALLET[Digital Wallet]
    end

    subgraph "Entry Points"
        AUTH[OpenID4VPAuthenticator]
        SERVLETS[HTTP Servlets]
    end

    subgraph "Business Logic"
        SERVICES[Service Layer]
        HANDLERS[Handlers]
    end

    subgraph "Data & State"
        DAO[DAO Layer]
        CACHE[Cache Layer]
        POLLING[Polling Manager]
    end

    subgraph "Utilities"
        UTILS[Utility Classes]
    end

    subgraph "Infrastructure"
        INTERNAL[OSGi Components]
        DB[(Database)]
    end

    BROWSER --> AUTH
    BROWSER --> SERVLETS
    WALLET --> SERVLETS
    AUTH --> SERVICES
    SERVLETS --> SERVICES
    SERVICES --> HANDLERS
    SERVICES --> DAO
    SERVICES --> CACHE
    SERVLETS --> CACHE
    SERVLETS --> POLLING
    DAO --> DB
    SERVICES --> UTILS
    INTERNAL --> |registers| AUTH
    INTERNAL --> |registers| SERVLETS
```

---

## Package Communication Matrix

| Source Package | Communicates With | Communication Type |
|----------------|-------------------|-------------------|
| `authenticator` | `service`, `cache`, `util`, `model`, `dto` | Method calls |
| `servlet` | `service`, `cache`, `polling`, `util`, `dto`, `exception` | Method calls |
| `service` | `dao`, `util`, `model`, `dto`, `exception`, `handler` | Method calls |
| `dao` | `model`, `exception` | Method calls |
| `cache` | `model`, `dto` | Data storage |
| `polling` | `cache`, `service` | Async coordination |
| `handler` | `model`, `dto`, `util` | Request/Response building |
| `internal` | All packages | OSGi registration |
| `util` | `model`, `exception`, `constant` | Stateless utilities |

---

## Component Details

### 1. Authenticator Package

**Files:** `OpenID4VPAuthenticator.java`

**Role:** WSO2 IS authentication framework integration point.

**Inbound Communication:**
- Called by WSO2 authentication framework during login flow
- Receives `HttpServletRequest`, `AuthenticationContext`

**Outbound Communication:**
```mermaid
graph LR
    AUTH[OpenID4VPAuthenticator] --> VPS[VPRequestService]
    AUTH --> VSS[VPSubmissionService]
    AUTH --> VRS[VPResultService]
    AUTH --> PDS[PresentationDefinitionService]
    AUTH --> CACHE[WalletDataCache]
    AUTH --> QR[QRCodeUtil]
```

| Target | Method Called | Purpose |
|--------|--------------|---------|
| `VPRequestService` | `createVPRequest()` | Initiate VP authorization request |
| `VPSubmissionService` | `getSubmissionByRequestId()` | Check for wallet response |
| `VPResultService` | `getVPResult()` | Get verification result |
| `PresentationDefinitionService` | `getPresentationDefinition()` | Get credential requirements |
| `WalletDataCache` | `storeData()`, `getData()` | Session state management |
| `QRCodeUtil` | `generateQRContent()` | Generate `openid4vp://` URI |

---

### 2. Servlet Package

**Files:** 9 servlets handling HTTP endpoints

**Role:** HTTP API layer for wallets and browser clients

```mermaid
graph TB
    subgraph "Servlet Layer"
        VPReq[VPRequestServlet<br>/request]
        ReqUri[RequestUriServlet<br>/request-uri/{id}]
        VPSub[VPSubmissionServlet<br>/response]
        VPStat[VPStatusPollingServlet<br>/status/{id}]
        VPRes[VPResultServlet<br>/result/{id}]
        VPDef[VPDefinitionServlet<br>/presentation-definitions]
        VCVer[VCVerificationServlet<br>/verify]
        DID[WellKnownDIDServlet<br>/.well-known/did.json]
    end

    subgraph "Services"
        VPReqSvc[VPRequestService]
        VPSubSvc[VPSubmissionService]
        VPResSvc[VPResultService]
        PDSvc[PresentationDefinitionService]
        VCSvc[VCVerificationService]
        DIDSvc[DIDDocumentService]
    end

    VPReq --> VPReqSvc
    ReqUri --> VPReqSvc
    VPSub --> VPSubSvc
    VPStat --> VPReqSvc
    VPRes --> VPResSvc
    VPDef --> PDSvc
    VCVer --> VCSvc
    DID --> DIDSvc
```

**Servlet → Service Mapping:**

| Servlet | Primary Service | Purpose |
|---------|----------------|---------|
| `VPRequestServlet` | `VPRequestService` | Create VP authorization request |
| `RequestUriServlet` | `VPRequestService` | Return JWT request object to wallet |
| `VPSubmissionServlet` | `VPSubmissionService` | Receive and process wallet VP |
| `VPStatusPollingServlet` | `VPRequestService` | Return current request status |
| `VPResultServlet` | `VPResultService` | Return detailed verification result |
| `VPDefinitionServlet` | `PresentationDefinitionService` | CRUD presentation definitions |
| `VCVerificationServlet` | `VCVerificationService` | Standalone VC verification |
| `WellKnownDIDServlet` | `DIDDocumentService` | Return verifier DID document |

**Additional Servlet Dependencies:**

| Servlet | Also Uses |
|---------|----------|
| `VPSubmissionServlet` | `WalletDataCache`, `LongPollingManager`, `VPSubmissionValidator` |
| `VPStatusPollingServlet` | `LongPollingManager`, `WalletDataCache` |
| `WalletStatusServlet` | `WalletDataCache`, `LongPollingManager` |

---

### 3. Service Package

**Files:** 11 service interfaces + 11 implementations

**Role:** Core business logic layer

```mermaid
graph TB
    subgraph "Request Flow Services"
        VPReq[VPRequestService]
        VPSub[VPSubmissionService]
        VPRes[VPResultService]
    end

    subgraph "Verification Services"
        VCVer[VCVerificationService]
        DIDRes[DIDResolverService]
        SLS[StatusListService]
    end

    subgraph "Configuration Services"
        PDS[PresentationDefinitionService]
        AppPD[AppPresentationDefinitionMappingService]
        TIS[TrustedIssuerService]
        TVS[TrustedVerifierService]
    end

    subgraph "Infrastructure Services"
        DIDS[DIDDocumentService]
    end

    VPSub --> VCVer
    VCVer --> DIDRes
    VCVer --> SLS
    VPReq --> PDS
    VPReq --> AppPD
    VCVer --> TIS
```

**Service Communication Patterns:**

| Service | Depends On | DAO Used |
|---------|-----------|----------|
| `VPRequestService` | `PresentationDefinitionService`, `VPRequestDAO` | `VPRequestDAO` |
| `VPSubmissionService` | `VCVerificationService`, `VPRequestService` | `VPSubmissionDAO` |
| `VPResultService` | `VPSubmissionService` | `VPSubmissionDAO` |
| `VCVerificationService` | `DIDResolverService`, `StatusListService`, `TrustedIssuerService` | None |
| `PresentationDefinitionService` | None | `PresentationDefinitionDAO` |
| `DIDResolverService` | External HTTP (Universal Resolver) | None |
| `StatusListService` | External HTTP (Status List endpoints) | None |

---

### 4. DAO Package

**Files:** 5 DAO interfaces + 5 implementations

**Role:** Database persistence layer

```mermaid
graph LR
    subgraph "DAO Layer"
        VPReqDAO[VPRequestDAO]
        VPSubDAO[VPSubmissionDAO]
        PDDAO[PresentationDefinitionDAO]
        AppPDDAO[AppPresentationDefinitionMappingDAO]
        TIDAO[TrustedIssuerDAO]
    end

    subgraph "Database Tables"
        T1[(IDN_VP_REQUEST)]
        T2[(IDN_VP_SUBMISSION)]
        T3[(IDN_PRESENTATION_DEFINITION)]
        T4[(IDN_APPLICATION_PRESENTATION_DEFINITION)]
        T5[(IDN_TRUSTED_ISSUER)]
    end

    VPReqDAO --> T1
    VPSubDAO --> T2
    PDDAO --> T3
    AppPDDAO --> T4
    TIDAO --> T5
```

**DAO Methods:**

| DAO | Key Operations |
|-----|---------------|
| `VPRequestDAO` | `create()`, `get()`, `updateStatus()`, `delete()`, `deleteExpired()` |
| `VPSubmissionDAO` | `create()`, `getByRequestId()`, `getById()`, `delete()` |
| `PresentationDefinitionDAO` | `create()`, `get()`, `update()`, `delete()`, `list()` |
| `AppPresentationDefinitionMappingDAO` | `create()`, `getByAppId()`, `delete()` |
| `TrustedIssuerDAO` | `create()`, `getByDid()`, `list()`, `delete()` |

---

### 5. Cache Package

**Files:** `VPRequestCache`, `VPStatusListenerCache`, `WalletDataCache`

**Role:** In-memory state management for real-time flows

```mermaid
graph TB
    subgraph "Cache Layer"
        VPReqCache[VPRequestCache<br>VP Request Objects]
        VPStatusCache[VPStatusListenerCache<br>Polling Listeners]
        WalletCache[WalletDataCache<br>Session Data + VP Tokens]
    end

    AUTH[Authenticator] --> VPReqCache
    AUTH --> WalletCache
    SERVLET[Servlets] --> WalletCache
    SERVLET --> VPStatusCache
    POLLING[LongPollingManager] --> VPStatusCache
    POLLING --> WalletCache
```

**Cache Usage:**

| Cache | Stores | Used By |
|-------|--------|---------|
| `VPRequestCache` | VP request objects | Authenticator (quick lookup during polling) |
| `VPStatusListenerCache` | Async response listeners | LongPollingManager, StatusPollingServlet |
| `WalletDataCache` | Session data, VP tokens, submissions | Authenticator, Servlets, LongPollingManager |

**Key WalletDataCache Methods:**
```java
storeVPRequest(requestId, vpRequest)
getVPRequest(requestId)
storeVPToken(requestId, vpToken)
getVPToken(requestId)
storeSubmission(requestId, submission)
getSubmission(requestId)
```

---

### 6. Polling Package

**Files:** `LongPollingManager`, `PollingResult`

**Role:** Coordinate async wait for wallet response

```mermaid
sequenceDiagram
    participant Browser
    participant StatusServlet
    participant LongPollingManager
    participant WalletDataCache
    participant SubmissionServlet
    participant Wallet

    Browser->>StatusServlet: GET /status/{id}
    StatusServlet->>LongPollingManager: waitForResult(requestId, timeout)
    LongPollingManager->>LongPollingManager: Create CompletableFuture
    
    Wallet->>SubmissionServlet: POST /response
    SubmissionServlet->>WalletDataCache: storeSubmission()
    SubmissionServlet->>LongPollingManager: notifyResult(requestId, result)
    LongPollingManager->>LongPollingManager: Complete Future
    
    LongPollingManager-->>StatusServlet: PollingResult
    StatusServlet-->>Browser: {"status": "completed"}
```

**LongPollingManager Methods:**
```java
waitForResult(requestId, timeoutSeconds) → PollingResult
notifyResult(requestId, pollingResult)
cancelWait(requestId)
```

---

### 7. Handler Package

**Files:** `VPRequestBuilder`, `VPResponseHandler`

**Role:** Construct/parse protocol messages

```mermaid
graph LR
    subgraph "Handlers"
        Builder[VPRequestBuilder]
        Handler[VPResponseHandler]
    end

    AUTH[Authenticator] --> Builder
    SERVLET[VPSubmissionServlet] --> Handler
    Builder --> |creates| REQ[JWT Request Object]
    Handler --> |parses| VP[VP Token]
```

| Handler | Input | Output |
|---------|-------|--------|
| `VPRequestBuilder` | PresentationDefinition, config | Signed JWT authorization request |
| `VPResponseHandler` | VP Token, Presentation Submission | Parsed VerifiablePresentation, extracted VCs |

---

### 8. Util Package

**Files:** 10 utility classes

**Role:** Stateless helper functions

```mermaid
graph TB
    subgraph "Cryptography"
        SigVer[SignatureVerifier]
        DIDKey[DIDKeyManager]
        BCED[BCEd25519Signer]
        SecUtil[SecurityUtils]
    end

    subgraph "Validation"
        VPVal[VPSubmissionValidator]
        PDUtil[PresentationDefinitionUtil]
    end

    subgraph "Protocol"
        QR[QRCodeUtil]
        O4VP[OpenID4VPUtil]
        CORS[CORSUtil]
    end

    subgraph "Logging"
        Logger[OpenID4VPLogger]
    end
```

**Utility Dependencies:**

| Utility | Used By | Purpose |
|---------|---------|---------|
| `SignatureVerifier` | `VCVerificationService` | Verify JWT/VC signatures |
| `VPSubmissionValidator` | `VPSubmissionServlet`, `VPSubmissionService` | Validate VP against definition |
| `DIDKeyManager` | `DIDDocumentService`, `VPRequestBuilder` | Generate/manage Ed25519 keys |
| `BCEd25519Signer` | `VPRequestBuilder` | Sign JWT requests |
| `QRCodeUtil` | `OpenID4VPAuthenticator` | Generate QR code content |
| `PresentationDefinitionUtil` | `PresentationDefinitionService` | Parse/validate definitions |
| `OpenID4VPUtil` | Multiple | Common helpers |
| `CORSUtil` | Servlets | Add CORS headers |
| `SecurityUtils` | Verification services | Crypto utilities |
| `OpenID4VPLogger` | All | Structured logging |

---

### 9. Internal Package

**Files:** 4 OSGi components

**Role:** Component lifecycle and service registration

```mermaid
graph TB
    subgraph "OSGi Components"
        VPReg[VPServiceRegistrationComponent]
        VPServlet[VPServletRegistrationComponent]
        DBInit[DatabaseSchemaInitializer]
        Holder[VPServiceDataHolder]
    end

    subgraph "Registered Artifacts"
        AUTH[OpenID4VPAuthenticator]
        SERVLETS[HTTP Servlets]
        SERVICES[Service OSGi Services]
    end

    VPReg --> |registers| AUTH
    VPReg --> |registers| SERVICES
    VPReg --> |calls| DBInit
    VPServlet --> |registers| SERVLETS
    Holder --> |holds| SERVICES
```

**VPServiceDataHolder Pattern:**
```java
// Singleton holding service references
VPServiceDataHolder.getInstance().getVPRequestService()
VPServiceDataHolder.getInstance().getVPSubmissionService()
VPServiceDataHolder.getInstance().getPresentationDefinitionService()
// ... etc
```

---

## Complete Request Flow

### VP Authentication Flow (End-to-End)

```mermaid
sequenceDiagram
    participant U as User Browser
    participant IS as Identity Server
    participant W as Wallet

    Note over U,IS: Phase 1: Initialize
    U->>IS: 1. Access protected app
    IS->>IS: 2. OpenID4VPAuthenticator.initiateAuthenticationRequest()
    IS->>IS: 3. VPRequestService.createVPRequest()
    IS->>IS: 4. VPRequestDAO.create()
    IS->>IS: 5. QRCodeUtil.generateQRContent()
    IS-->>U: 6. wallet_login.jsp + QR

    Note over W,IS: Phase 2: Wallet Interaction
    W->>IS: 7. GET /request-uri/{id}
    IS->>IS: 8. RequestUriServlet → VPRequestService.getRequest()
    IS-->>W: 9. JWT Authorization Request

    W->>W: 10. User selects credential
    W->>IS: 11. POST /response (vp_token)
    IS->>IS: 12. VPSubmissionServlet.doPost()
    IS->>IS: 13. VPSubmissionValidator.validate()
    IS->>IS: 14. VCVerificationService.verify()
    IS->>IS: 15. SignatureVerifier.verifySignature()
    IS->>IS: 16. DIDResolverService.resolveDID()
    IS->>IS: 17. StatusListService.checkRevocation()
    IS->>IS: 18. VPSubmissionService.saveSubmission()
    IS->>IS: 19. WalletDataCache.storeSubmission()
    IS->>IS: 20. LongPollingManager.notifyResult()
    IS-->>W: 21. HTTP 200 OK

    Note over U,IS: Phase 3: Complete Auth
    U->>IS: 22. Poll /status/{id}
    IS->>IS: 23. VPStatusPollingServlet → LongPollingManager
    IS-->>U: 24. {"status": "VP_SUBMITTED"}
    U->>IS: 25. POST /commonauth (status=success)
    IS->>IS: 26. OpenID4VPAuthenticator.processAuthenticationResponse()
    IS->>IS: 27. VPResultService.getVPResult()
    IS->>IS: 28. Extract credentialSubject.id
    IS-->>U: 29. Redirect to app (authenticated)
```

---

## Exception Flow

```mermaid
graph TB
    subgraph "Exception Hierarchy"
        VPEx[VPException]
        ReqNF[VPRequestNotFoundException]
        ReqExp[VPRequestExpiredException]
        SubNF[VPSubmissionNotFoundException]
        SubVal[VPSubmissionValidationException]
        CredVer[CredentialVerificationException]
        DIDRes[DIDResolutionException]
        RevCheck[RevocationCheckException]
    end

    VPEx --> ReqNF
    VPEx --> ReqExp
    VPEx --> SubNF
    VPEx --> SubVal
    VPEx --> CredVer
    VPEx --> DIDRes
    VPEx --> RevCheck

    subgraph "Handlers"
        SERV[Servlets]
        SVC[Services]
    end

    SVC --> |throws| VPEx
    SERV --> |catches & maps| HTTP[HTTP Error Response]
```

**Exception → HTTP Mapping:**

| Exception | HTTP Status | Error Code |
|-----------|-------------|------------|
| `VPRequestNotFoundException` | 404 | `request_not_found` |
| `VPRequestExpiredException` | 400 | `expired_request` |
| `VPSubmissionValidationException` | 400 | `invalid_presentation` |
| `CredentialVerificationException` | 400 | `invalid_proof` |
| `DIDResolutionException` | 502 | `server_error` |
| `RevocationCheckException` | 400 | `credential_revoked` |

---

## Summary

| Layer | Components | Responsibility |
|-------|------------|----------------|
| **Entry** | Authenticator, Servlets | HTTP/Auth framework integration |
| **Business** | Services, Handlers | Core logic, verification |
| **State** | Cache, Polling | Real-time coordination |
| **Persistence** | DAO | Database operations |
| **Support** | Util, Exception, Constant | Helpers, errors, config |
| **Infrastructure** | Internal | OSGi lifecycle |
