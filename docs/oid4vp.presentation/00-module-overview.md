# OID4VP Presentation Module — Overview

## 1. Purpose

The `org.wso2.carbon.identity.openid4vc.oid4vp.presentation` module implements the **Verifier (RP)** side of the [OpenID for Verifiable Presentations (OID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) specification inside WSO2 Identity Server.

In practical terms it:

| Responsibility | What it does |
|---|---|
| **Authenticator** | Integrates as a WSO2 IS federated authenticator so that any SP can use "Login with Wallet" |
| **Authorization Request** | Builds OID4VP authorization requests (by-value JSON **or** signed JWT) containing a Presentation Definition |
| **QR Code / Deep Link** | Generates the `openid4vp://authorize?…` URI that a wallet scans |
| **VP Submission** | Receives the wallet's `direct_post` response carrying `vp_token` + `presentation_submission` |
| **Polling / Long-Polling** | Bridges the async gap between the browser (waiting) and the wallet (submitting) using an in-memory listener + `CountDownLatch` approach |
| **Credential Verification** | Delegates to the `oid4vp.verification` module for SD-JWT / JWT / JSON-LD VC verification |
| **Presentation Definition CRUD** | Full lifecycle management of Presentation Definitions stored in the `IDN_PRESENTATION_DEFINITION` table |
| **Trusted Verifier Management** | In-memory registry of trusted verifiers with DID/clientId indexing |
| **Status State Machine** | Enforces `ACTIVE → VP_SUBMITTED → COMPLETED / EXPIRED` transitions |
| **DID Document Serving** | Exposes `/.well-known/did.json` via the `did:web` method |

---

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  Browser / React SPA                                                            │
│  ┌──────────────┐   polls    ┌──────────────────┐   scanned by   ┌──────────┐  │
│  │ wallet_login  │──────────→│ WalletStatusServlet│               │  Wallet  │  │
│  │    .jsp       │           └──────────────────┘               │  App     │  │
│  └──────┬───────┘                                               └────┬─────┘  │
│         │ shows QR                                                    │        │
│         │                                                             │        │
└─────────┼─────────────────────────────────────────────────────────────┼────────┘
          │                                                             │
          ▼                                                             ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│  WSO2 Identity Server  (OSGi Runtime)                                           │
│                                                                                  │
│  ┌──────────────────────┐        ┌──────────────────────┐                        │
│  │ OpenID4VPAuthenticator│───────→│ VPRequestServiceImpl │                        │
│  │  (Federated Auth)     │  uses  │  (creates VPRequest) │                        │
│  └──────────┬───────────┘        └───────────┬──────────┘                        │
│             │                                │                                   │
│             │ QR content                     │ stores in                          │
│             ▼                                ▼                                   │
│  ┌──────────────────┐             ┌──────────────────┐                           │
│  │   QRCodeUtil      │             │  VPRequestCache   │ (in-memory)              │
│  │  openid4vp://…    │             │  ConcurrentHashMap│                          │
│  └──────────────────┘             └──────────────────┘                           │
│                                                                                  │
│  Wallet calls:                                                                   │
│  ┌────────────────────┐   ┌────────────────────┐   ┌──────────────────────┐      │
│  │RequestUriServlet    │   │VPSubmissionServlet  │   │VPStatusPollingServlet│      │
│  │GET /request-uri/{id}│   │POST /response       │   │GET /vp-status/{id}  │      │
│  └────────────────────┘   └─────────┬──────────┘   └──────────┬───────────┘      │
│                                     │                          │                 │
│                                     ▼                          ▼                 │
│                          ┌─────────────────────┐    ┌────────────────────┐        │
│                          │StatusNotificationSvc │    │LongPollingManager  │        │
│                          │  notify listeners    │    │ CountDownLatch     │        │
│                          └─────────┬───────────┘    └────────────────────┘        │
│                                    │                                             │
│                                    ▼                                             │
│                          ┌─────────────────────┐                                 │
│                          │VPStatusListenerCache │                                 │
│                          │  StatusCallback      │◄──── Authenticator registers    │
│                          └─────────────────────┘      itself as callback          │
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────┐               │
│  │ Persistence Layer                                              │               │
│  │  ┌──────────────────────────┐  ┌────────────────────────────┐ │               │
│  │  │PresentationDefinitionDAO │  │VPRequestDAOImpl            │ │               │
│  │  │   (JDBC → H2/MySQL)      │  │   (Cache-based, no DB)     │ │               │
│  │  │ IDN_PRESENTATION_DEFN    │  │   wraps VPRequestCache     │ │               │
│  │  └──────────────────────────┘  └────────────────────────────┘ │               │
│  └────────────────────────────────────────────────────────────────┘               │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Module Dependencies

| Dependency | Purpose |
|---|---|
| `oid4vp.common` | Shared models (`VPRequest`, `VPSubmission`, `PresentationDefinition`), DTOs, exceptions, constants, utility classes |
| `oid4vp.did` | DID Document generation/resolution, `DIDProvider` / `DIDProviderFactory` for signing JWT request objects |
| `oid4vp.verification` | `VCVerificationService` for SD-JWT token verification, issuer trust verification |
| `carbon.identity.application.authentication.framework` | Federated authenticator SPI (`AbstractApplicationAuthenticator`) |
| `carbon.identity.core` | `IdentityDatabaseUtil` for JDBC connections, `IdentityUtil` for config properties |
| `carbon.identity.application.mgt` | `ApplicationManagementService` for IDP lookups |
| `carbon.idp.mgt` | `IdentityProviderMgtListener` SPI for IDP lifecycle hooks |
| `osgi.service.http` | `HttpService` for programmatic servlet registration |
| `nimbus-jose-jwt` (Orbit) | JWT creation, signing (`JWSObject`, `JWSSigner`, `JWTClaimsSet`) |
| `gson` | JSON serialization/deserialization throughout |
| `json-path` + `json-smart` | Embedded in the OSGi bundle for JSONPath evaluation |

---

## 4. Package Structure

```
org.wso2.carbon.identity.openid4vc.oid4vp.presentation
├── authenticator/
│   └── OpenID4VPAuthenticator.java        # WSO2 IS federated authenticator
├── cache/
│   ├── VPRequestCache.java                # In-memory cache for active VP requests
│   ├── VPStatusListenerCache.java         # Long-polling listener registry
│   └── WalletDataCache.java              # Temp storage for tokens, contexts, submissions
├── dao/
│   ├── PresentationDefinitionDAO.java     # Interface – CRUD for definitions
│   ├── VPRequestDAO.java                  # Interface – CRUD for VP requests
│   └── impl/
│       ├── PresentationDefinitionDAOImpl.java  # JDBC implementation
│       └── VPRequestDAOImpl.java               # Cache-based implementation
├── handler/
│   ├── VPRequestBuilder.java              # Builds authorization request JSON/JWT
│   └── VPResponseHandler.java             # Processes VP submissions, validates tokens
├── internal/
│   ├── OpenID4VCPresentationDataHolder.java   # Eager singleton data holder
│   ├── VPServiceDataHolder.java               # Lazy singleton (DCL) data holder
│   ├── VPServiceRegistrationComponent.java    # OSGi component – registers services + authenticator
│   └── VPServletRegistrationComponent.java    # OSGi component – registers all 8 servlets
├── listener/
│   └── OpenID4VPIdentityProviderMgtListener.java  # IDP lifecycle → PresentationDef management
├── polling/
│   ├── LongPollingManager.java            # CountDownLatch-based long polling
│   └── PollingResult.java                 # Immutable result with factory methods
├── servlet/
│   ├── RequestUriServlet.java             # GET /request-uri/{id}
│   ├── VCVerificationServlet.java         # POST /vc-verification
│   ├── VPDefinitionServlet.java           # CRUD /presentation-definitions
│   ├── VPRequestServlet.java              # POST/GET /vp-request
│   ├── VPStatusPollingServlet.java        # GET /vp-status/{id}
│   ├── VPSubmissionServlet.java           # POST /response  (direct_post)
│   ├── WalletStatusServlet.java           # GET /wallet-status
│   └── WellKnownDIDServlet.java           # GET /.well-known/did.json
├── service/
│   ├── PresentationDefinitionService.java # Interface
│   ├── TrustedVerifierService.java        # Interface
│   ├── VPRequestService.java              # Interface
│   └── impl/
│       ├── PresentationDefinitionServiceImpl.java
│       ├── TrustedVerifierServiceImpl.java
│       └── VPRequestServiceImpl.java
├── status/
│   ├── StatusNotificationService.java     # Centralized notification coordinator
│   └── StatusTransitionManager.java       # State machine: ACTIVE → VP_SUBMITTED → COMPLETED
└── util/
    └── QRCodeUtil.java                    # QR content / HTML / JS generation
```

---

## 5. Servlet Endpoint Map

| Path | Servlet | Methods | Purpose |
|---|---|---|---|
| `/openid4vp/v1/vp-request` | `VPRequestServlet` | POST, GET | Create VP request; Get JWT or status |
| `/openid4vp/v1/request-uri` | `RequestUriServlet` | GET | Wallet fetches full authorization request |
| `/openid4vp/v1/response` | `VPSubmissionServlet` | POST | Wallet submits VP (direct_post) |
| `/openid4vp/v1/presentation-definitions` | `VPDefinitionServlet` | GET, POST, PUT | CRUD for Presentation Definitions |
| `/openid4vp/v1/vc-verification` | `VCVerificationServlet` | POST, GET | Single VC or VP verification |
| `/openid4vp/v1/vp-status` | `VPStatusPollingServlet` | GET | Long-polling status endpoint |
| `/openid4vp/v1/wallet-status` | `WalletStatusServlet` | GET | Login page polling (lightweight) |
| `/.well-known/did.json` | `WellKnownDIDServlet` | GET | DID Document for did:web |

---

## 6. Storage Strategy

| Data Type | Storage | Backed by | TTL |
|---|---|---|---|
| **VP Requests** | In-memory cache | `VPRequestCache` (`ConcurrentHashMap`) | Config-based (default 5 min) + LRU eviction |
| **Presentation Definitions** | Database | `IDN_PRESENTATION_DEFINITION` table via JDBC | Permanent until deleted |
| **VP Submissions** | In-memory cache | `WalletDataCache` | 5 minutes |
| **Long-poll listeners** | In-memory | `VPStatusListenerCache` | 10-second cleanup cycle |
| **Trusted Verifiers** | In-memory | `TrustedVerifierServiceImpl` (`ConcurrentHashMap`) | No expiry (runtime only) |

---

## 7. Key Design Decisions

1. **Cache-over-DB for VP Requests**: `VPRequestDAOImpl` delegates entirely to `VPRequestCache` — no database table exists for VP requests. This simplifies deployment and avoids DB schema changes for transient request data.

2. **Direct Processing Pattern**: When a VP is submitted, the `VPSubmissionServlet` stores the `VPSubmission` in cache and notifies listeners directly. The authenticator, registered as a `StatusCallback`, receives the submission object in-memory without a DB round-trip.

3. **Dual Polling Endpoints**: Both `VPStatusPollingServlet` and `WalletStatusServlet` serve status checks. `WalletStatusServlet` is a lighter endpoint used by the JSP login page, while `VPStatusPollingServlet` provides the full API with long-polling support.

4. **DID Provider Abstraction**: JWT request objects are signed using the `DIDProvider` from the `oid4vp.did` module, supporting `did:web`, `did:key`, and `did:jwk` methods dynamically based on IDP configuration.

5. **IDP Lifecycle Integration**: The `OpenID4VPIdentityProviderMgtListener` hooks into IDP create/update/delete events to automatically link or clean up Presentation Definitions.

---

## 8. Configuration

Configuration lives in `openid4vp.properties`:

| Property | Default | Description |
|---|---|---|
| `OpenID4VP.VPRequestExpirySeconds` | 300 | VP request TTL |
| `OpenID4VP.EnableRequestUri` | true | Use `request_uri` flow |
| `OpenID4VP.EnableRequestJWT` | false | Sign requests as JWT |
| `OpenID4VP.SigningAlgorithm` | RS256 | JWT signing algorithm |
| `OpenID4VP.VerificationEnabled` | true | Enable VC verification |
| `OpenID4VP.SupportedVCFormats` | jwt_vp_json,jwt_vc_json,ldp_vp,ldp_vc,vc+sd-jwt | Supported formats |
| `OpenID4VP.Cache.EntryExpirySeconds` | 300 | Cache TTL |
| `OpenID4VP.Cache.MaxEntries` | 1000 | Max cache entries |
| `OpenID4VP.QRCode.Size` | 300 | QR pixel dimensions |
| `OpenID4VP.QRCode.ErrorCorrectionLevel` | M | QR error correction |

---

## 9. Database Schema

Single table in `WSO2_CARBON_DB`:

```sql
CREATE TABLE IDN_PRESENTATION_DEFINITION (
    DEFINITION_ID  VARCHAR(255) NOT NULL,   -- UUID primary key
    RESOURCE_ID    VARCHAR(255),            -- IDP Resource ID (link)
    NAME           VARCHAR(255) NOT NULL,   -- Human-readable name
    DESCRIPTION    CLOB,                    -- Optional description
    DEFINITION_JSON CLOB NOT NULL,          -- Full Presentation Definition JSON
    TENANT_ID      INTEGER DEFAULT -1234,   -- Multi-tenant support
    PRIMARY KEY (DEFINITION_ID),
    UNIQUE (NAME, TENANT_ID)
);
```
