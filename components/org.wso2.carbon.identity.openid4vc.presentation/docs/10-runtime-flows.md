# OpenID4VP Runtime Flows

## Complete Authentication Flow Diagrams

This document provides detailed runtime flow diagrams for all major operations in the OpenID4VP component.

---

## Flow 1: Browser-Based Authentication (QR Code)

The primary use case - user scans QR code with mobile wallet.

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant IS as Identity Server
    participant DB as Database
    participant Wallet
    participant Issuer as Issuer DID

    rect rgb(240, 248, 255)
    note right of User: Phase 1: Initiation
    User->>Browser: 1. Access protected resource
    Browser->>IS: 2. Authentication request
    IS->>IS: 3. OpenID4VPAuthenticator.initiateAuthenticationRequest()
    IS->>IS: 4. resolvePresentationDefinitionId()
    IS->>DB: 5. Get presentation definition
    DB-->>IS: 6. Return definition
    IS->>IS: 7. Generate nonce, state
    IS->>IS: 8. createVPRequest()
    IS->>DB: 9. Store VP request
    IS->>IS: 10. QRCodeUtil.generateQRCode()
    IS-->>Browser: 11. Redirect to wallet_login.jsp with QR
    end

    rect rgb(255, 248, 240)
    note right of User: Phase 2: Wallet Interaction
    User->>Wallet: 12. Scan QR code
    Wallet->>IS: 13. GET /openid4vp/v1/request-uri/{id}
    IS->>DB: 14. Get VP request
    DB-->>IS: 15. Return request
    IS->>IS: 16. Build authorization request JWT
    IS-->>Wallet: 17. Return signed request object
    Wallet->>Wallet: 18. Parse presentation definition
    Wallet->>Wallet: 19. Find matching credentials
    Wallet->>User: 20. Show consent screen
    User->>Wallet: 21. Select credentials and confirm
    end

    rect rgb(240, 255, 240)
    note right of User: Phase 3: VP Submission
    Wallet->>Wallet: 22. Create Verifiable Presentation
    Wallet->>IS: 23. POST /openid4vp/v1/response
    Note over IS: VPSubmissionServlet.doPost()
    IS->>IS: 24. Parse vp_token
    IS->>IS: 25. Validate nonce, state
    IS->>IS: 26. Extract VCs from VP
    
    loop For each VC
        IS->>IS: 27. Get issuer DID
        IS->>Issuer: 28. Resolve DID document
        Issuer-->>IS: 29. Return DID document
        IS->>IS: 30. Verify signature
        IS->>IS: 31. Check expiration
        IS->>IS: 32. Check revocation status
    end
    
    IS->>DB: 33. Store VP submission
    IS->>DB: 34. Update request status = COMPLETED
    IS-->>Wallet: 35. HTTP 200 OK
    end

    rect rgb(255, 240, 255)
    note right of User: Phase 4: Authentication Completion
    Browser->>IS: 36. Poll GET /openid4vp/v1/status/{id}
    IS->>DB: 37. Get request status
    DB-->>IS: 38. status = COMPLETED
    IS-->>Browser: 39. Return {status: "completed"}
    Browser->>IS: 40. Status callback
    IS->>IS: 41. processAuthenticationResponse()
    IS->>DB: 42. Get VP submission
    IS->>IS: 43. Extract credentialSubject
    IS->>IS: 44. Find user by email/username
    IS->>IS: 45. Set authenticated user
    IS-->>Browser: 46. Redirect to application
    end
```

---

## Flow 2: VP Submission Processing

Detailed breakdown of what happens when wallet submits VP.

```mermaid
flowchart TD
    A[POST /openid4vp/v1/response] --> B[VPSubmissionServlet.doPost]
    B --> C[Parse form parameters]
    C --> D{vp_token present?}
    D -->|No| E[400: missing vp_token]
    D -->|Yes| F{state present?}
    F -->|No| G[400: missing state]
    F -->|Yes| H[Get VP request by state]
    
    H --> I{Request found?}
    I -->|No| J[404: request_not_found]
    I -->|Yes| K{Request expired?}
    K -->|Yes| L[400: expired_request]
    K -->|No| M[Parse VP token]
    
    M --> N{Token format?}
    N -->|JSON-LD| O[Parse as JSON]
    N -->|SD-JWT| P[Split by ~ separator]
    N -->|JWT| Q[Decode JWT payload]
    
    O --> R[Validate VP structure]
    P --> R
    Q --> R
    
    R --> S{Nonce matches request?}
    S -->|No| T[400: invalid_nonce]
    S -->|Yes| U[Extract VCs from VP]
    
    U --> V[For each VC]
    V --> W[VCVerificationService.verify]
    W --> X{All VCs valid?}
    X -->|No| Y[400: invalid_proof]
    X -->|Yes| Z[Create VPSubmission]
    
    Z --> AA[Store in database]
    AA --> AB[Update request status]
    AB --> AC[200 OK]
```

---

## Flow 3: VC Signature Verification

How individual credentials are verified.

```mermaid
flowchart TD
    A[VC Input] --> B[Parse as JWT or JSON-LD]
    B --> C[Extract issuer DID]
    C --> D{DID method?}
    
    D -->|did:web| E[HTTP GET /.well-known/did.json]
    D -->|did:key| F[Decode multibase key]
    D -->|did:jwk| G[Decode JWK from DID]
    D -->|Other| H[Universal Resolver]
    
    E --> I[Parse DID Document]
    F --> I
    G --> I
    H --> I
    
    I --> J{Key ID in JWT header?}
    J -->|Yes| K[Get specific verification method]
    J -->|No| L[Use first assertionMethod]
    
    K --> M[Extract public key]
    L --> M
    
    M --> N{Algorithm?}
    N -->|EdDSA| O[Ed25519 verify]
    N -->|ES256| P[ECDSA P-256 verify]
    N -->|RS256| Q[RSA verify]
    
    O --> R{Signature valid?}
    P --> R
    Q --> R
    
    R -->|No| S[INVALID_SIGNATURE]
    R -->|Yes| T[Check expiration]
    
    T --> U{exp claim passed?}
    U -->|Yes| V[EXPIRED]
    U -->|No| W{Revocation check enabled?}
    
    W -->|No| X[VALID]
    W -->|Yes| Y[Fetch status list]
    
    Y --> Z[Check bit at status index]
    Z --> AA{Bit set?}
    AA -->|Yes| AB[REVOKED]
    AA -->|No| X
```

---

## Flow 4: Presentation Definition Resolution

How the authenticator determines which definition to use.

```mermaid
flowchart TD
    A[resolvePresentationDefinitionId] --> B{App-specific mapping exists?}
    B -->|Yes| C[Use mapped definition ID]
    B -->|No| D{Authenticator config has ID?}
    
    D -->|Yes| E[Use configured definition ID]
    D -->|No| F{Default definition configured?}
    
    F -->|Yes| G[Use default definition ID]
    F -->|No| H[Create inline default definition]
    
    C --> I[Fetch from database]
    E --> I
    G --> I
    
    I --> J{Definition found?}
    J -->|No| K[PresentationDefinitionNotFoundException]
    J -->|Yes| L[Return definition]
    
    H --> L
```

---

## Flow 5: Polling State Machine

Browser polls for VP submission status.

```mermaid
stateDiagram-v2
    [*] --> PENDING: VP Request Created
    
    PENDING --> PENDING: Poll returns "pending"
    PENDING --> COMPLETED: Wallet submits valid VP
    PENDING --> FAILED: Verification fails
    PENDING --> EXPIRED: 5 min timeout
    
    COMPLETED --> Authenticated: Extract user
    FAILED --> ShowError: Display error
    EXPIRED --> ShowError: Display timeout
    
    Authenticated --> [*]
    ShowError --> [*]

    note right of PENDING
        Browser polls every 2 seconds
        GET /openid4vp/v1/status/{id}
    end note
    
    note right of COMPLETED
        Contains submissionId
        for result lookup
    end note
```

---

## Flow 6: Error Handling Chain

How errors propagate through the system.

```mermaid
flowchart TD
    subgraph "Servlet Layer"
        A[HTTP Request] --> B[Servlet.doPost]
        B --> C{try}
    end
    
    subgraph "Service Layer"
        C --> D[Service.process]
        D --> E{Validation}
        E -->|Fail| F[VPSubmissionValidationException]
        E -->|Pass| G[VC Verification]
        G -->|Fail| H[CredentialVerificationException]
        G -->|Pass| I[DID Resolution]
        I -->|Fail| J[DIDResolutionException]
        I -->|Pass| K[Success]
    end
    
    subgraph "Error Response"
        F --> L[400 Bad Request]
        H --> L
        J --> M[500 Server Error]
        
        L --> N["{ error, error_description }"]
        M --> N
    end
    
    K --> O[200 OK]
```

---

## API Endpoint Summary

| Endpoint | Method | Purpose | Success | Error |
|----------|--------|---------|---------|-------|
| `/openid4vp/v1/request` | POST | Create VP request | 201 | 400 |
| `/openid4vp/v1/request-uri/{id}` | GET | Wallet fetches request | 200 | 404 |
| `/openid4vp/v1/response` | POST | Wallet submits VP | 200 | 400 |
| `/openid4vp/v1/status/{id}` | GET | Poll status | 200 | 404 |
| `/openid4vp/v1/result/{id}` | GET | Get result | 200 | 404 |
| `/.well-known/did.json` | GET | Verifier DID doc | 200 | 500 |
