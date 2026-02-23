# OID4VP Presentation Module

**Package:** `org.wso2.carbon.identity.openid4vc.oid4vp.presentation`

## Purpose

Application layer implementing the OpenID4VP verifier flow for WSO2 Identity Server. Contains the federated authenticator, HTTP endpoints, business logic, and data access.

**Dependencies:** `oid4vp.common`, `oid4vp.did`, `oid4vp.verification`

## API Endpoints

| Method | Path | Servlet | Description |
|--------|------|---------|-------------|
| POST | `/openid4vp/v1/vp-request` | `VPRequestServlet` | Create VP request |
| GET | `/openid4vp/v1/vp-request/{id}` | `VPRequestServlet` | Get request JWT |
| GET | `/openid4vp/v1/request-uri/{id}` | `RequestUriServlet` | Wallet fetches authorization request |
| POST | `/openid4vp/v1/response` | `VPSubmissionServlet` | Wallet submits VP (direct_post) |
| GET | `/openid4vp/v1/vp-status/{id}/status` | `VPStatusPollingServlet` | Poll VP request status |
| GET | `/openid4vp/v1/wallet-status/{id}` | `WalletStatusServlet` | Login page polls for completion |
| CRUD | `/openid4vp/v1/presentation-definitions` | `VPDefinitionServlet` | Manage presentation definitions |
| POST | `/openid4vp/v1/vc-verification` | `VCVerificationServlet` | Verify a VC |
| GET | `/.well-known/did.json` | `WellKnownDIDServlet` | Serve verifier DID document |

## Package Structure

| Package | Description |
|---------|-------------|
| `authenticator` | `OpenID4VPAuthenticator` – WSO2 IS federated authenticator |
| `servlet` | HTTP servlet endpoints |
| `service` | Business logic interfaces |
| `service.impl` | Service implementations |
| `handler` | VP request builder and response handler |
| `dao` | Data access for presentation definitions and VP requests |
| `cache` | In-memory caching (`VPRequestCache`, `WalletDataCache`, `VPStatusListenerCache`) |
| `polling` | Long-polling manager for async status updates |
| `status` | Status notification and transition management |
| `listener` | IdP management listener for presentation definition sync |
| `internal` | OSGi components and service holders |
| `util` | QR code generation, signature verification |

## Authentication Flow

```
1. User clicks "Login with Wallet"
   ↓
2. OpenID4VPAuthenticator.initiateAuthenticationRequest()
   ├─ Creates VP Request (VPRequestService)
   ├─ Generates DID + signs request JWT (DID module)
   ├─ Generates QR code content
   └─ Redirects to wallet_login.jsp with QR data
   ↓
3. User scans QR code with wallet app
   ↓
4. Wallet fetches authorization request via GET /request-uri/{id}
   ↓
5. Wallet processes request + selects credentials
   ↓
6. Wallet POSTs VP to /openid4vp/v1/response (direct_post)
   ├─ VPSubmissionServlet validates + caches submission
   └─ Notifies status listeners
   ↓
7. Login page polls /wallet-status/{id} → detects "VP_SUBMITTED"
   ↓
8. OpenID4VPAuthenticator.processAuthenticationResponse()
   ├─ Retrieves cached VP submission
   ├─ Extracts format from presentation_submission
   ├─ Verifies VP token (verification module)
   ├─ Extracts + maps claims to local claims
   └─ Creates AuthenticatedUser with attributes
   ↓
9. WSO2 IS issues ID token with mapped claims
```

## Authenticator Configuration Properties

| Property | Display Name | Default | Description |
|----------|-------------|---------|-------------|
| `presentationDefinition` | Presentation Definition ID | — | UUID of the definition to use |
| `ResponseMode` | Response Mode | `direct_post` | `direct_post` or `direct_post.jwt` |
| `TimeoutSeconds` | Timeout | `300` | VP request expiry in seconds |
| `ClientId` | Client ID | auto | Client ID for VP requests |
| `SubjectClaim` | Subject Claim | `credentialSubject.id` | Claim path for subject identifier |
| `DIDMethod` | DID Method | — | `did:web`, `did:key`, or `did:jwk` |
