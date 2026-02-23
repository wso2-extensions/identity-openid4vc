# 05 — Servlet Layer

Eight servlets are registered programmatically by `VPServletRegistrationComponent` via the OSGi `HttpService`. All servlets follow a consistent pattern: parse request → delegate to service/cache → send JSON response.

---

## 1. RequestUriServlet — `GET /openid4vp/v1/request-uri/{requestId}`

### Purpose
Serves the authorization request object to wallets using the `request_uri` flow. The wallet scans a QR code containing `request_uri=https://is.example.com/openid4vp/v1/request-uri/<requestId>`, then calls this endpoint to fetch the full request.

### Flow
```
Wallet → GET /request-uri/{requestId}
       → VPRequestServiceImpl.getRequestJwt(requestId)
       → Return JWT or JSON with appropriate Content-Type
```

### Response Content-Type
- If response starts with `eyJ` → `application/oauth-authz-req+jwt`
- Otherwise → `application/json`

### Error Responses
| Status | When |
|---|---|
| 400 | Missing or empty requestId |
| 404 | Request not found (`VPRequestNotFoundException`) |
| 410 | Request expired (`VPRequestExpiredException`) |
| 500 | Internal error |

### Headers
- `Cache-Control: no-store` — prevents caching of request objects (security requirement)
- `Pragma: no-cache`

---

## 2. VPSubmissionServlet — `POST /openid4vp/v1/response`

### Purpose
The **most critical servlet** — receives VP submissions from wallets via the `direct_post` response mode. This is the wallet's callback endpoint.

### Request Format
The OID4VP spec mandates `application/x-www-form-urlencoded`:

```
vp_token=<JWT or JSON-LD VP>&
presentation_submission=<JSON>&
state=<requestId>&
error=<optional>&
error_description=<optional>
```

The servlet also supports `application/json` as an alternative.

### Processing Flow

```
1. parseSubmission(request) → VPSubmissionDTO
2. VPSubmissionValidator.validateSubmission(dto)       // from verification module
3. verifyAllCredentialIssuers(vpToken, tenantDomain)   // trust check
4. Build VPSubmission object (in-memory, NO DB)
5. WalletDataCache.storeSubmission(requestId, submission)
6. VPRequestDAO.updateVPRequestStatus(requestId, VP_SUBMITTED)
7. notifyStatusListeners(requestId, submission)
8. sendSuccessResponse(response, submission)
```

### Issuer Trust Verification

`verifyAllCredentialIssuers()` extracts all VCs from the VP token:
1. Detects VP format (JWT vs JSON-LD)
2. Extracts `verifiableCredential` array
3. For each credential:
   - JWT VC → `VCVerificationService.verifyJWTVCIssuer(vcJwt, tenantDomain)`
   - JSON-LD VC → `VCVerificationService.verifyJSONLDVCIssuer(vcObj, tenantDomain)`
4. If any credential fails → returns `403 Forbidden` with `untrusted_issuer` error

### Notification Flow

```java
if (statusNotificationService != null) {
    statusNotificationService.notifyVPSubmitted(requestId, submission);
} else if (statusListenerCache != null) {
    statusListenerCache.notifyListenersWithSubmission(requestId, submission);
}
```

The notification has two paths:
- **Primary**: `StatusNotificationService` → coordinates both listener cache and long polling manager
- **Fallback**: Direct `VPStatusListenerCache.notifyListenersWithSubmission()` for direct processing

### Success Response
```json
{
  "status": "received",
  "submission_id": "<uuid>",
  "transaction_id": "<optional>"
}
```

---

## 3. VPDefinitionServlet — CRUD on `/openid4vp/v1/presentation-definitions`

### Endpoints

| Method | Path | Action |
|---|---|---|
| GET | `/presentation-definitions` | List all definitions |
| GET | `/presentation-definitions/{id}` | Get by ID |
| GET | `/presentation-definitions/{id}/claims` | Extract claims from definition |
| POST | `/presentation-definitions` | Create new definition |
| PUT | `/presentation-definitions/{id}` | Update existing definition |
| DELETE | `/presentation-definitions/{id}` | **Disabled** — returns 405 |

### Claims Extraction (`/claims` sub-path)

Parses the Presentation Definition JSON, iterates `input_descriptors[].constraints.fields[]`, and returns claim paths. This is used by the IDP configuration UI to display available claims for mapping.

### CORS Support
- `doOptions()` → `CORSUtil.handlePreflight(request, response)`
- All JSON responses include CORS headers via `CORSUtil.addCORSHeaders()`

### Tenant Resolution
Reads `X-Tenant-Id` header (with fallback to `Tenant-Id`), defaults to `-1234` (super tenant).

---

## 4. VPRequestServlet — `POST/GET /openid4vp/v1/vp-request`

### Endpoints

| Method | Path | Action |
|---|---|---|
| POST | `/vp-request` | Create new VP authorization request |
| GET | `/vp-request/{requestId}` | Get request JWT |
| GET | `/vp-request/{requestId}/status` | Poll for status (with long-polling) |

### Create VP Request (POST)

Accepts `VPRequestCreateDTO`:
```json
{
  "clientId": "did:web:example.com",
  "presentationDefinitionId": "abc-123",
  "nonce": "optional",
  "transactionId": "optional",
  "didMethod": "web",
  "signingAlgorithm": "EdDSA"
}
```

Delegates to `VPRequestServiceImpl.createVPRequest()`.

### Status Polling (GET with `/status`)

Uses `LongPollingManager.waitForStatusChange()` with configurable timeout. Returns `VPRequestStatusDTO`:
```json
{
  "requestId": "...",
  "status": "ACTIVE" | "VP_SUBMITTED" | "COMPLETED" | "EXPIRED"
}
```

---

## 5. VPStatusPollingServlet — `GET /openid4vp/v1/vp-status/{requestId}`

### Purpose
Dedicated status polling endpoint with full long-polling support. More featured than the status sub-path on `VPRequestServlet`.

### Query Parameters

| Param | Default | Description |
|---|---|---|
| `timeout` | 5s | Long poll timeout in seconds (max 120s) |
| `long_poll` | `false` | Explicitly enable long polling |
| `request_id` | — | Fallback param if not in path |

### Long-polling Detection
Long-polling is enabled if:
- `long_poll=true` or `long_poll=1`, **OR**
- `timeout` parameter is present

### Response (VPStatusResponseDTO)

```json
{
  "requestId": "...",
  "status": "ACTIVE" | "VP_SUBMITTED" | "EXPIRED" | "NOT_FOUND" | "ERROR",
  "tokenReceived": true | false,
  "expired": true | false,
  "timeout": true | false,
  "error": "...",
  "error_description": "..."
}
```

---

## 6. WalletStatusServlet — `GET /openid4vp/v1/wallet-status`

### Purpose
A **lightweight status check** used by `wallet_login.jsp` for browser-side polling. Simpler than `VPStatusPollingServlet`.

### Query Parameters
- `state` (required) — the requestId
- `timeout` — long poll timeout (default 60s)
- `long_poll` — enable long polling

### Immediate Status Check (no long poll)

Checks three sources in order:
1. `WalletDataCache.hasToken(state)` — raw VP token in cache
2. `WalletDataCache.hasSubmission(state)` — full submission in cache
3. **DB fallback**: `VPRequestService.getVPRequestById(state)` → check if status is VP_SUBMITTED or COMPLETED

### Response
```json
{
  "status": "success",
  "tokenReceived": true | false,
  "vpStatus": "ACTIVE" | "VP_SUBMITTED",
  "expired": true,      // if applicable
  "timeout": true,       // if applicable
  "walletError": true    // if applicable
}
```

---

## 7. VCVerificationServlet — `POST /openid4vp/v1/vc-verification`

### Purpose
Standalone VC/VP verification endpoint. Can verify individual VCs or full VPs.

### Routing
- Path contains `vp-verification` → `handleVPVerification()` — verifies entire VP, returns per-credential results
- Default → `handleVCVerification()` — verifies single VC

### Supported Content-Types
Delegates to `VCVerificationService.isContentTypeSupported()`:
- `application/vc+ld+json`
- `application/jwt` / `application/vc+jwt`
- `application/vc+sd-jwt`
- `application/json` (auto-detect)

### GET `/vc-verification/supported-formats`
Returns list of supported content types and VC formats.

---

## 8. WellKnownDIDServlet — `GET /.well-known/did.json`

### Purpose
Serves the DID Document for the `did:web` method. When the server's domain is `example.com`, this endpoint provides the DID Document for `did:web:example.com`.

### Flow
```
1. extractDomain() → reads from OpenID4VPUtil.getBaseUrl(), strips protocol
2. DIDDocumentServiceImpl.getDIDDocument(domain, tenantId)
3. Response Content-Type: application/did+json
4. CORS headers added
```

### Domain Extraction
Uses `OpenID4VPUtil.getBaseUrl()` (server configuration) rather than `request.getServerName()`, ensuring consistency regardless of how the request arrives.

---

## Common Patterns Across Servlets

### Tenant ID Resolution
All servlets that need tenant context use the same pattern:
```java
private int getTenantId(HttpServletRequest request) {
    String header = request.getHeader("X-Tenant-Id");
    if (isNotBlank(header)) return Integer.parseInt(header);
    return -1234; // super tenant
}
```

### Error Response Format
Most servlets use `ErrorDTO`:
```json
{
  "error": "invalid_request",
  "error_description": "Detailed message"
}
```

### Code Review Notes

| Issue | Servlet(s) | Severity |
|---|---|---|
| **No authentication/authorization** | All | 🔴 Critical — Servlets don't check if the caller is authenticated. `VPDefinitionServlet` allows anyone to create/update definitions. |
| **Hardcoded tenant ID** | All | 🟡 Medium — `DEFAULT_TENANT_ID = -1234` is used as fallback everywhere. No proper tenant resolution from auth context. |
| **New service instances in `init()`** | Most | 🟡 Medium — Each servlet creates `new VPRequestServiceImpl()` / `new PresentationDefinitionServiceImpl()` in `init()` instead of using the OSGi-registered singleton. |
| **XSS annotations** | All | 🟢 Low — `@SuppressFBWarnings("XSS_SERVLET")` is used liberally. The JSON responses are properly serialized via Gson, so XSS risk is minimal for JSON endpoints, but the annotations mask potential issues in error messages. |
| **DELETE disabled** | VPDefinitionServlet | 🟢 Info — `doDelete()` returns 405, comment says definitions are auto-deleted with connections. |
