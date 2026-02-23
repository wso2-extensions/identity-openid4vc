# 09 — Flows & Sequence Diagrams

---

## 1. End-to-End OID4VP Authentication Flow

This is the **primary flow** — a user authenticates via a Verifiable Presentation from their wallet.

```
┌──────────┐   ┌─────────────┐   ┌──────────────┐   ┌────────────┐   ┌───────────┐
│  Browser  │   │  WSO2 IS    │   │ VP Servlets   │   │  Wallet    │   │ VP Engine │
│ (React)   │   │ Auth FW     │   │ (Tomcat)      │   │  (Mobile)  │   │ (Services)│
└─────┬─────┘   └──────┬──────┘   └──────┬────────┘   └─────┬──────┘   └─────┬─────┘
      │                │                  │                   │               │
      │  1. /authorize │                  │                   │               │
      ├───────────────►│                  │                   │               │
      │                │                  │                   │               │
      │  2. Dispatch to│ authenticator    │                   │               │
      │                ├─────────────────►│                   │               │
      │                │  initiateAuth()  │                   │               │
      │                │                  │                   │               │
      │                │  3. Create VP    │                   │               │
      │                │     Request      ├──────────────────────────────────►│
      │                │                  │  VPRequestService │               │
      │                │                  │  .createVPRequest()              │
      │                │                  │                   │               │
      │                │                  │  ◄────────────────────────────────┤
      │                │                  │  {requestId,      │               │
      │                │                  │   requestUri,     │               │
      │                │                  │   qrContent}      │               │
      │                │                  │                   │               │
      │  4. Redirect to wallet_login.jsp  │                   │               │
      │◄───────────────┤  (with QR code)  │                   │               │
      │                │                  │                   │               │
      │  ═══════════ QR Code Displayed ═══════════            │               │
      │                │                  │                   │               │
      │                │                  │  5. Wallet scans  │               │
      │                │                  │     QR code       │               │
      │                │                  │◄──────────────────┤               │
      │                │                  │  GET /request-uri │               │
      │                │                  │  /{requestId}     │               │
      │                │                  │                   │               │
      │                │                  │  6. Return auth   │               │
      │                │                  │     request JWT   │               │
      │                │                  ├──────────────────►│               │
      │                │                  │  (signed JWT w/   │               │
      │                │                  │   PD, nonce, etc) │               │
      │                │                  │                   │               │
      │  ═══════════ Wallet Processes Request ════════════    │               │
      │                │                  │                   │               │
      │                │                  │  7. Submit VP     │               │
      │                │                  │◄──────────────────┤               │
      │                │                  │  POST /response   │               │
      │                │                  │  (vp_token +      │               │
      │                │                  │   presentation_   │               │
      │                │                  │   submission)     │               │
      │                │                  │                   │               │
      │                │                  │  8. Validate +    │               │
      │                │                  │     Extract claims│               │
      │                │                  ├──────────────────────────────────►│
      │                │                  │  VPResponseHandler│               │
      │                │                  │  .processResponse()              │
      │                │                  │                   │               │
      │                │                  │  9. Store in      │               │
      │                │                  │     WalletData    │               │
      │                │                  │     Cache         │               │
      │                │                  │                   │               │
      │                │                  │  10. Notify       │               │
      │                │                  │      listeners    │               │
      │                │                  │      (status →    │               │
      │                │                  │       SUBMITTED)  │               │
      │                │                  │                   │               │
      │  ═══════════ Browser Polling (concurrent) ════════    │               │
      │                │                  │                   │               │
      │  11. Poll status│                 │                   │               │
      ├───────────────────────────────────►                   │               │
      │  GET /wallet-status?id=X          │                   │               │
      │                │                  │                   │               │
      │  12. Status: VP_SUBMITTED         │                   │               │
      │◄──────────────────────────────────┤                   │               │
      │                │                  │                   │               │
      │  13. POST commonauth             │                   │               │
      │      (sessionDataKey)             │                   │               │
      ├───────────────►│                  │                   │               │
      │                │                  │                   │               │
      │                │  14. processAuth │                   │               │
      │                │      Response()  │                   │               │
      │                │  - Get claims    │                   │               │
      │                │    from cache    │                   │               │
      │                │  - Map to IS     │                   │               │
      │                │    claims        │                   │               │
      │                │                  │                   │               │
      │  15. Auth success / token         │                   │               │
      │◄───────────────┤                  │                   │               │
      │                │                  │                   │               │
```

### Step-by-Step Breakdown

| Step | Component | Method | Key Details |
|------|-----------|--------|-------------|
| 1 | Browser | — | OAuth2 `/authorize` with `acr_values` or IDP selection |
| 2 | Auth Framework | `initiateAuthenticationRequest()` | Selects `OpenID4VPAuthenticator` based on IDP config |
| 3 | VPRequestServiceImpl | `createVPRequest()` | Resolves PD from IDP config, generates nonce/state, signs JWT with DID key |
| 4 | Authenticator | — | Returns redirect to `wallet_login.jsp` with `requestId` and QR content |
| 5 | RequestUriServlet | `doGet()` | Wallet fetches the full authorization request JWT |
| 6 | RequestUriServlet | — | Returns JWT from VPRequestCache |
| 7 | VPSubmissionServlet | `doPost()` | Wallet submits `vp_token` via `direct_post` response mode |
| 8 | VPResponseHandler | `processResponse()` | Validates nonce, parses JWT/JSON-LD, extracts claims |
| 9 | WalletDataCache | `putSubmission()` | Claims stored keyed by `state` |
| 10 | StatusNotificationService | `notifyVPSubmitted()` | Triggers all registered `StatusChangeListener` callbacks |
| 11-12 | WalletStatusServlet | `doGet()` | Browser's JS polls until status changes |
| 13 | Auth Framework | — | Browser posts back to `/commonauth` with `sessionDataKey` |
| 14 | Authenticator | `processAuthenticationResponse()` | Retrieves claims from WalletDataCache, applies ClaimMapping[] |
| 15 | Auth Framework | — | Standard OAuth2/OIDC token generation |

---

## 2. VP Request Creation Flow (Detail)

```
VPRequestServiceImpl.createVPRequest(tenantDomain, idpName)
│
├─ 1. getIdPByName(idpName, tenantDomain)
│      └─ IdentityProviderManager → IDP object
│
├─ 2. Extract authenticator config
│      └─ Find "OpenID4VPAuthenticator" in FederatedAuthenticatorConfig[]
│
├─ 3. Read authenticator properties
│      ├─ presentationDefinitionId
│      ├─ verifierDID (clientId)
│      ├─ responseUri
│      ├─ requestUriBase
│      └─ _internal config (expiry, signing, etc.)
│
├─ 4. Resolve Presentation Definition
│      └─ PresentationDefinitionService.getPresentationDefinition(pdId)
│
├─ 5. Generate identifiers
│      ├─ requestId = UUID
│      ├─ nonce = UUID
│      └─ state = UUID
│
├─ 6. Build authorization request JWT
│      └─ buildRequestObjectJwt()
│          ├─ DIDProviderFactory.getDIDProvider(did)
│          ├─ didProvider.getSigningKey() → JWK
│          ├─ Create JWSHeader (alg, kid, typ)
│          ├─ Create JWTClaimsSet
│          │    ├─ iss = verifierDID
│          │    ├─ aud = "https://self-issued.me/v2"
│          │    ├─ response_type = "vp_token"
│          │    ├─ response_mode = "direct_post"
│          │    ├─ response_uri
│          │    ├─ nonce, state
│          │    ├─ client_id = verifierDID
│          │    ├─ presentation_definition (JSON object)
│          │    └─ exp, iat, nbf
│          ├─ Sign with RSASSASigner(jwk)
│          └─ Return serialized JWT
│
├─ 7. Create VPRequest object
│      ├─ Set all fields
│      ├─ Set status = ACTIVE
│      └─ Set expiryTimestamp
│
├─ 8. Store in VPRequestDAO
│      └─ VPRequestDAOImpl → VPRequestCache.put()
│
├─ 9. Generate QR content
│      └─ QRCodeUtil.generateRequestUriQRContent(requestUri, clientId)
│          → "openid4vp://authorize?client_id=...&request_uri=..."
│
└─ 10. Return AuthorizationDetailsDTO
       ├─ requestId
       ├─ requestUri
       ├─ qrCodeContent
       ├─ qrCodeDataUrl
       └─ expiresIn
```

---

## 3. VP Submission Processing Flow (Detail)

```
VPSubmissionServlet.doPost(request, response)
│
├─ 1. Extract form parameters
│      ├─ vp_token (JWT or JSON)
│      ├─ presentation_submission (JSON)
│      └─ state
│
├─ 2. Validate state
│      └─ VPRequestDAO.getVPRequest(state)
│          └─ Returns VPRequest from cache
│
├─ 3. Validate request not expired
│      └─ Check expiryTimestamp > now
│
├─ 4. Parse VP token
│      └─ VPResponseHandler.processResponse(vpToken, submission, vpRequest)
│          │
│          ├─ Detect format: JWT vs JSON-LD
│          │
│          ├─ [JWT Path]
│          │   ├─ Parse as SignedJWT
│          │   ├─ Validate nonce (jwt.nonce == vpRequest.nonce)
│          │   ├─ Validate audience (jwt.aud contains responseUri)
│          │   ├─ TODO: Verify signature ⚠️
│          │   ├─ Extract "vp" claim → verifiableCredential[]
│          │   └─ For each VC:
│          │       ├─ Parse as nested JWT
│          │       └─ Extract credentialSubject claims
│          │
│          └─ [JSON-LD Path]
│              ├─ Parse as JsonObject
│              ├─ Extract "verifiableCredential" array
│              └─ For each VC:
│                  └─ Extract credentialSubject claims
│
├─ 5. Verify issuer trust (optional)
│      └─ Check VC issuer against known trusted issuers
│
├─ 6. Store extracted claims
│      └─ WalletDataCache.putSubmission(state, claims)
│
├─ 7. Update request status
│      └─ VPRequest.status = VP_SUBMITTED
│      └─ VPRequestDAO.updateVPRequest(vpRequest)
│
├─ 8. Notify listeners
│      ├─ StatusNotificationService.notifyVPSubmitted(requestId, claims)
│      └─ VPStatusListenerCache.notifyListeners(requestId, ...)
│          └─ For each StatusCallback:
│              callback.onSubmissionReceived(requestId, claims)
│              └─ Releases CountDownLatch in LongPollingManager
│
└─ 9. Return HTTP 200
       └─ {"status": "success"}
```

---

## 4. Long-Polling Sequence

```
┌──────────┐     ┌──────────────────┐     ┌─────────────────┐     ┌──────────────┐
│ Browser   │     │ VPStatusPolling  │     │ LongPolling      │     │ VPStatusList │
│ (JS)      │     │ Servlet          │     │ Manager          │     │ enerCache    │
└─────┬─────┘     └────────┬─────────┘     └────────┬─────────┘     └──────┬───────┘
      │                    │                         │                      │
      │  GET /vp-status/X  │                         │                      │
      │  ?timeout=30       │                         │                      │
      ├───────────────────►│                         │                      │
      │                    │                         │                      │
      │                    │  waitForStatusChange    │                      │
      │                    │  (requestId, 30s)       │                      │
      │                    ├────────────────────────►│                      │
      │                    │                         │                      │
      │                    │                         │  1. Check current    │
      │                    │                         │     status (cache    │
      │                    │                         │     then DAO)        │
      │                    │                         │                      │
      │                    │                         │  [If already done]   │
      │                    │                         │  Return immediately  │
      │                    │                         │                      │
      │                    │                         │  [If ACTIVE]         │
      │                    │                         │  2. Create           │
      │                    │                         │     CountDownLatch(1)│
      │                    │                         │                      │
      │                    │                         │  3. Register         │
      │                    │                         │     StatusCallback   │
      │                    │                         ├─────────────────────►│
      │                    │                         │                      │
      │                    │                         │  4. latch.await      │
      │                    │                         │     (timeout)        │
      │                    │                         │  ┌─── BLOCKED ───┐   │
      │                    │                         │  │               │   │
      ║ ════════════ Meanwhile, wallet submits VP ══════════════════════    │
      │                    │                         │  │               │   │
      │                    │                         │  │  5. Callback  │   │
      │                    │                         │  │  fires from   │◄──┤
      │                    │                         │  │  VPSubmission │   │
      │                    │                         │  │  Servlet      │   │
      │                    │                         │  │               │   │
      │                    │                         │  │  6. latch     │   │
      │                    │                         │  │  .countDown() │   │
      │                    │                         │  └─── UNBLOCK ──┘   │
      │                    │                         │                      │
      │                    │                         │  7. Remove listener  │
      │                    │                         ├─────────────────────►│
      │                    │                         │                      │
      │                    │  PollingResult          │                      │
      │                    │  (SUBMITTED)            │                      │
      │                    │◄────────────────────────┤                      │
      │                    │                         │                      │
      │  {"status":        │                         │                      │
      │   "VP_SUBMITTED",  │                         │                      │
      │   "complete":true} │                         │                      │
      │◄───────────────────┤                         │                      │
      │                    │                         │                      │
```

### Timeout Scenario

If no submission arrives within the timeout:

```
latch.await(timeout) → returns false (timed out)
│
├─ Re-check status one more time (in case of race condition)
│   └─ If still ACTIVE → PollingResult.timeout()
│   └─ If changed → PollingResult with new status
│
└─ Remove listener from cache
```

---

## 5. Presentation Definition CRUD Flow

```
┌──────────┐     ┌────────────────┐     ┌─────────────────────┐     ┌──────────────┐
│ Admin     │     │ VPDefinition   │     │ PresentationDef     │     │ PresentationDef│
│ (REST)    │     │ Servlet        │     │ ServiceImpl         │     │ DAOImpl       │
└─────┬─────┘     └───────┬────────┘     └──────────┬──────────┘     └──────┬────────┘
      │                   │                          │                       │
      │  POST /pres...    │                          │                       │
      │  {name, desc,     │                          │                       │
      │   definition}     │                          │                       │
      ├──────────────────►│                          │                       │
      │                   │                          │                       │
      │                   │  1. Parse JSON body      │                       │
      │                   │  2. Validate fields      │                       │
      │                   │                          │                       │
      │                   │  createPresentation      │                       │
      │                   │  Definition(dto, tenant) │                       │
      │                   ├─────────────────────────►│                       │
      │                   │                          │                       │
      │                   │                          │  3. Validate PD JSON  │
      │                   │                          │     (parse, check     │
      │                   │                          │      input_descriptors│
      │                   │                          │      constraints)     │
      │                   │                          │                       │
      │                   │                          │  4. Generate UUID     │
      │                   │                          │                       │
      │                   │                          │  addPresentation      │
      │                   │                          │  Definition(...)      │
      │                   │                          ├──────────────────────►│
      │                   │                          │                       │
      │                   │                          │                       │  5. JDBC INSERT
      │                   │                          │                       │  INTO IDN_PRES...
      │                   │                          │                       │  (DEFINITION_ID,
      │                   │                          │                       │   RESOURCE_ID,
      │                   │                          │                       │   NAME, DESC,
      │                   │                          │                       │   DEFINITION_JSON,
      │                   │                          │                       │   TENANT_ID)
      │                   │                          │                       │
      │                   │                          │◄──────────────────────┤
      │                   │◄─────────────────────────┤                       │
      │                   │  PresentationDefinition  │                       │
      │                   │  (with generated ID)     │                       │
      │                   │                          │                       │
      │  201 Created      │                          │                       │
      │  {id, name, ...}  │                          │                       │
      │◄──────────────────┤                          │                       │
```

---

## 6. IDP Lifecycle & Presentation Definition Linking

```
Admin creates IDP with OID4VP authenticator
│
├─ 1. IDP created in WSO2 IS database
│
├─ 2. doPostAddIdP() fires
│      └─ OpenID4VPIdentityProviderMgtListener
│
├─ 3. Find "OpenID4VPAuthenticator" config in IDP
│
├─ 4. Read "presentationDefinition" property
│      └─ This is the definition ID (UUID)
│
├─ 5. Get IDP's resourceId
│      └─ Used to link PD ↔ IDP
│
├─ 6. Lookup PresentationDefinition by ID
│      └─ PresentationDefinitionService.getPresentationDefinition(pdId)
│
├─ 7. Set resourceId on PresentationDefinition
│      └─ pd.setResourceId(idp.getResourceId())
│
└─ 8. Update PresentationDefinition in DB
       └─ PresentationDefinitionService.updatePresentationDefinition(pd)
```

### IDP Deletion Cleanup

```
Admin deletes IDP
│
├─ 1. doPreDeleteIdP() fires (BEFORE IDP is removed)
│
├─ 2. Lookup IDP by name → get resourceId
│
├─ 3. Find PresentationDefinition by resourceId
│      └─ If not found → try by name "<idpName> Definition"
│
└─ 4. Delete PresentationDefinition from DB
```

---

## 7. StatusCallback Flow (Authenticator as Listener)

When the authenticator uses **long-polling mode** (not browser polling):

```
OpenID4VPAuthenticator.process()
│
├─ 1. Register as StatusCallback
│      └─ VPStatusListenerCache.addListener(requestId, this)
│          (Authenticator implements StatusCallback)
│
├─ 2. Create CountDownLatch(1) internally
│
├─ 3. Wait for callback
│      └─ latch.await(pollingTimeout)
│
│  ═══════════ VP Submitted ═══════════
│
├─ 4. onSubmissionReceived(requestId, claims)
│      └─ Store claims in authenticator instance
│      └─ latch.countDown()
│
├─ 5. Execution resumes
│      └─ Return claims to auth framework
│
└─ [Alternative: onTimeout]
       └─ Return error to auth framework
```

> **Note**: In the current implementation, the authenticator primarily uses **browser-based polling** via `wallet_login.jsp` → `WalletStatusServlet`, not the direct `StatusCallback` approach. The callback mechanism exists but the browser redirect + polling is the active path.

---

## 8. State Machine (Status Transitions)

```
                    ┌─────────┐
                    │ ACTIVE  │
                    └────┬────┘
                         │
              ┌──────────┴──────────┐
              │                     │
              ▼                     ▼
     ┌────────────────┐      ┌──────────┐
     │ VP_SUBMITTED   │      │ EXPIRED  │
     └───────┬────────┘      └──────────┘
             │
     ┌───────┴───────┐
     │               │
     ▼               ▼
┌───────────┐  ┌──────────┐
│ COMPLETED │  │ EXPIRED  │
└───────────┘  └──────────┘
```

### Transition Rules (StatusTransitionManager)

| From | Allowed To | Trigger |
|------|-----------|---------|
| `ACTIVE` | `VP_SUBMITTED` | Wallet submits VP token |
| `ACTIVE` | `EXPIRED` | TTL exceeded, cleanup task |
| `VP_SUBMITTED` | `COMPLETED` | Authenticator successfully extracts claims |
| `VP_SUBMITTED` | `EXPIRED` | Timeout during claim processing |

> **⚠️ Important**: `StatusTransitionManager` defines these rules but they are **not enforced** in the actual codebase. Status updates are done directly on the `VPRequest` object without calling `StatusTransitionManager.transition()`.

---

## 9. Cross-Module Integration Points

```
┌────────────────────────────────────────────────────────────────────┐
│                     oid4vp.presentation                            │
│                                                                    │
│  ┌──────────────┐    ┌───────────────┐    ┌──────────────────┐    │
│  │ Authenticator │    │  Servlets     │    │  Services        │    │
│  └──────┬───────┘    └───────┬───────┘    └────────┬─────────┘    │
│         │                    │                      │              │
└─────────┼────────────────────┼──────────────────────┼──────────────┘
          │                    │                      │
          ▼                    ▼                      ▼
┌─────────────────┐  ┌──────────────────┐  ┌──────────────────────┐
│ oid4vp.common   │  │ oid4vp.did       │  │ oid4vp.verification  │
│                 │  │                  │  │                      │
│ • VPRequest     │  │ • DIDProvider    │  │ • VCVerification     │
│ • PresentationDef│ │   Factory        │  │   Service            │
│ • DTOs          │  │ • DIDProvider    │  │                      │
│ • Constants     │  │   (signing keys) │  │                      │
│ • Exceptions    │  │ • DIDDocument    │  │                      │
│ • Util classes  │  │   Service        │  │                      │
└─────────────────┘  └──────────────────┘  └──────────────────────┘
          │                    │                      │
          ▼                    ▼                      ▼
┌────────────────────────────────────────────────────────────────────┐
│                 WSO2 Carbon Identity Framework                     │
│  • ApplicationAuthenticator SPI                                   │
│  • IdentityProviderMgtListener SPI                                │
│  • IdentityProviderManager                                        │
│  • CarbonUtils (DB connections)                                   │
│  • IdentityUtil (config properties)                               │
└────────────────────────────────────────────────────────────────────┘
```
