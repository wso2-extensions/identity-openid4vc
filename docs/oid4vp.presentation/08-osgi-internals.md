# 08 — OSGi Internals & Utilities

---

## 1. Data Holders

### OpenID4VCPresentationDataHolder (67 lines)

**Eager singleton** (static final instance, no synchronization needed):

```java
private static final OpenID4VCPresentationDataHolder INSTANCE = new OpenID4VCPresentationDataHolder();
```

Holds:
- `VPRequestService`
- `PresentationDefinitionService`
- `ApplicationManagementService`

### VPServiceDataHolder (183 lines)

**Lazy singleton** (double-checked locking with `volatile`):

```java
private static volatile VPServiceDataHolder instance;
```

Holds:
- `RealmService`
- `VPRequestService`
- `PresentationDefinitionService`
- `VCVerificationService` — **lazy-initialized** with `new VCVerificationServiceImpl()` if null
- `DIDDocumentService` — **lazy-initialized** with `new DIDDocumentServiceImpl()` if null
- `ApplicationManagementService`

### ⚠️ Two Data Holders

There are **two** data holder classes. This is likely a result of iterative development:

| Class | Pattern | Used By |
|---|---|---|
| `OpenID4VCPresentationDataHolder` | Eager singleton, generic fields | Not heavily used in current code |
| `VPServiceDataHolder` | DCL singleton, more fields | Used by servlets, listener, authenticator |

**Recommendation**: Merge into one, or clearly document which should be used where.

---

## 2. VPServiceRegistrationComponent (132 lines)

### What It Is
An **OSGi Declarative Services (SCR) component** annotated with `@Component(immediate = true)`. This is the primary bootstrap point for the presentation module.

### Component Name
```
org.wso2.carbon.identity.openid4vc.presentation.service.component
```

### What It Does on `@Activate`

1. **Guards against double registration** — static `authenticatorRegistered` flag
2. **Creates service instances**:
   - `new VPRequestServiceImpl()`
   - `new PresentationDefinitionServiceImpl()`
3. **Registers OSGi services**:
   - `VPRequestService`
   - `PresentationDefinitionService`
4. **Sets services in data holder**: `VPServiceDataHolder.getInstance().set*()`
5. **Registers the authenticator**:
   - `new OpenID4VPAuthenticator()` → registered as `ApplicationAuthenticator`
6. **Registers IDP listener**:
   - `new OpenID4VPIdentityProviderMgtListener()` → registered as `IdentityProviderMgtListener`

### OSGi References (Dependencies)

| Reference | Service | Cardinality | Policy |
|---|---|---|---|
| `user.realm.service` | `RealmService` | MANDATORY | DYNAMIC |
| `ApplicationManagementService` | `ApplicationManagementService` | MANDATORY | DYNAMIC |

Both are injected into `VPServiceDataHolder`.

### Deactivate

Nulls out services in data holder. OSGi automatically unregisters the services.

### Code Review Notes

- **Static mutable state**: `authenticatorRegistered` is a static field written from an instance method (`@Activate`). This is flagged by FindBugs (`ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD`) and suppressed.
- **Empty catch block**: The entire `activate()` body is wrapped in a try-catch that silently swallows exceptions. If activation fails, no log entry is produced.
- **Direct instantiation**: Services are created with `new` instead of using constructor injection. While this works, it makes testing harder.

---

## 3. VPServletRegistrationComponent (190 lines)

### What It Is
A second OSGi SCR component, responsible for registering **all 8 HTTP servlets**.

### Component Name
```
org.wso2.carbon.identity.openid4vc.presentation.servlet.component
```

### Servlet Registration

Uses `HttpService.registerServlet(path, servlet, null, null)`:

| Path Constant | Servlet |
|---|---|
| `/openid4vp/v1/vp-request` | `VPRequestServlet` |
| `/openid4vp/v1/request-uri` | `RequestUriServlet` |
| `/openid4vp/v1/response` | `VPSubmissionServlet` |
| `/openid4vp/v1/presentation-definitions` | `VPDefinitionServlet` |
| `/openid4vp/v1/vc-verification` | `VCVerificationServlet` |
| `/openid4vp/v1/vp-status` | `VPStatusPollingServlet` |
| `/openid4vp/v1/wallet-status` | `WalletStatusServlet` |
| `/.well-known/did.json` | `WellKnownDIDServlet` |

### OSGi References

| Reference | Service | Cardinality |
|---|---|---|
| `osgi.http.service` | `HttpService` | MANDATORY |
| `user.realm.service` | `RealmService` | MANDATORY |

### Deactivation

Each servlet is unregistered individually in its own try-catch to prevent one failure from blocking others.

### Code Review Notes

- **New servlet instances**: Each call creates `new VPRequestServlet()` etc. These servlets then create their own service instances in `init()`. This means there's no connection between the OSGi-registered service singletons and what the servlets use.
- **No security filters**: The servlets are registered without any servlet filter chain. In a production WSO2 IS deployment, additional security filters (authentication, rate limiting) should be applied.

---

## 4. OpenID4VPIdentityProviderMgtListener (234 lines)

### What It Is
A WSO2 IS **Identity Provider Management Listener** that hooks into IDP lifecycle events. It manages the link between IDPs configured for OpenID4VP authentication and their associated Presentation Definitions.

### Hook Points

| Method | When | What It Does |
|---|---|---|
| `doPreAddIdP` | Before IDP create | No-op (previously intercepted JSON, now delegates to post-persist) |
| `doPostAddIdP` | After IDP create | Links Presentation Definition to IDP |
| `doPreUpdateIdP` | Before IDP update | No-op |
| `doPostUpdateIdP` | After IDP update | Re-links Presentation Definition |
| `doPreDeleteIdP` | Before IDP delete | Deletes associated Presentation Definition |
| `doPostDeleteIdP` | After IDP delete | No-op (data already cleaned in pre-delete) |

### Post-Persistence Logic (`handlePostPersistence`)

1. Find the `OpenID4VPAuthenticator` config in the IDP's `FederatedAuthenticatorConfig[]`
2. Get the `presentationDefinition` property value (this is a **definition ID**, not JSON)
3. Get the IDP's `resourceId`
4. Look up the Presentation Definition by ID
5. Link it to the IDP by setting `resourceId` on the definition
6. Update the definition in DB

### Pre-Delete Logic (`doPreDeleteIdP`)

1. Look up IDP by name to get `resourceId`
2. Find Presentation Definition by `resourceId`
3. If not found, try by name convention: `"<idpName> Definition"`
4. Delete the found definition

### Execution Order
`getDefaultOrderId()` returns **99** — runs relatively late in the listener chain, after core IDP operations.

### CRLF Injection Protection

Uses a `sanitize()` method for log messages:
```java
private String sanitize(String input) {
    return input.replace("\r", "").replace("\n", "");
}
```

---

## 5. QRCodeUtil (Utility, ~300 lines)

### Purpose
Generates QR code content (the `openid4vp://` URI) and provides helpers for HTML/JS rendering.

### Main Method: `generateRequestUriQRContent(requestUri, clientId)`

Produces:
```
openid4vp://authorize?client_id=<encoded>&request_uri=<encoded>
```

### By-Value Method: `generateByValueQRContent(AuthorizationDetailsDTO)`

For embedding the full authorization request in the QR code (instead of just a reference). Encodes all params: `client_id`, `response_type`, `response_mode`, `response_uri`, `nonce`, `state`, `presentation_definition`.

### QR Image Generation

`generateQRCodeDataUrl(content, size)` is a **placeholder** — returns a JSON object:
```json
{
  "type": "qrcode",
  "content": "openid4vp://...",
  "size": 300,
  "errorCorrection": "M"
}
```

The actual QR rendering is done client-side using JavaScript (QRCode.js). The `generateQRCodeScript()` method produces the JS code for rendering.

### Configuration

| Property | Default | Read From |
|---|---|---|
| `OpenID4VP.QRCode.Size` | 300 | `IdentityUtil.getProperty()` |
| `OpenID4VP.QRCode.ErrorCorrectionLevel` | M | `IdentityUtil.getProperty()` |

### Helper Methods

- `urlEncode(value)` — UTF-8 URL encoding
- `escapeJson(value)` — Escapes `\`, `"`, newlines for JSON strings
- `escapeHtml(value)` — Escapes `&`, `<`, `>`, `"`, `'` for HTML attributes
- `escapeJs(value)` — Escapes `\`, `'`, `"`, newlines for JavaScript strings

### Code Review Notes

| Issue | Details |
|---|---|
| **No server-side QR generation** | Depends on client-side JS. If JS is disabled or the library isn't loaded, no QR code is shown. |
| **HTML injection risk** | `generateQRCodeHtml()` includes `requestId` and `content` in HTML attributes. While `escapeHtml()` is used, this is a risk surface. |
| **ZXing comment** | The code has a commented-out ZXing implementation. This should be either implemented or removed. |

---

## OSGi Bundle Configuration (from pom.xml)

```xml
<Export-Package>
    !org.wso2.carbon.identity.openid4vc.oid4vp.presentation.internal,
    org.wso2.carbon.identity.openid4vc.oid4vp.presentation.*
</Export-Package>
<Private-Package>
    org.wso2.carbon.identity.openid4vc.oid4vp.presentation.internal
</Private-Package>
<Embed-Dependency>
    json-path, json-smart, accessors-smart, asm
</Embed-Dependency>
```

- The `internal` package is **private** — not visible to other bundles
- `json-path` and dependencies are **embedded** inside the bundle JAR
- All other packages are exported for use by other modules
- `DynamicImport-Package: *` — resolves optional dependencies at runtime
