# OpenID4VP Data Storage Architecture

## Overview
The OpenID for Verifiable Presentations (OpenID4VP) implementation in WSO2 Identity Server uses a **Cache-based** storage mechanism for transient request data and the **Authentication Context** for successful authentication artifacts.

> **Note**: The `IDN_VP_REQUEST` database table has been removed to optimize performance and reduce database load for ephemeral request data.

## 1. Request Storage (Cache)

VP Requests are transient. They are created during authentication initiation and are only needed until the wallet submits a response or the request expires.

### Storage Mechanism
-   **Component**: `VPRequestCache`
-   **Underlying Store**: WSO2 Carbon Caching (JCache/Ehcache) or dedicated Distributed Cache.
-   **Key**: `REQUEST_ID` (UUID)
-   **Value**: `VPRequest` object (Serializable)

### Stored Data (`VPRequest` Object)
| Field | Description |
| :--- | :--- |
| `requestId` | Unique ID used in the QR code and deep link. |
| `transactionId` | Links to the browser session. |
| `nonce` | Security nonce for replay protection. |
| `presentationDefinitionId` | Reference to the required credentials. |
| `status` | Request state (`ACTIVE`, `COMPLETED`, `EXPIRED`, `CANCELLED`). |
| `didMethod` | DID method used for signing. |
| `signingAlgorithm` | Algorithm used for signing. |
| `expiryTime` | Timestamp when the request becomes invalid. |
| `tenantId` | Tenant isolation. |

### Lifecycle
1.  **Creation**: `processAuthenticationRequest` generates a `VPRequest` and puts it into the cache.
2.  **Polling**: The frontend polls for status updates using the `requestId`. The `VPResultServlet` or `OpenID4VPAuthenticator` checks the cache.
3.  **Completion**: When a valid response is received, the cache entry status is updated to `COMPLETED` (or removed depending on implementation).
4.  **Expiry**: Cache eviction policies automatically clean up expired requests.

---

## 2. Response Artifact Storage (Authentication Context)

Upon successful verification of a Verifiable Presentation, the relevant artifacts are stored in the **Authentication Context** to make them available to downstream components (e.g., adaptive authentication scripts, custom post-authentication handlers, or logging).

### Storage Mechanism
-   **Component**: `AuthenticationContext`
-   **Scope**: Request-scoped (available during the authentication flow).

### Stored Artifacts
| Constant Key | Description | Use Case |
| :--- | :--- | :--- |
| `OpenID4VPConstants.OPENID4VP_VP_TOKEN` | The raw **VP Token** (JWT or JSON-LD) received from the wallet. | Compliance logging, custom claim extraction, non-repudiation. |
| `OpenID4VPConstants.OPENID4VP_PRESENTATION_SUBMISSION` | The **Presentation Submission** JSON object. | Analyzing which credentials satisfied which input descriptors. |

### Accessing Data
Downstream components can retrieve these values using:
```java
String vpToken = (String) context.getProperty(OpenID4VPConstants.RequestParams.OPENID4VP_VP_TOKEN);
PresentationSubmissionDTO submission = (PresentationSubmissionDTO) context.getProperty( 
    OpenID4VPConstants.RequestParams.OPENID4VP_PRESENTATION_SUBMISSION
);
```

---

## 3. Persistent Configuration (Database)

While transient data is cached, configuration data remains in the database.

### `IDN_PRESENTATION_DEFINITION`
Stores the templates for what credentials can be requested.
-   **ID**: Unique definition ID.
-   **CONTENT**: The JSON definition body.
-   **TENANT_ID**: Tenant isolation.

### `IDN_APPLICATION_PRESENTATION_DEFINITION`
Maps specific applications to presentation definitions.
-   **APP_ID**: Service Provider ID.
-   **DEF_ID**: FK to `IDN_PRESENTATION_DEFINITION`.

---

## Summary of Changes from Previous Architecture

| Feature | Previous Architecture | Current Architecture |
| :--- | :--- | :--- |
| **Request Storage** | Database Table (`IDN_VP_REQUEST`) | Distributed Cache (`VPRequestCache`) |
| **Request JWT** | Stored in DB CLOB | Generated on-the-fly (`VPRequest.didMethod/signingAlgo`) |
| **Poll Status** | SQL Queries | Cache Lookups |
| **Cleanup** | Database Scheduled Task | Cache Eviction / TTL |
| **Artifacts** | Not exposed in Context | Exposed in `AuthenticationContext` |
