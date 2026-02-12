# IDN_VP_REQUEST Table Documentation

## Overview
The `IDN_VP_REQUEST` table is the central storage for OpenID for Verifiable Presentations (OpenID4VP) authorization requests in WSO2 Identity Server. It tracks the lifecycle of a VP request from creation to expiry or completion.

## Table Schema & Column Usage

| Column Name | Data Type | Description | Usage/Function |
| :--- | :--- | :--- | :--- |
| **ID** | `INTEGER` | Auto-increment Primary Key | Internal reference. |
| **REQUEST_ID** | `VARCHAR(255)` | Unique UUID for the request | **Primary Identifier**. Used in URLs, API calls, and linking to submissions. |
| **TRANSACTION_ID** | `VARCHAR(255)` | OIDC Transaction identifier | Links the VP request to the original OIDC authentication flow. |
| **CLIENT_ID** | `VARCHAR(255)` | Service Provider / Client ID | Identifies the relying party app initiating the request. |
| **NONCE** | `VARCHAR(255)` | Security Nonce | Replay protection. Verified against the wallet's response. |
| **PRESENTATION_DEFINITION_ID** | `VARCHAR(255)` | FK to `IDN_PRESENTATION_DEFINITION` | ID of the specific presentation requirement (what credentials are requested). |
| **PRESENTATION_DEFINITION** | `TEXT` / `CLOB` | Full JSON of the Pres. Def. | **Snapshot** of the definition at request time. Used for validation to ensure requirements haven't changed during the flow. |
| **RESPONSE_URI** | `VARCHAR(2048)` | Redirect URI | Where the wallet should send the response (if not direct_post). |
| **RESPONSE_MODE** | `VARCHAR(50)` | e.g., `direct_post` | Defines how the wallet communicates the response. |
| **REQUEST_JWT** | `TEXT` / `CLOB` | Signed JWT | The actual signed Authorization Request Object sent to the wallet. |
| **STATUS** | `VARCHAR(50)` | Enum: `ACTIVE`, `EXPIRED`, `COMPLETED` | Tracks request state. |
| **CREATED_AT** | `BIGINT` | Timestamp (ms) | Audit and cleanup. |
| **EXPIRES_AT** | `BIGINT` | Timestamp (ms) | Enforcement of request validity window. |
| **TENANT_ID** | `INTEGER` | Tenant ID | Multi-tenancy isolation. |

## Key Functions & Behavior

### 1. Request Creation
- **Trigger**: When a user initiates a login with a connection configured for OpenID4VP.
- **Action**: A new row is inserted with status `ACTIVE`.
- **Key Data**: A signed `REQUEST_JWT` is generated and stored. The `PRESENTATION_DEFINITION` JSON is snapshotted into the table to freeze requirements.

### 2. Request Retrieval (Wallet Interaction)
- **Trigger**: The wallet scans the QR code or uses the deeplink.
- **Action**: The wallet fetches the request details using the `request_uri`.
- **Query**: `SELECT * FROM IDN_VP_REQUEST WHERE REQUEST_ID = ?`
- **Behavior**: Returns the `REQUEST_JWT` to the wallet.

### 3. Response Validation (Processing Submission)
- **Trigger**: Wallet submits the verifiable presentation (VP) to the `response_uri`.
- **Action**: The system looks up the request status.
- **Validation**:
    - Checks if `STATUS` is `ACTIVE`.
    - Checks if `Current Time < EXPIRES_AT`.
    - Verifies the `NONCE` in the response matches the stored `NONCE`.
- **State Change**: Upon successful verification, the status is updated (conceptually, though often the record is deleted or archived depending on retention policy).

### 4. Expiry & Cleanup
- **Trigger**: Scheduled task or lazy check.
- **Action**: Requests where `EXPIRES_AT < Current Time` are marked as `EXPIRED` or deleted.
- **Query**: `UPDATE IDN_VP_REQUEST SET STATUS = 'EXPIRED' WHERE ...`

## Lifecycle State Machine

1.  **Created** -> `ACTIVE`
2.  **Wallet Fetches** -> Remains `ACTIVE`
3.  **Wallet Responds (Success)** -> Processed -> (Ideally `COMPLETED` or Deleted)
4.  **Timeout** -> `EXPIRED`

## Indexes
- `IDX_VP_REQ_TRANSACTION_ID`: Fast lookup during the OIDC flow.
- `IDX_VP_REQ_STATUS`: Efficient polling for active/expired requests.
- `IDX_VP_REQ_EXPIRES`: efficient cleanup of stale records.
