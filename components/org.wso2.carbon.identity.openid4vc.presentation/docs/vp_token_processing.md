# VP Token Processing and Authentication Flow

This document explains how Verifiable Presentation (VP) tokens are processed by the backend and how the authentication flow works in the OpenID4VP implementation.

## 1. Authentication Initiation

The authentication process begins in `OpenID4VPAuthenticator`:

1.  **Initiate Request**: When a user selects "Wallet" login, `initiateAuthenticationRequest` is called.
2.  **VP Request Creation**: A `VPRequest` is created with a unique `state` (nonce) and stored in the database.
3.  **Redirect/QR**: The user is redirected to a login page with a signed Request URI (or QR code content) incorporating the request details.
4.  **Session Association**: The Request ID is stored in the user's authentication session for correlation.

## 2. VP Submission (Wallet to Backend)

The user scans the QR code and submits credentials via their Wallet app. The Wallet sends a POST request to the **Direct Post Endpoint**: `/openid4vp/v1/response`.

### Handling in `VPSubmissionServlet`

1.  **Receive**: The `doPost` method receives the submission containing the `vp_token` and `presentation_submission`.
2.  **Parse**: `parseSubmission` extracts the token (JWT or JSON-LD) and metadata.
3.  **Validate**: `VPSubmissionValidator` checks the submission structure.
4.  **Verify Issuers**: `verifyAllCredentialIssuers` extracts all VCs within the VP and verifies that their issuers are trusted (against a trusted issuer allowlist).
5.  **Process & Store**:
    *   The submission is passed to `VPSubmissionServiceImpl`.
    *   The service validates the VP signature (if applicable) and checks that it matches the original request (nonce, client_id validation).
    *   The submission is persisted in the database or cache, linked to the Request ID.
6.  **Notify**: The servlet notifies the frontend (via Long Polling or Status listeners) that the submission has been received.

## 3. Backend Processing & Authentication Completion

Once the submission is received, the `OpenID4VPAuthenticator` resumes control to finalize authentication.

### Flow in `OpenID4VPAuthenticator`

1.  **Resume**: The browser polls the backend, detects the "SUBMITTED" status, and triggers `processAuthenticationResponse`.
2.  **Retrieve Submission**: The authenticator retrieves the stored `VPSubmission` using the Request ID from the session.
3.  **VP Token Parsing**:
    *   The `vp_token` is parsed based on its format (JSON-LD, JWT, or SD-JWT).
    *   The authenticator handles decoding of Base64 encoded payloads and nested structures.
4.  **Credential Extraction**:
    *   It accesses the `verifiableCredential` array within the VP.
    *   It iterates through credentials to find user identity information (Subject).
5.  **User Identification**:
    *   It looks for identity claims in the Credential Subject (e.g., `email`, `username`, `id`, `sub`).
    *   If a valid identifier is found, it is used as the authenticated username.
6.  **Claim Mapping**:
    *   Other claims in the VP are extracted and mapped to WSO2 Identity Server user attributes.
7.  **Finalize**:
    *   An `AuthenticatedUser` object is created.
    *   The flow is marked as successful, logging the user in.
    *   **Cleanup**: VP data is deleted from the database/cache to adhere to data minimization principles.

## 4. Key Components

*   **`OpenID4VPAuthenticator`**: Orchestrates the flow, initiates requests, and finalizes user authentication.
*   **`VPSubmissionServlet`**: The API endpoint that receives the VP from the wallet.
*   **`VPResponseHandler`**: Helper class used to parse, validate, and verify the cryptographic integrity of the VP token.
*   **`VCVerificationService`**: Service responsible for verifying the issuers and signatures of the provided credentials.
