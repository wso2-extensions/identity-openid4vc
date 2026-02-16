# WSO2 Identity Server - OpenID4VP Presentation Module

## Overview

This module implements the OpenID for Verifiable Presentations (OpenID4VP) specification for WSO2 Identity Server. It enables the Identity Server to act as a verifier, requesting and verifying Verifiable Credentials from wallet applications such as Inji Wallet.

## Features

### Core Capabilities

- **VP Request Management**: Create, track, and manage Verifiable Presentation requests
- **Request-by-Value**: Full authorization request embedded in QR code
- **Request-by-Reference**: Authorization request fetched via `request_uri`
- **VP Submission**: Receive VP tokens via `direct_post` response mode
- **Credential Verification**: Cryptographic verification of VCs

### Supported Formats

| Format | Content-Type | Status |
|--------|--------------|--------|
| JSON-LD VC | `application/vc+ld+json` | ✅ Supported |
| JWT VC | `application/vc+jwt` | ✅ Supported |
| SD-JWT VC | `application/vc+sd-jwt` | ✅ Supported |

### Supported DID Methods

| Method | Example | Status |
|--------|---------|--------|
| did:web | `did:web:example.com` | ✅ Supported |
| did:jwk | `did:jwk:eyJrdHkiOiJFQyJ9` | ✅ Supported |
| did:key | `did:key:z6Mk...` | ✅ Supported |

### Verification Features

- ✅ Cryptographic signature verification
- ✅ Expiration checking
- ✅ StatusList2021 revocation checking
- ✅ BitstringStatusList support
- ✅ Trusted verifier management

## API Endpoints

### VP Request Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/identity/vp/v1/vp-request` | POST | Create authorization request |
| `/api/identity/vp/v1/vp-request/{requestId}` | GET | Get request JWT (for request_uri) |
| `/api/identity/vp/v1/vp-request/{requestId}/status` | GET | Get request status (long polling) |

### VP Submission Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/identity/vp/v1/vp-submission/direct-post` | POST | Submit VP token |

### Verification Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/identity/vp/v1/vp-result/{transactionId}` | GET | Get verification results |
| `/api/identity/vp/v1/vc-verification` | POST | Standalone VC verification |
| `/api/identity/vp/v1/vp-definition/{id}` | GET | Get presentation definition |

## Configuration

Add the following to `deployment.toml`:

```toml
[openid4vp]
enabled = true
request_expiry_seconds = 300
polling_timeout_seconds = 60
base_url = "https://localhost:9443"

[openid4vp.verification]
enable_signature_verification = true
enable_expiration_check = true
enable_revocation_check = true
supported_formats = ["ldp_vc", "jwt_vc", "jwt_vc_json", "dc+sd-jwt"]

[openid4vp.did]
enable_did_resolution = true
supported_methods = ["web", "jwk", "key"]
cache_ttl_seconds = 3600
```

## Usage Example

### 1. Create Authorization Request

```bash
curl -X POST https://localhost:9443/api/identity/vp/v1/vp-request \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "did:web:verifier.example.com",
    "nonce": "random_nonce_123",
    "presentationDefinitionId": "identity_verification"
  }'
```

**Response:**
```json
{
  "transactionId": "txn_abc123",
  "requestId": "req_def456",
  "requestUri": "https://localhost:9443/api/identity/vp/v1/vp-request/req_def456",
  "expiresAt": 1752838929
}
```

### 2. Generate QR Code

Use the response to generate a QR code:

```
openid4vp://?client_id=did:web:verifier.example.com&request_uri=https://localhost:9443/api/identity/vp/v1/vp-request/req_def456
```

### 3. Poll for Status

```bash
curl https://localhost:9443/api/identity/vp/v1/vp-request/req_def456/status
```

**Response:**
```json
{
  "status": "ACTIVE"
}
```

### 4. Get Verification Results

After VP submission:

```bash
curl https://localhost:9443/api/identity/vp/v1/vp-result/txn_abc123
```

**Response:**
```json
{
  "transactionId": "txn_abc123",
  "vcVerificationResults": [
    {
      "vcIndex": 0,
      "verificationStatus": "SUCCESS",
      "credentialType": "IdentityCredential",
      "issuer": "did:web:issuer.example.com"
    }
  ]
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer                            │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────────┐ │
│  │ VPRequest   │  │ VPSubmission │  │ VCVerification/VPResult/   │ │
│  │ Servlet     │  │ Servlet      │  │ VPDefinition Servlets      │ │
│  └──────┬──────┘  └──────┬───────┘  └─────────────┬──────────────┘ │
└─────────┼────────────────┼────────────────────────┼─────────────────┘
          │                │                        │
┌─────────┼────────────────┼────────────────────────┼─────────────────┐
│         │           Service Layer                 │                  │
│  ┌──────┴──────┐  ┌──────┴───────┐  ┌────────────┴──────────────┐  │
│  │ VPRequest   │  │ VPSubmission │  │ VCVerification / VPResult │  │
│  │ Service     │  │ Service      │  │ / StatusList / DIDResolver│  │
│  └─────────────┘  └──────────────┘  └───────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Package Structure

```
org.wso2.carbon.identity.openid4vc.presentation/
├── authenticator/        # Wallet authenticator for login
├── cache/                # In-memory caching
├── constant/             # Constants and configuration
├── dto/                  # Data transfer objects
├── exception/            # Custom exceptions
├── internal/             # OSGi components
├── model/                # Domain models
├── service/              # Service interfaces
│   └── impl/             # Service implementations
├── servlet/              # HTTP servlets
└── util/                 # Utilities (JWT, security, etc.)
```

## Security Considerations

1. **HTTPS Only**: All endpoints require HTTPS in production
2. **Nonce Validation**: Each request includes a unique nonce
3. **State Binding**: State parameter prevents CSRF attacks
4. **Signature Verification**: All credentials are cryptographically verified
5. **DID Validation**: Only supported DID methods are accepted
6. **Revocation Checking**: Credentials are checked against status lists
7. **Request Expiry**: Authorization requests expire after configurable timeout

## Testing

Run unit tests:

```bash
mvn test -Dcheckstyle.skip=true -Dspotbugs.skip=true
```

Run integration tests:

```bash
mvn verify -Dcheckstyle.skip=true -Dspotbugs.skip=true
```

## Compatibility

- **Inji Wallet**: Fully compatible with cross-device flow
- **OpenID4VP Draft 21**: Compliant with specification
- **Presentation Exchange 2.0**: Supported for credential selection

## Building

```bash
mvn clean install -Dcheckstyle.skip=true -Dspotbugs.skip=true
```

## References

- [OpenID for Verifiable Presentations (OpenID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [Presentation Exchange 2.0](https://identity.foundation/presentation-exchange/)
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [DID Core Specification](https://www.w3.org/TR/did-core/)
- [StatusList2021](https://w3c-ccg.github.io/vc-status-list-2021/)

## License

Apache License 2.0
