# OID4VP Verification Module

**Package:** `org.wso2.carbon.identity.openid4vc.oid4vp.verification`

## Purpose

Verifies Verifiable Credentials and Presentations, including signature validation, expiry checks, revocation status, and claim constraint matching.

**Dependencies:** `oid4vp.common`, `oid4vp.did`

## Supported Credential Formats

| Format | Content Type | Description |
|--------|-------------|-------------|
| JWT VC | `application/vc+jwt` | JWT-encoded Verifiable Credential |
| JSON-LD VC | `application/vc+ld+json` | Linked Data Proof credential |
| SD-JWT VC | `vc+sd-jwt` | Selective Disclosure JWT |

## Package Structure

| Package | Description |
|---------|-------------|
| `service` | Verification service interfaces |
| `service.impl` | Service implementations |
| `jwt` | Extended JWKS validator |
| `util` | Signature verification, submission validation |

## Key Classes

### VCVerificationService
Main verification service with these operations:

| Method | Description |
|--------|-------------|
| `verify(vcToken, contentType)` | Verify any VC format |
| `verifyVPToken(vpToken)` | Verify a Verifiable Presentation |
| `verifySdJwtToken(vpToken, nonce, audience, pdJson)` | Full SD-JWT verification |
| `verifyJWTVCIssuer(vcJwt, tenantDomain)` | Verify JWT VC issuer |
| `verifySignature(credential)` | Signature verification via JWKS |
| `verifyClaimsAgainstDefinition(claims, pdJson)` | Validate claims meet presentation definition constraints |

### SD-JWT Verification Steps
1. **Parse** – Split SD-JWT into issuer JWT + disclosures + key binding JWT
2. **Verify Issuer Signature** – Resolve issuer JWKS and verify
3. **Check Time Claims** – Validate `exp` and `nbf`
4. **Verify Disclosures** – Match disclosure hashes against `_sd` digests
5. **Verify Key Binding** – Validate nonce, audience, `sd_hash`, and holder signature
6. **Check Claims** – Validate against presentation definition constraints

### VPSubmissionValidator
Validates incoming wallet submissions:
- Content type validation
- Required parameter checks (`vp_token`, `state`)
- VP token format detection
- Presentation submission parsing

### ExtendedJWKSValidator
Extended JWKS validator that supports `vc+sd-jwt` JOSE header type.

## Verification API

**Endpoint:** `POST /openid4vp/v1/vc-verification`

```json
{
  "vcToken": "<JWT or JSON-LD VC>",
  "contentType": "application/vc+jwt"
}
```

**Response:**
```json
{
  "success": true,
  "status": "VALID",
  "format": "jwt",
  "issuer": "did:web:example.com"
}
```
