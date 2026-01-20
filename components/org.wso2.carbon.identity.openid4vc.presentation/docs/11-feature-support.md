# OpenID4VP Feature Support

## Comprehensive OID4VP Specification Compliance

This document details all OpenID4VP features supported by this implementation.

---

## Protocol Features

### Response Types

| Feature | Status | Notes |
|---------|--------|-------|
| `vp_token` | ✅ Supported | Primary response type |
| `vp_token id_token` | ⚠️ Partial | ID token extracted but not validated |

### Response Modes

| Mode | Status | Description |
|------|--------|-------------|
| `direct_post` | ✅ Supported | Wallet POSTs to response_uri |
| `direct_post.jwt` | ✅ Supported | Signed JWT response |
| `fragment` | ❌ Not supported | Browser-based flow |
| `query` | ❌ Not supported | Browser-based flow |

### Client ID Schemes

| Scheme | Status | Description |
|--------|--------|-------------|
| `did` | ✅ Supported | DID as client_id |
| `redirect_uri` | ❌ Not supported | OAuth2 style |
| `x509_san_dns` | ❌ Not supported | X.509 certificate |
| `x509_san_uri` | ❌ Not supported | X.509 certificate |
| `verifier_attestation` | ❌ Not supported | Pre-registered verifier |

---

## Credential Format Support

### Verifiable Credential Formats

| Format | Status | Algorithms |
|--------|--------|------------|
| `jwt_vc_json` | ✅ Full | EdDSA, ES256, ES384, RS256 |
| `jwt_vc` | ✅ Full | EdDSA, ES256, ES384, RS256 |
| `jwt_vp` | ✅ Full | EdDSA, ES256, ES384, RS256 |
| `ldp_vc` | ⚠️ Limited | Ed25519Signature2020 |
| `ldp_vp` | ⚠️ Limited | Ed25519Signature2020 |
| `vc+sd-jwt` | ✅ Supported | EdDSA, ES256 |
| `mso_mdoc` | ❌ Not supported | Mobile documents |

### Algorithm Support

| Algorithm | Key Type | Status |
|-----------|----------|--------|
| `EdDSA` | Ed25519 | ✅ Full (Bouncy Castle) |
| `ES256` | P-256 ECDSA | ✅ Full |
| `ES384` | P-384 ECDSA | ✅ Full |
| `ES512` | P-521 ECDSA | ⚠️ Untested |
| `RS256` | RSA PKCS#1 | ✅ Full |
| `RS384` | RSA PKCS#1 | ⚠️ Untested |
| `RS512` | RSA PKCS#1 | ⚠️ Untested |
| `PS256` | RSA PSS | ❌ Not supported |

---

## DID Method Support

| Method | Status | Resolution |
|--------|--------|------------|
| `did:web` | ✅ Full | HTTPS request to `.well-known/did.json` |
| `did:key` | ✅ Full | Multibase key decoding |
| `did:jwk` | ✅ Full | JWK embedded in DID |
| `did:ion` | ⚠️ Via resolver | Universal Resolver |
| `did:ethr` | ⚠️ Via resolver | Universal Resolver |
| `did:sov` | ⚠️ Via resolver | Universal Resolver |

### DID Document Verification Methods

| Type | Status |
|------|--------|
| `Ed25519VerificationKey2020` | ✅ Supported |
| `Ed25519VerificationKey2018` | ✅ Supported |
| `JsonWebKey2020` | ✅ Supported |
| `EcdsaSecp256k1VerificationKey2019` | ⚠️ Partial |
| `RsaVerificationKey2018` | ✅ Supported |

---

## Presentation Definition Support (DIF PE 2.0)

### Core Features

| Feature | Status |
|---------|--------|
| `id` | ✅ Required |
| `name` | ✅ Optional |
| `purpose` | ✅ Optional |
| `input_descriptors` | ✅ Required |
| `format` | ✅ Optional |
| `submission_requirements` | ⚠️ Basic support |

### Input Descriptor Features

| Feature | Status |
|---------|--------|
| `id` | ✅ Required |
| `name` | ✅ Optional |
| `purpose` | ✅ Optional |
| `format` | ✅ Optional |
| `constraints` | ✅ Supported |
| `group` | ⚠️ Partial |

### Constraint Features

| Feature | Status | Description |
|---------|--------|-------------|
| `fields` | ✅ Supported | Field-level constraints |
| `limit_disclosure` | ⚠️ Partial | SD-JWT selective disclosure |
| `subject_is_holder` | ❌ Not implemented | - |
| `subject_is_issuer` | ❌ Not implemented | - |

### Field Constraint Features

| Feature | Status |
|---------|--------|
| `path` | ✅ JSONPath supported |
| `filter` | ✅ JSON Schema filter |
| `optional` | ✅ Supported |
| `predicate` | ❌ Not supported |
| `intent_to_retain` | ⚠️ Parsed but not enforced |

### JSON Schema Filters

| Filter | Status |
|--------|--------|
| `type` | ✅ Supported |
| `const` | ✅ Supported |
| `enum` | ✅ Supported |
| `pattern` | ✅ Regex supported |
| `minimum/maximum` | ⚠️ Partial |
| `contains` | ✅ Supported |
| `format` | ⚠️ Limited |

---

## Revocation Support

### Status List Mechanisms

| Mechanism | Status | Description |
|-----------|--------|-------------|
| StatusList2021 | ✅ Supported | W3C VC Status List |
| BitstringStatusList | ✅ Supported | Latest W3C spec |
| RevocationList2020 | ⚠️ Legacy | Basic support |
| CredentialStatusList2017 | ❌ Not supported | Deprecated |

### Revocation Check Features

| Feature | Status |
|---------|--------|
| Fetch status list | ✅ Supported |
| Cache status lists | ✅ Configurable TTL |
| Multi-purpose lists | ✅ revocation, suspension |
| Signed status lists | ✅ Signature verified |

---

## Security Features

### Request Security

| Feature | Status |
|---------|--------|
| Nonce validation | ✅ Always required |
| State correlation | ✅ Always required |
| Request expiry | ✅ Configurable (default 5 min) |
| Signed requests | ✅ JAR (JWT Secured) |
| HTTPS | ✅ Required in production |

### Response Security

| Feature | Status |
|---------|--------|
| VP signature verification | ✅ Required |
| VC signature verification | ✅ Required |
| Audience validation | ✅ client_id must match |
| Replay protection | ✅ Via nonce |

---

## Configuration Options

```toml
[OpenID4VP]
# Request expiry
VPRequestExpirySeconds = 300

# Revocation
EnableRevocationCheck = true
StatusListCacheTTLSeconds = 3600

# Default definition
DefaultPresentationDefinitionId = ""

# DID configuration
[OpenID4VP.DID]
Method = "web"
UniversalResolverUrl = "https://dev.uniresolver.io/1.0/identifiers/"

# Base URL for verifier DID
BaseUrl = "https://is.example.com"
```

---

## Compliance Summary

| Specification | Status |
|---------------|--------|
| OpenID4VP Draft 20 | ✅ Core features |
| DIF Presentation Exchange 2.0 | ⚠️ Most features |
| W3C VC Data Model 1.1 | ✅ Full |
| W3C VC Data Model 2.0 | ⚠️ Partial |
| W3C DID Core 1.0 | ✅ Full |
| SD-JWT VC Draft | ⚠️ Partial |
