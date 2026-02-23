# 01 — Signature Verification

This document covers `SignatureVerifier.java` (576 lines) and `ExtendedJWKSValidator.java` (~95 lines) — the cryptographic signature verification layer.

---

## SignatureVerifier

### Purpose

Low-level utility that verifies cryptographic signatures on Verifiable Credentials. Supports:
- **JWT signatures** (RSA, EC, EdDSA via fallback)
- **Linked Data signatures** (Ed25519Signature2020, JsonWebSignature2020, EcdsaSecp256k1)
- **Generic fallback** for unknown proof types

### Constructor

```java
public SignatureVerifier(DIDResolverService didResolverService)
```

Takes a `DIDResolverService` but **does not currently use it** — the comment says "kept for API stability". Public key resolution is done at the `VCVerificationServiceImpl` level before calling `SignatureVerifier`.

---

### JWT Signature Verification

```java
public boolean verifyJwtSignature(String jwt, PublicKey publicKey, String algorithm)
```

**Flow by key type:**

| Key Type | Library | Verifier Class |
|---|---|---|
| `RSAPublicKey` | Nimbus JOSE | `RSASSAVerifier` |
| `ECPublicKey` | Nimbus JOSE | `ECDSAVerifier` |
| Other (EdDSA) | JCA `Signature` | `verifyJwtSignatureWithJca()` |

#### Nimbus JOSE Path (RSA/EC)
1. Parse JWT with `SignedJWT.parse(jwt)`
2. Create appropriate verifier (`RSASSAVerifier` or `ECDSAVerifier`)
3. Call `signedJWT.verify(verifier)`

#### JCA Fallback Path (EdDSA)
Used when the public key is neither RSA nor EC (e.g., EdDSA `EdECPublicKey`):

1. Extract signing input: `header + "." + payload`
2. Decode signature from Base64URL
3. Map JWT algorithm to JCA: `getJcaAlgorithm(algorithm)`
4. For ECDSA algorithms (`ES*`): convert JWT compact format (R||S) to DER format
5. Verify with `java.security.Signature`

#### Algorithm Mapping (`getJcaAlgorithm`)

| JWT Algorithm | JCA Algorithm |
|---|---|
| `RS256` | `SHA256withRSA` |
| `RS384` | `SHA384withRSA` |
| `RS512` | `SHA512withRSA` |
| `ES256` | `SHA256withECDSA` |
| `ES384` | `SHA384withECDSA` |
| `ES512` | `SHA512withECDSA` |
| `ES256K` | `SHA256withECDSA` |
| `EdDSA` | `EdDSA` |
| `PS256` | `SHA256withRSAandMGF1` |
| `PS384` | `SHA384withRSAandMGF1` |
| `PS512` | `SHA512withRSAandMGF1` |

---

### ECDSA Signature Format Conversion

JWT ECDSA signatures use **concatenated R||S format** (fixed size), while JCA expects **DER format**. The conversion handles:

1. **Split** the compact signature into R and S components
2. **Trim leading zeros** from each component
3. **Add padding byte** if high bit is set (avoids negative number interpretation in ASN.1)
4. **Build DER structure**: `SEQUENCE { INTEGER(R), INTEGER(S) }`

Component sizes by algorithm:
| Algorithm | Component Length |
|---|---|
| `ES256`, `ES256K` | 32 bytes |
| `ES384` | 48 bytes |
| `ES512` | 66 bytes |

---

### Linked Data Signature Verification

```java
public boolean verifyLinkedDataSignature(String document, PublicKey publicKey,
                                          String proofType, String proofValue)
```

Routes to format-specific verifiers based on `proofType`:

| Proof Type (contains) | Method | Approach |
|---|---|---|
| `Ed25519Signature` | `verifyEd25519Signature()` | Multibase decode → SHA-256 hash → `EdDSA` JCA |
| `JsonWebSignature` | `verifyJsonWebSignature()` | Detached JWS → reconstruct → JWT verify |
| `EcdsaSecp256k1` | `verifyEcdsaSecp256k1Signature()` | Base58/Base64 decode → `SHA256withECDSA` |
| Other | `verifyGenericSignature()` | Guess algorithm from key type |

#### Ed25519 Signature Verification
1. Decode proof value (multibase `z` prefix → Base58btc, or Base64)
2. Hash document with SHA-256
3. Verify with `Signature.getInstance("EdDSA")`

#### JSON Web Signature (Detached JWS)
1. Parse JWS format: `header..signature` (empty payload)
2. Extract algorithm from header
3. Hash document with SHA-256, Base64URL encode
4. Reconstruct full JWS with payload
5. Delegate to `verifyJwtSignature()`

#### Signature Value Decoding
All LD proof values support multiple encodings:
- Multibase `z` prefix → Base58btc decode (custom implementation)
- Otherwise → Base64 decode (standard or URL-safe)

### Base58 Decoder
Custom implementation of Bitcoin Base58 decoding using `BigInteger` arithmetic. Handles leading zeros (mapped from `'1'` characters).

---

## ExtendedJWKSValidator

### Purpose

Validates JWT signatures against a remote **JWKS endpoint**. Replaces WSO2 IS's built-in `JWKSBasedJWTValidator` which only supports RSA. This custom validator supports **any algorithm** including EdDSA and ES256.

### How It Works

```java
public boolean validateSignature(String jwtString, String jwksUri, String algorithm)
```

**Flow:**
1. Create `DefaultJWTProcessor<SecurityContext>`
2. Configure JOSE type verifier to allow:
   - Standard `JWT` type
   - `vc+sd-jwt` type (for SD-JWT credentials)
   - `null` type (missing `typ` header)
3. Create `RemoteJWKSet` key source from JWKS URI (handles HTTP fetching + caching internally)
4. Create `JWSVerificationKeySelector` for the expected algorithm
5. Call `jwtProcessor.process(jwtString, null)` — verifies signature + basic claims (exp)

### Library: Nimbus JOSE+JWT

**Key classes used:**
| Class | Purpose |
|---|---|
| `DefaultJWTProcessor` | Configurable JWT processing pipeline |
| `RemoteJWKSet` | Fetches and caches JWKS from HTTP endpoint |
| `JWSVerificationKeySelector` | Selects the matching key from JWKS by algorithm + kid |
| `DefaultJOSEObjectTypeVerifier` | Validates the JWT `typ` header |

`RemoteJWKSet` has built-in HTTP caching with automatic refresh, avoiding repeated network calls for the same JWKS endpoint.

---

## When Each Path Is Used

| Issuer Type | Signature Verifier | Key Source |
|---|---|---|
| `did:web:*`, `did:key:*`, etc. | `SignatureVerifier.verifyJwtSignature()` | `DIDResolverService.getPublicKey()` |
| `https://issuer.example.com` | `ExtendedJWKSValidator.validateSignature()` | `RemoteJWKSet` via JWKS URI |
| Non-DID, non-URL | Skipped (returns `true`) | N/A |

---

## Code Review Notes

| Issue | Severity | Details |
|---|---|---|
| **`SignatureVerifier` constructor takes unused `DIDResolverService`** | Low | Dead parameter. Remove or use it for key resolution within the verifier. |
| **Custom Base58 decoder** | Medium | Hand-rolled crypto primitive. Should use a proven library (e.g., `org.bitcoinj.core.Base58` or BouncyCastle). |
| **`extractAlgorithmFromHeader` uses string manipulation** | Medium | Manual string parsing instead of JSON parsing: `headerJson.indexOf("\"alg\"")`. Fragile — breaks with whitespace variations. Should use Gson/JsonParser. |
| **Generic fallback defaults to `SHA256withRSA`** | Medium | `verifyGenericSignature()` defaults to RSA if key type is unknown. Could silently pass/fail with wrong algorithm. |
| **`verifyEd25519Signature` hashes before verify** | High | Ed25519 expects the **raw message**, not a hash. The spec says Ed25519 internally does SHA-512. Hashing first with SHA-256 may produce incorrect results depending on the proof suite version. |
| **`removeCRLF` duplicated** | Low | Both `SignatureVerifier` and `VCVerificationServiceImpl` have identical `removeCRLF()` methods. Should use `LogSanitizer` from the common module. |
| **Broad `catch (Exception e)`** | Medium | Multiple methods catch all exceptions. Could mask unexpected errors (NPE, ClassCast, etc.). |
| **No retry on JWKS fetch failure** | Low | `ExtendedJWKSValidator` relies on Nimbus internal caching but has no explicit retry logic for transient network failures. |
| **`@SuppressFBWarnings("CRLF_INJECTION_LOGS")`** | Info | Applied to multiple methods. The manual CRLF removal handles the concern, but the suppression is still needed for SpotBugs. |
