# Service Layer

**Package:** `org.wso2.carbon.identity.openid4vc.oid4vp.did.service`

The service layer provides two high-level services:

| Service | Direction | Purpose |
|---|---|---|
| `DIDDocumentService` | **Outward** — "What is *my* DID?" | Generates and manages the IS's own DID Document |
| `DIDResolverService` | **Inward** — "What is *their* DID?" | Resolves external DIDs to extract verification keys |

---

## 1. DIDDocumentService.java — Interface

**Path:** `service/DIDDocumentService.java`

Manages the Identity Server's own DID identity.

### Method Summary

| Method | Returns | Purpose |
|---|---|---|
| `getDIDDocument(domain, tenantId)` | `String` (JSON) | Get DID Document as a JSON string (for HTTP endpoints) |
| `getDIDDocumentObject(domain, tenantId)` | `DIDDocument` | Get DID Document as a model object |
| `getDID(domain)` | `String` | Get the DID identifier (e.g., `did:web:example.com`) |
| `regenerateKeys(domain, tenantId)` | `String` | Force-regenerate keys and return new DID |
| `hasKeys(tenantId)` | `boolean` | Check if keys exist for the tenant |

### Typical Caller

The `/.well-known/did.json` servlet endpoint calls `getDIDDocument(domain, tenantId)` to serve the DID Document over HTTPS.

---

## 2. DIDDocumentServiceImpl.java — Implementation

**Path:** `service/impl/DIDDocumentServiceImpl.java`

### Core Logic

#### `getDIDDocumentObject(domain, tenantId)`

```
1. Get DIDProvider for "web" via DIDProviderFactory
2. Call provider.getDIDDocument(tenantId, domain)
3. Return DIDDocument model
```

This always uses `did:web` because the `.well-known/did.json` endpoint implies the `did:web` method. The domain in the DID comes from the IS's base URL.

#### `getDIDDocument(domain, tenantId)` — JSON serialisation

Calls `getDIDDocumentObject()` then serialises via `convertToJson()`.

The `convertToJson()` method does **custom serialisation** instead of using `Gson.toJson(didDocument)` directly. This is because the DID Core spec requires specific field names (`@context`, `publicKeyJwk`, `publicKeyMultibase`, etc.) and the `DIDDocument` model uses Java-style getters. The method:

1. Builds a `Map<String, Object>` from the `DIDDocument` fields
2. Handles the verification methods by choosing the right key representation (`publicKeyJwk` vs `publicKeyMultibase` vs `publicKeyBase58`)
3. Includes optional fields (`controller`, `alsoKnownAs`, `service`, etc.) only when present
4. Uses `Gson.toJson(map)` with pretty-printing

#### `getDID(domain)` — Static DID lookup

Two overloads:
- `getDID(String domain)` — uses `DIDProviderFactory.getProvider("web")` with a dummy tenant ID (-1234)
- `getDID(int tenantId)` — reads the IS base URL from `OpenID4VPUtil.getBaseUrl()`

#### `regenerateKeys(domain, tenantId)`

1. Calls `DIDKeyManager.regenerateKeyPair(tenantId)` — clears Ed25519 key cache and re-fetches from KeyStore
2. Returns the `did:key` representation of the new keys (not `did:web`)

> **Note:** This only regenerates Ed25519 keys. RSA keys come from the default KeyStore certificate and are not regenerated here.

#### `hasKeys(tenantId)`

Delegates to `DIDKeyManager.hasKeys(tenantId)` — checks if keys are in the in-memory cache only.

---

## 3. DIDResolverService.java — Interface

**Path:** `service/DIDResolverService.java`

Resolves any DID (from a wallet/holder) to its DID Document, and extracts public keys for signature verification.

### Method Summary

| Method | Returns | Purpose |
|---|---|---|
| `resolve(did)` | `DIDDocument` | Resolve DID to document (with caching) |
| `resolve(did, useCache)` | `DIDDocument` | Control cache usage |
| `getPublicKey(did, keyId)` | `PublicKey` | Extract a specific public key |
| `getPublicKeyFromReference(ref)` | `PublicKey` | Extract key by full `did:...#key-1` reference |
| `isSupported(did)` | `boolean` | Check if DID method is supported |
| `getMethod(did)` | `String` | Extract method name from DID |
| `getSupportedMethods()` | `String[]` | `["web", "jwk", "key"]` |
| `clearCache(did)` | `void` | Remove one cached document |
| `clearAllCache()` | `void` | Clear entire cache |
| `isValidDID(did)` | `boolean` | Basic format validation |
| `getIdentifier(did)` | `String` | Extract method-specific identifier |

---

## 4. DIDResolverServiceImpl.java — Implementation

**Path:** `service/impl/DIDResolverServiceImpl.java`

This is the largest file in the module (~600 lines). It handles:

### 4.1 Caching

Uses a `ConcurrentHashMap<String, CacheEntry>`:

```java
private static class CacheEntry {
    final DIDDocument document;
    final long expiresAt;  // System.currentTimeMillis() + 1 hour
}
```

- **TTL:** 1 hour (`DEFAULT_CACHE_TTL_MS = 3600000`)
- **Eviction:** Lazy — expired entries are only removed when accessed
- Cache is **per-instance**, not shared across the JVM

### 4.2 Resolution by Method

`resolve(did, useCache)` dispatches to the appropriate private method:

```
did:web:...  → resolveDidWeb(did)
did:jwk:...  → resolveDidJwk(did)
did:key:...  → resolveDidKey(did)
```

#### `resolveDidWeb(did)` — HTTP-based resolution

```
1. Extract identifier after "did:web:"
2. Replace ":" with "/" for path segments
3. URL-decode "%3A" back to ":" for ports
4. If path contains "/": URL = https://domain/path/did.json
   Else: URL = https://domain/.well-known/did.json
5. HTTP GET the URL (10s connect timeout, 10s read timeout)
6. Parse JSON into DIDDocument
```

The HTTP fetch uses `HttpURLConnection` with:
- `Accept: application/json` header
- Only HTTP 200 is accepted
- TLS verification is default (no custom TrustManager)

#### `resolveDidJwk(did)` — Self-contained resolution

```
1. Extract identifier (everything after "did:jwk:")
2. Base64URL decode → JWK JSON
3. Create DIDDocument with one JsonWebKey2020 verification method
4. Key ID = did + "#0"
```

No network call needed — the key is in the DID itself.

#### `resolveDidKey(did)` — Self-contained resolution

```
1. Extract identifier (after "did:key:")
2. Verify 'z' prefix (base58btc)
3. Base58 decode
4. Read 2-byte multicodec prefix:
   - 0xed01 → Ed25519VerificationKey2020
   - 0x1200 → EcdsaSecp256k1VerificationKey2019
   - 0x1201 → JsonWebKey2020 (P-256)
5. Create DIDDocument with appropriate verification method
6. Key ID = did + "#" + multibase_identifier
```

### 4.3 Public Key Extraction

`getPublicKey(did, keyId)` resolves the DID, then `extractPublicKey(method)` converts the verification method into a `java.security.PublicKey`:

| Key Format | Conversion Path |
|---|---|
| `publicKeyJwk` (RSA) | Base64URL decode `n`, `e` → `RSAPublicKeySpec` → `KeyFactory.getInstance("RSA")` |
| `publicKeyJwk` (EC) | Base64URL decode `x`, `y` → `ECPublicKeySpec` with curve params → `KeyFactory.getInstance("EC")` |
| `publicKeyJwk` (OKP/Ed25519) | Nimbus `OctetKeyPair.Builder(Ed25519, x).build().toPublicKey()` |
| `publicKeyMultibase` | Strip `z` prefix → base58 decode → skip 2-byte multicodec → `OctetKeyPair` for Ed25519 |
| `publicKeyBase58` | Base58 decode → raw bytes → `OctetKeyPair` for Ed25519 |

### 4.4 DID Document Parsing

`parseDIDDocument(did, json)` handles the full W3C DID Core JSON structure:

- `@context` — array or single string
- `id`, `controller` — string fields
- `verificationMethod` — array of objects with `id`, `type`, `controller`, various key formats
- `authentication`, `assertionMethod`, `keyAgreement` — arrays of strings or embedded objects
- `service` — array of service endpoint objects

### 4.5 Base58 and Encoding Utilities

The class includes its own `base58Decode()` using the Bitcoin alphabet — duplicated from `DIDKeyManager`.

### 4.6 Static Utility

```java
public static OctetKeyPair generateEd25519KeyPair()
```

Uses Bouncy Castle to generate a new Ed25519 key pair. This is a utility method that appears to be a leftover — it's `public static` and doesn't fit the resolver's responsibility.

### 4.7 Supported EC Curves

| Curve Name | Standard Name |
|---|---|
| `P-256` | `secp256r1` |
| `P-384` | `secp384r1` |
| `P-521` | `secp521r1` |
| `secp256k1` | `secp256k1` |

---

## Service Layer — Interaction with WSO2 IS Storage

```
┌──────────────────────────────┐
│        Callers               │
│  (Servlets, Authenticator)   │
└──────────┬───────────────────┘
           │
    ┌──────▼──────────┐    ┌──────────────────┐
    │ DIDDocumentService│    │ DIDResolverService│
    │ (generate MY doc) │    │ (resolve THEIR DID)│
    └──────┬──────────┘    └──────┬───────────┘
           │                       │
    ┌──────▼──────────┐    ┌──────▼───────────┐
    │ DIDProviderFactory│    │ ConcurrentHashMap │
    │   → DIDWebProvider│    │ (1hr TTL cache)   │
    └──────┬──────────┘    └──────┬───────────┘
           │                       │
    ┌──────▼──────────┐    ┌──────▼───────────┐
    │ DIDKeyManager   │    │ HttpURLConnection │
    │ (key cache)     │    │ (did:web fetch)   │
    └──────┬──────────┘    └──────┬───────────┘
           │                       │
    ┌──────▼──────────┐           │
    │ KeyStoreManager │           │
    │ (Carbon JKS)    │           │
    └─────────────────┘           │
                                  ▼
                           External DID
                           Document Host
```
