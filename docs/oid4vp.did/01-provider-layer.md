# Provider Layer

**Package:** `org.wso2.carbon.identity.openid4vc.oid4vp.did.provider`

The provider layer implements the **Strategy pattern** — each DID method (`did:web`, `did:key`, `did:jwk`) is encapsulated behind the `DIDProvider` interface and selected at runtime through `DIDProviderFactory`.

---

## 1. DIDProvider.java — Interface

**Path:** `provider/DIDProvider.java`

The contract that every DID method must implement.

### Method Summary

| Method | Returns | Purpose |
|---|---|---|
| `getName()` | `String` | DID method name — `"web"`, `"key"`, `"jwk"` |
| `getDID(tenantId, baseUrl)` | `String` | Full DID string for the tenant |
| `getDID(tenantId, baseUrl, algorithm)` | `String` | Algorithm-specific variant (default delegates to 2-arg) |
| `getSigningKeyId(tenantId, baseUrl)` | `String` | Key ID for JWT `kid` header |
| `getSigningKeyId(tenantId, baseUrl, algorithm)` | `String` | Algorithm-specific key ID |
| `getSigningAlgorithm()` | `JWSAlgorithm` | Default signing algorithm |
| `getSigningAlgorithm(algorithm)` | `JWSAlgorithm` | Parses preferred algorithm string → `JWSAlgorithm` |
| `getSigner(tenantId)` | `JWSSigner` | Creates signer with default algorithm |
| `getSigner(tenantId, algorithm)` | `JWSSigner` | Creates signer for specific algorithm |
| `getDIDDocument(tenantId, baseUrl)` | `DIDDocument` | Generates a DID Document model object |
| `getDIDDocument(tenantId, baseUrl, algorithm)` | `DIDDocument` | Algorithm-specific DID Document |

### Design Notes

- All algorithm-aware methods are `default` methods that delegate to the non-algorithm overload. Concrete providers override them when they need algorithm-specific behaviour.
- `JWSAlgorithm` comes from Nimbus JOSE — it represents algorithms like `RS256`, `ES256`, `EdDSA`.
- `DIDDocument` is the shared model from `oid4vp.common`.

---

## 2. DIDProviderFactory.java — Static Factory

**Path:** `provider/DIDProviderFactory.java`

Registers and retrieves provider instances from a static `HashMap<String, DIDProvider>`.

### Initialisation (static block)

```
static {
    register(new DIDWebProvider());
    register(new DIDKeyProvider());
    register(new DIDJwkProvider());
}
```

### `getProvider(method)`

| Argument | Behaviour |
|---|---|
| `null` or blank | Returns `DIDWebProvider` (default) |
| `"web"`, `"key"`, `"jwk"` | Returns the registered provider |
| Anything else | Throws `IllegalArgumentException` |

### Review Notes

- Providers are **singletons** stored in a `HashMap` — not thread-safe for writes, but writes only happen once in the static initialiser so this is safe.
- To add a new DID method (e.g., `did:ion`), create the implementation and add one `register()` call.

---

## 3. DIDJwkProvider.java — `did:jwk` Implementation

**Path:** `provider/impl/DIDJwkProvider.java`  
**DID Method:** `did:jwk`  
**Default Algorithm:** EdDSA (Ed25519)

### How `did:jwk` Works

The `did:jwk` method embeds the full JWK directly in the DID identifier as a Base64URL-encoded JSON string:

```
did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ii4uLiJ9
         └───────────── Base64URL(JWK JSON) ────────────────┘
```

### Key Operations

| Method | Implementation |
|---|---|
| `getDID()` | Gets Ed25519 `OctetKeyPair` from `DIDKeyManager` → extracts public JWK JSON → Base64URL encodes → prepends `did:jwk:` |
| `getSigningKeyId()` | `getDID() + "#0"` — the `#0` fragment is the standard key reference for `did:jwk` |
| `getSigner()` | Gets key from `DIDKeyManager` → wraps in `BCEd25519Signer` |
| `getDIDDocument()` | Creates `DIDDocument` with one `JsonWebKey2020` verification method containing the public JWK |

### Dependencies

- `DIDKeyManager.getOrGenerateKeyPair(tenantId)` — retrieves Ed25519 key from WSO2 KeyStore
- `BCEd25519Signer` — Bouncy Castle signer

### DID Document Structure

```json
{
  "id": "did:jwk:eyJrdH...",
  "verificationMethod": [{
    "id": "did:jwk:eyJrdH...#0",
    "type": "JsonWebKey2020",
    "controller": "did:jwk:eyJrdH...",
    "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." }
  }],
  "authentication": ["did:jwk:eyJrdH...#0"],
  "assertionMethod": ["did:jwk:eyJrdH...#0"]
}
```

---

## 4. DIDKeyProvider.java — `did:key` Implementation

**Path:** `provider/impl/DIDKeyProvider.java`  
**DID Method:** `did:key`  
**Default Algorithm:** EdDSA (Ed25519); also supports ES256 (P-256)

### How `did:key` Works

`did:key` encodes the public key directly using **multibase** (base58btc with `z` prefix) and **multicodec** prefixes:

```
did:key:z6MkhaXg...
        │└── base58btc(multicodec_prefix + raw_public_key_bytes)
        └─── 'z' = base58btc multibase prefix
```

| Algorithm | Multicodec Prefix | Key Size |
|---|---|---|
| Ed25519 | `0xed01` | 32 bytes |
| P-256 | `0x8024` (varint) | 33 bytes (compressed point) |

### Key Operations

| Method | Ed25519 (default) | ES256 |
|---|---|---|
| `getDID()` | `DIDKeyManager.generateDIDKey(tenantId)` | `DIDKeyManager.generateDIDKey(ecKey)` |
| `getSigningKeyId()` | `did:key:z6Mk...#z6Mk...` (multibase repeated as fragment) | Same pattern |
| `getSigningAlgorithm()` | `EdDSA` | `ES256` |
| `getSigner()` | `BCEd25519Signer(keyPair)` | `ECDSASigner(ecKey)` (Nimbus built-in) |
| `getDIDDocument()` | Type: `Ed25519VerificationKey2020`, uses `publicKeyMultibase` | Type: `JsonWebKey2020`, uses `publicKeyJwk` |

### Key ID Structure

The key ID for `did:key` is the DID itself plus a fragment that repeats the multibase part:

```
did:key:z6MkhaXg...#z6MkhaXg...
└── DID ──────────┘ └── fragment (= multibase identifier)
```

This is per the [W3C did:key specification](https://w3c-ccg.github.io/did-method-key/).

---

## 5. DIDWebProvider.java — `did:web` Implementation

**Path:** `provider/impl/DIDWebProvider.java`  
**DID Method:** `did:web`  
**Default Algorithm:** RS256; also supports EdDSA and ES256

This is the most complex provider because `did:web` leverages the WSO2 Carbon **KeyStore** for RSA keys and supports all three algorithm families.

### How `did:web` Works

`did:web` maps a domain name to a URL where the DID Document is hosted:

```
did:web:example.com       → https://example.com/.well-known/did.json
did:web:example.com%3A9443 → https://example.com:9443/.well-known/did.json
```

Port colons are URL-encoded as `%3A` in the DID identifier.

### DID Generation

```java
getDID(tenantId, baseUrl):
  1. Strip http(s):// prefix
  2. Strip trailing /
  3. Encode ":" as "%3A" (for ports)
  4. Return "did:web:" + encodedDomain
```

### Signing Key IDs

| Algorithm | Key ID Pattern |
|---|---|
| RS256 (default) | `did:web:domain#owner` |
| EdDSA | `did:web:domain#ed25519` |
| ES256 | `did:web:domain#p256` |

### Signer Creation

| Algorithm | Source | Signer Class |
|---|---|---|
| RS256 | `KeyStoreManager.getDefaultPrivateKey()` | `RSASSASigner` (Nimbus) |
| EdDSA | `KeyStoreManager` via `DIDKeyManager.getEdDSAKeyAlias()` → `convertToOctetKeyPair()` | `BCEd25519Signer` |
| ES256 | `DIDKeyManager.getOrGenerateECKeyPair()` (ephemeral) | `ECDSASigner` (Nimbus) |

### DID Document Generation

When `algorithm` is `null` (default), the DID Document includes **all three** verification methods:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/security/suites/ecdsa-secp256r1-2019/v1",
    "https://w3id.org/security/suites/rsa-2018/v1"
  ],
  "id": "did:web:example.com%3A9443",
  "verificationMethod": [
    {
      "id": "did:web:example.com%3A9443#owner",
      "type": "RsaVerificationKey2018",
      "controller": "did:web:example.com%3A9443",
      "publicKeyJwk": { "kty": "RSA", "n": "...", "e": "..." }
    },
    {
      "id": "did:web:example.com%3A9443#ed25519",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:example.com%3A9443",
      "publicKeyMultibase": "z6Mk..."
    },
    {
      "id": "did:web:example.com%3A9443#p256",
      "type": "EcdsaSecp256r1VerificationKey2019",
      "controller": "did:web:example.com%3A9443",
      "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
    }
  ],
  "authentication": ["...#owner", "...#ed25519", "...#p256"],
  "assertionMethod": ["...#owner", "...#ed25519", "...#p256"]
}
```

When `algorithm` is specified, only the matching verification method is included.

### Multibase Encoding (Private Helper)

`DIDWebProvider` has its own `convertPublicKeyToMultibase()` and `base58Encode()` methods for the Ed25519 verification method. These duplicate functionality in `DIDKeyManager` — see the code review guide for discussion.

### Error Handling

All three key blocks in `getDIDDocument()` silently catch and swallow exceptions:

```java
} catch (Exception e) {
    // silently swallowed
}
```

This means if one key type fails (e.g., EdDSA key not in keystore), the DID Document is still generated with the remaining key types. This is intentional — the IS may not have all key types configured.

---

## Provider Comparison Matrix

| Feature | DIDJwkProvider | DIDKeyProvider | DIDWebProvider |
|---|---|---|---|
| Default algorithm | EdDSA | EdDSA | RS256 |
| Additional algorithms | — | ES256 | EdDSA, ES256 |
| Key source (Ed25519) | KeyStore via DIDKeyManager | KeyStore via DIDKeyManager | KeyStore via DIDKeyManager |
| Key source (P-256) | — | In-memory (ephemeral) | In-memory (ephemeral) |
| Key source (RSA) | — | — | KeyStore (default cert) |
| Verification method type (Ed25519) | `JsonWebKey2020` | `Ed25519VerificationKey2020` | `Ed25519VerificationKey2020` |
| Key representation (Ed25519) | `publicKeyJwk` | `publicKeyMultibase` | `publicKeyMultibase` |
| Multiple keys in doc | No (single) | No (single) | Yes (all three by default) |
