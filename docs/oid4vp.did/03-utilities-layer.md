# Utilities Layer

**Package:** `org.wso2.carbon.identity.openid4vc.oid4vp.did.util`

Two utility classes handle the low-level cryptographic operations.

---

## 1. BCEd25519Signer.java — Bouncy Castle Ed25519 Signer

**Path:** `util/BCEd25519Signer.java`  
**Implements:** `com.nimbusds.jose.JWSSigner`

### Why This Class Exists

Nimbus JOSE JWT's built-in `com.nimbusds.jose.crypto.Ed25519Signer` requires **Google Tink** as a transitive dependency. Tink is a large library (~5 MB) with its own key management that conflicts with WSO2 IS's existing key infrastructure. `BCEd25519Signer` provides the same EdDSA signing capability using only **Bouncy Castle**, which is already bundled with WSO2 IS.

### How It Works

```
                         ┌──────────────────────────┐
                         │   JWSSigner interface     │
                         │   (Nimbus JOSE)           │
                         └────────────┬─────────────┘
                                      │ implements
                         ┌────────────▼─────────────┐
                         │   BCEd25519Signer         │
                         │                           │
                         │ - privateKey: OctetKeyPair │
                         │                           │
                         │ + sign(header, input)     │
                         │ + supportedJWSAlgorithms() │
                         │ + getJCAContext()          │
                         └────────────┬─────────────┘
                                      │ uses
                         ┌────────────▼─────────────┐
                         │  Bouncy Castle            │
                         │  Ed25519PrivateKeyParams  │
                         │  Ed25519Signer            │
                         └──────────────────────────┘
```

### Constructor

```java
public BCEd25519Signer(OctetKeyPair privateKey) throws JOSEException
```

**Validations:**
1. Curve must be `Ed25519` — throws `JOSEException` otherwise
2. Private key `d` parameter must be present — throws `JOSEException` otherwise

**Parameter:** `OctetKeyPair` (Nimbus) — contains:
- `x` (Base64URL) — 32-byte public key
- `d` (Base64URL) — 32-byte private key
- `crv` — must be `Ed25519`

### `sign(JWSHeader header, byte[] signingInput)` Method

| Step | Operation |
|---|---|
| 1 | Verify `header.getAlgorithm()` is in `supportedJWSAlgorithms()` (`EdDSA` only) |
| 2 | Extract raw private key bytes: `privateKey.getD().decode()` (32 bytes) |
| 3 | Create BC `Ed25519PrivateKeyParameters(bytes, 0)` |
| 4 | Init BC `Ed25519Signer` in sign mode |
| 5 | Feed `signingInput` bytes |
| 6 | Call `generateSignature()` → 64-byte Ed25519 signature |
| 7 | Return `Base64URL.encode(signature)` |

### Library Explanation: Bouncy Castle Ed25519

The `org.bouncycastle.crypto.signers.Ed25519Signer` is a low-level API:

```java
// 1. Create signer instance
Ed25519Signer signer = new Ed25519Signer();

// 2. Initialize with private key parameters
Ed25519PrivateKeyParameters params = new Ed25519PrivateKeyParameters(rawBytes, 0);
signer.init(true, params);  // true = sign mode

// 3. Feed the data to sign
signer.update(data, 0, data.length);

// 4. Generate 64-byte signature
byte[] sig = signer.generateSignature();
```

Ed25519 signatures are **deterministic** — the same input + key always produces the same signature (no random nonce needed, unlike ECDSA).

### Supported Algorithms

Only `JWSAlgorithm.EdDSA` is supported. This algorithm identifier covers both Ed25519 and Ed448 curves in the JOSE specification, but this signer only handles Ed25519.

---

## 2. DIDKeyManager.java — Key Storage & Generation

**Path:** `util/DIDKeyManager.java`

Central key management utility that bridges WSO2 IS's **Carbon KeyStore** with the Nimbus JOSE JWK types used throughout the DID module.

### Storage Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    DIDKeyManager                         │
│                                                          │
│  ┌─────────────────┐    ┌─────────────────┐            │
│  │ keyCache         │    │ ecKeyCache       │            │
│  │ ConcurrentHash   │    │ ConcurrentHash   │            │
│  │ <tenantId,       │    │ <tenantId,       │            │
│  │  OctetKeyPair>   │    │  ECKey>          │            │
│  └────────┬────────┘    └────────┬────────┘            │
│           │                       │                      │
│     Ed25519 keys            P-256 keys                  │
│     (persistent)            (ephemeral)                  │
│           │                       │                      │
│           ▼                       ▼                      │
│  ┌─────────────────┐    Generated fresh on              │
│  │ KeyStoreManager  │    each server restart              │
│  │ (Carbon JKS)     │                                    │
│  └─────────────────┘                                    │
└─────────────────────────────────────────────────────────┘
```

### Key Types and Persistence

| Key Type | Nimbus Type | Cache | Persistent Storage | Regeneration |
|---|---|---|---|---|
| Ed25519 | `OctetKeyPair` | `keyCache` | WSO2 Carbon KeyStore (JKS) | Clear cache → re-fetch from keystore |
| P-256 (ECDSA) | `ECKey` | `ecKeyCache` | None (in-memory only) | Generate new key pair |

### WSO2 KeyStore Integration

#### How Ed25519 Keys Are Retrieved

```
getOrGenerateKeyPair(tenantId):
  1. Check keyCache → return if found
  2. Get KeyStoreManager.getInstance(tenantId)
  3. Determine alias via getEdDSAKeyAlias(tenantId):
     - Super tenant (-1234): alias = "wso2carbon_ed"
     - Other tenants: KeyStoreUtil.getTenantEdKeyAlias(tenantDomain)
  4. keyStoreManager.getDefaultPublicKey(alias) → verify key exists
  5. keyStoreManager.getDefaultPrivateKey(alias) → get private key
  6. convertToOctetKeyPair(privateKey, keyStoreManager, alias)
  7. Cache and return
```

#### `KeyStoreManager` (from `org.wso2.carbon.core`)

This is WSO2 Carbon's central key store API. Key methods used:

| Method | Purpose |
|---|---|
| `getInstance(tenantId)` | Get keystore manager for a tenant |
| `getDefaultPrivateKey()` | Get RSA private key (default alias) |
| `getDefaultPrivateKey(alias)` | Get private key by alias |
| `getDefaultPublicKey(alias)` | Get public key by alias |
| `getDefaultPrimaryCertificate()` | Get the default X.509 certificate |

The keystore file is typically at `repository/resources/security/wso2carbon.jks`.

#### Ed25519 Key Alias Convention

| Tenant Type | Alias | Example |
|---|---|---|
| Super tenant | `wso2carbon_ed` | Fixed alias |
| Regular tenant | `{tenantDomain}_ed` via `KeyStoreUtil.getTenantEdKeyAlias()` | `example.com_ed` |

#### Key Conversion: PKCS#8/X.509 → OctetKeyPair

`convertToOctetKeyPair()` converts Java standard-format keys to Nimbus JWK format:

```
Private Key (PKCS#8 DER encoded):
  [ASN.1 header ~ varies] [32 bytes raw Ed25519 private key]
  → Extract last 32 bytes

Public Key (X.509 DER encoded):
  [ASN.1 header ~ varies] [32 bytes raw Ed25519 public key]
  → Extract last 32 bytes

Then:
  x = Base64URL.encode(rawPublicKey)   // 32 bytes
  d = Base64URL.encode(rawPrivateKey)  // 32 bytes
  OctetKeyPair = new Builder(Ed25519, x).d(d).build()
```

> **Assumption:** The raw key is always the last 32 bytes of the encoded form. This works for standard Java 15+ / Bouncy Castle Ed25519 key encoding but is not guaranteed by the ASN.1 spec. A more robust implementation would parse the ASN.1 structure.

### P-256 Key Generation

```
getOrGenerateECKeyPair(tenantId):
  1. Check ecKeyCache → return if found
  2. Generate new P-256 key pair via Nimbus ECKeyGenerator
  3. Cache and return
```

P-256 keys are **ephemeral** — they don't survive server restarts. This means:
- `did:key` with ES256 will produce a different DID after each restart
- `did:web` ES256 verification method will have a different key after each restart

### Multibase / Multicodec Encoding

Used to convert public keys into the format required by `did:key` identifiers.

#### Ed25519 → Multibase

```
publicKeyToMultibase(OctetKeyPair):
  1. Get raw 32-byte public key from keyPair.getX().decode()
  2. Prepend 2-byte multicodec prefix: [0xed, 0x01] (Ed25519-pub)
  3. Result: 34-byte array
  4. Base58btc encode
  5. Prepend 'z' (multibase prefix for base58btc)
```

#### P-256 → Multibase

```
publicKeyToMultibase(ECKey):
  1. Get X coordinate (32 bytes)
  2. Get Y coordinate (32 bytes)
  3. Compute compressed point: [0x02 if Y even, 0x03 if Y odd] + X = 33 bytes
  4. Prepend 2-byte multicodec varint: [0x80, 0x24] (p256-pub = 0x1200)
  5. Result: 35-byte array
  6. Base58btc encode
  7. Prepend 'z'
```

> **Multicodec varint note:** The P-256 multicodec is `0x1200`. In unsigned varint encoding: `0x80, 0x24` means `(0x00 & 0x7F) | ((0x24) << 7)` = `0x1200`. This matches the [multicodec table](https://github.com/multiformats/multicodec/blob/master/table.csv).

### DID Key Generation

```
generateDIDKey(tenantId):
  1. getOrGenerateKeyPair(tenantId) → OctetKeyPair
  2. publicKeyToMultibase(keyPair) → "z6Mk..."
  3. Return "did:key:" + multibase

generateDIDKey(ECKey):
  1. publicKeyToMultibase(ecKey) → "zDn..."
  2. Return "did:key:" + multibase
```

### DID Key Extraction (Reverse)

```
extractPublicKeyFromDIDKey(didKey):
  1. Verify starts with "did:key:z"
  2. Strip "did:key:" prefix
  3. Strip 'z' multibase prefix
  4. Base58 decode
  5. Verify multicodec prefix = [0xed, 0x01]
  6. Return bytes[2..34] (32-byte Ed25519 public key)
```

### Base58 (Bitcoin Alphabet)

Both `base58Encode()` and `base58Decode()` use the **Bitcoin Base58** alphabet:

```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

Notable exclusions: `0`, `O`, `I`, `l` — characters that look similar in some fonts.

The implementation uses the classic divmod algorithm for base conversion:
- Encode: repeatedly divide by 58, collect remainders
- Decode: repeatedly multiply by 58, accumulate digits

### Other Methods

| Method | Purpose |
|---|---|
| `publicKeyToJwkMap(keyPair)` | `keyPair.toPublicJWK().toJSONObject()` — convenience wrapper |
| `regenerateKeyPair(tenantId)` | Clear Ed25519 cache → re-fetch from KeyStore |
| `hasKeys(tenantId)` | Check if either cache has keys for tenant |
| `removeKeys(tenantId)` | Remove both Ed25519 and P-256 keys from cache |

---

## Library Dependencies Used in Utilities

### Nimbus JOSE JWT (`com.nimbusds:nimbus-jose-jwt`)

| Class | Usage |
|---|---|
| `JWSSigner` | Interface implemented by `BCEd25519Signer` |
| `JWSAlgorithm` | Algorithm constants (`EdDSA`, `RS256`, `ES256`) |
| `JWSHeader` | JWT header passed to `sign()` |
| `OctetKeyPair` | Ed25519 key pair container (JWK format) |
| `ECKey` | P-256 key pair container (JWK format) |
| `ECKeyGenerator` | P-256 key pair generation |
| `Base64URL` | URL-safe Base64 encoding/decoding |
| `Curve` | Named curves (`Ed25519`, `P_256`) |

### Bouncy Castle (`org.bouncycastle:bcprov-jdk18on`)

| Class | Usage |
|---|---|
| `Ed25519PrivateKeyParameters` | Wraps raw 32-byte private key for signer |
| `Ed25519Signer` | Low-level Ed25519 signing |
| `BouncyCastleProvider` | JCA security provider (registered in static block) |

### WSO2 Carbon (`org.wso2.carbon.core`)

| Class | Usage |
|---|---|
| `KeyStoreManager` | Access tenant keystore for RSA + Ed25519 keys |
| `KeyStoreUtil` | Get tenant-specific key aliases |
| `PrivilegedCarbonContext` | Get tenant domain from thread-local context |
| `MultitenantConstants` | `SUPER_TENANT_ID` constant |
