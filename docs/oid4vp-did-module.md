# OID4VP DID Module

**Artifact ID:** `org.wso2.carbon.identity.openid4vc.oid4vp.did`  
**Package:** `org.wso2.carbon.identity.openid4vc.oid4vp.did`  
**Type:** DID Management Layer  
**Dependencies:** oid4vp.common

## Overview

The DID module handles Decentralized Identifier (DID) resolution, DID Document generation, and cryptographic key management. It provides a pluggable architecture supporting multiple DID methods.

## Module Structure

```
org.wso2.carbon.identity.openid4vc.oid4vp.did/
├── provider/          - DID method provider interfaces and factory
│   └── impl/         - Concrete DID method implementations
├── service/          - High-level DID services
│   └── impl/         - Service implementations
└── util/             - Cryptographic utilities and key management
```

## Supported DID Methods

| DID Method | Identifier Format | Use Case |
|------------|------------------|----------|
| **did:web** | `did:web:example.com` | Web-based DIDs with domain verification |
| **did:key** | `did:key:z6Mk...` | Self-contained cryptographic DIDs |
| **did:jwk** | `did:jwk:eyJrdHk...` | JWK-embedded DIDs |

## Components

### 1. Provider Layer (`provider/`)

#### DIDProvider (Interface)
Base interface for all DID method implementations.

**Methods:**
```java
public interface DIDProvider {
    String getDID(int tenantId, String domain);
    DIDDocument getDIDDocument(int tenantId, String domain) throws DIDDocumentException;
    String getMethod();  // Returns "web", "key", or "jwk"
}
```

#### DIDProviderFactory
Factory for obtaining DID provider instances.

**Key Methods:**
```java
public static DIDProvider getProvider(String method) {
    switch (method) {
        case "web": return new DIDWebProvider();
        case "key": return new DIDKeyProvider();
        case "jwk": return new DIDJwkProvider();
        default: throw new IllegalArgumentException("Unsupported method");
    }
}
```

**Usage:**
```java
DIDProvider provider = DIDProviderFactory.getProvider("web");
String did = provider.getDID(tenantId, "verifier.example.com");
```

---

### 2. DID Method Implementations (`provider/impl/`)

#### DIDWebProvider
Implements the `did:web` method per [W3C DID Web Spec](https://w3c-ccg.github.io/did-method-web/).

**DID Format:**
```
did:web:example.com
did:web:example.com:path:to:did
```

**Resolution:**
- Resolves to `https://example.com/.well-known/did.json`
- For paths: `https://example.com/path/to/did/did.json`

**Key Features:**
- Domain-based trust model
- HTTPS verification required
- Cached DID documents

**Implementation:**
```java
public class DIDWebProvider implements DIDProvider {
    @Override
    public String getDID(int tenantId, String domain) {
        return "did:web:" + domain.replace(":", "%3A");
    }
    
    @Override
    public DIDDocument getDIDDocument(int tenantId, String domain) {
        String did = getDID(tenantId, domain);
        DIDKeyManager keyManager = DIDKeyManager.getInstance(tenantId);
        
        VerificationMethod vm = new VerificationMethod();
        vm.setId(did + "#key-1");
        vm.setType("Ed25519VerificationKey2020");
        vm.setController(did);
        vm.setPublicKeyMultibase(keyManager.getPublicKeyMultibase());
        
        DIDDocument doc = new DIDDocument();
        doc.setId(did);
        doc.setVerificationMethod(List.of(vm));
        doc.setAuthentication(List.of(did + "#key-1"));
        doc.setAssertionMethod(List.of(did + "#key-1"));
        
        return doc;
    }
}
```

#### DIDKeyProvider
Implements the `did:key` method per [W3C DID Key Spec](https://w3c-ccg.github.io/did-method-key/).

**DID Format:**
```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

**Key Features:**
- Self-contained (public key encoded in DID)
- No external resolution needed
- Deterministic from public key
- Supports multiple key types (Ed25519, secp256k1)

**Encoding:**
- Multibase encoding (base58btc)
- Multicodec prefix for key type
- Ed25519 public key: `0xed01` prefix

**Implementation:**
```java
public class DIDKeyProvider implements DIDProvider {
    private static final String MULTICODEC_ED25519_PUB = "ed01";
    
    @Override
    public String getDID(int tenantId, String domain) {
        DIDKeyManager keyManager = DIDKeyManager.getInstance(tenantId);
        byte[] publicKey = keyManager.getPublicKeyBytes();
        
        // Add multicodec prefix
        byte[] multicodecKey = addPrefix(MULTICODEC_ED25519_PUB, publicKey);
        
        // Encode with multibase (base58btc = 'z')
        String encoded = Multibase.encode(Multibase.Base.Base58BTC, multicodecKey);
        
        return "did:key:" + encoded;
    }
}
```

#### DIDJwkProvider
Implements the `did:jwk` method per [DID JWK Spec](https://github.com/quartzjer/did-jwk).

**DID Format:**
```
did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjExcVlBWU...
```

**Key Features:**
- JWK embedded directly in DID
- Base64url encoded
- No resolution required
- Compact representation

**JWK Structure:**
```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
}
```

---

### 3. Services (`service/`)

#### DIDDocumentService
High-level service for DID document operations.

**Interface:**
```java
public interface DIDDocumentService {
    String getDIDDocument(String domain, int tenantId) throws DIDDocumentException;
    DIDDocument getDIDDocumentObject(String domain, int tenantId);
    String getDID(String domain);
    String getDID(int tenantId);
    String regenerateKeys(String domain, int tenantId);
}
```

**Implementation (DIDDocumentServiceImpl):**
- Delegates to appropriate DIDProvider
- Manages key rotation
- Caches DID documents
- Handles tenant-specific DIDs

**Usage:**
```java
@Reference
private DIDDocumentService didDocumentService;

String didDoc = didDocumentService.getDIDDocument("verifier.example.com", tenantId);
String did = didDocumentService.getDID(tenantId);
```

#### DIDResolverService
Service for resolving external DIDs (issuer DIDs).

**Interface:**
```java
public interface DIDResolverService {
    DIDDocument resolve(String did) throws DIDResolutionException;
    VerificationMethod getVerificationMethod(String did, String keyId);
}
```

**Resolution Process:**
1. Parse DID to determine method
2. Based on method:
   - `did:web` → Fetch from `/.well-known/did.json`
   - `did:key` → Decode public key from DID
   - `did:jwk` → Decode JWK from DID
3. Validate DID document structure
4. Cache resolved document

**Implementation:**
```java
@Component(service = DIDResolverService.class)
public class DIDResolverServiceImpl implements DIDResolverService {
    @Override
    public DIDDocument resolve(String did) throws DIDResolutionException {
        String method = extractMethod(did);
        
        switch (method) {
            case "web":
                return resolveWebDID(did);
            case "key":
                return resolveKeyDID(did);
            case "jwk":
                return resolveJwkDID(did);
            default:
                throw new DIDResolutionException("Unsupported method: " + method);
        }
    }
    
    private DIDDocument resolveWebDID(String did) {
        String domain = did.substring("did:web:".length()).replace("%3A", ":");
        String url = "https://" + domain + "/.well-known/did.json";
        
        // HTTP GET with caching
        HttpResponse response = httpClient.get(url);
        return parseDocument(response.getBody());
    }
}
```

---

### 4. Utilities (`util/`)

#### DIDKeyManager
Manages cryptographic keys for DID operations.

**Singleton per Tenant:**
```java
public class DIDKeyManager {
    private static final Map<Integer, DIDKeyManager> instances = new ConcurrentHashMap<>();
    
    public static DIDKeyManager getInstance(int tenantId) {
        return instances.computeIfAbsent(tenantId, DIDKeyManager::new);
    }
}
```

**Key Operations:**
```java
public class DIDKeyManager {
    private KeyPair keyPair;
    
    public byte[] getPublicKeyBytes();
    public String getPublicKeyMultibase();
    public String getPublicKeyJwk();
    
    public byte[] sign(byte[] data) throws SignatureException;
    public boolean verify(byte[] data, byte[] signature);
    
    public void rotateKeys();  // Generate new key pair
}
```

**Key Generation:**
- Algorithm: Ed25519 (EdDSA)
- Key size: 256 bits
- Storage: In-memory (tenant-specific)
- Persistence: Optional database storage

**Usage:**
```java
DIDKeyManager keyManager = DIDKeyManager.getInstance(tenantId);
byte[] signature = keyManager.sign(data);
String publicKeyJwk = keyManager.getPublicKeyJwk();
```

#### BCEd25519Signer
Bouncy Castle-based Ed25519 signature implementation.

**Methods:**
```java
public class BCEd25519Signer {
    public static byte[] sign(byte[] message, Ed25519PrivateKeyParameters privateKey);
    public static boolean verify(byte[] message, byte[] signature, Ed25519PublicKeyParameters publicKey);
    public static KeyPair generateKeyPair();
}
```

**Signature Format:**
- Raw Ed25519 signatures (64 bytes)
- Compatible with JWS EdDSA

**Integration with JWS:**
```java
// Sign JWT with Ed25519
JWSSigner signer = new Ed25519Signer(privateKey);
SignedJWT signedJWT = new SignedJWT(header, payload);
signedJWT.sign(signer);
```

---

## DID Document Structure

### Example: did:web DID Document
```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:web:verifier.example.com",
  "verificationMethod": [{
    "id": "did:web:verifier.example.com#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:web:verifier.example.com",
    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  }],
  "authentication": ["did:web:verifier.example.com#key-1"],
  "assertionMethod": ["did:web:verifier.example.com#key-1"]
}
```

### Verification Method Types

| Type | Description | Use Case |
|------|-------------|----------|
| `Ed25519VerificationKey2020` | Ed25519 public key | JWS signatures |
| `JsonWebKey2020` | JWK format | JWT/JWS |
| `EcdsaSecp256k1VerificationKey2019` | ECDSA secp256k1 | Bitcoin-style sigs |

---

## OSGi Service Registration

The DID module registers its services as OSGi components:

```java
@Component(
    service = DIDDocumentService.class,
    immediate = true
)
public class DIDDocumentServiceImpl implements DIDDocumentService {
    // Implementation
}
```

**Exported Services:**
- `DIDDocumentService`
- `DIDResolverService`

---

## Security Considerations

1. **Key Storage:** Private keys should be stored securely (HSM recommended for production)
2. **Key Rotation:** Implement regular key rotation policies
3. **HTTPS Required:** did:web resolution must use HTTPS
4. **DID Validation:** Always validate DID document structure
5. **Caching:** Cache DID documents with appropriate TTL

---

## Configuration

**Properties:**
- `openid4vp.did.method` - Default DID method (web/key/jwk)
- `openid4vp.did.cache.ttl` - DID document cache TTL (seconds)
- `openid4vp.did.keystore.path` - Key storage location

---

## Usage Examples

### Generate DID for Verifier
```java
DIDDocumentService didService = // OSGi reference
String verifierDID = didService.getDID("verifier.example.com");
// Returns: "did:web:verifier.example.com"
```

### Resolve Issuer DID
```java
DIDResolverService resolver = // OSGi reference
DIDDocument issuerDoc = resolver.resolve("did:web:issuer.example.com");
VerificationMethod vm = issuerDoc.getVerificationMethod().get(0);
```

### Sign Data with DID
```java
DIDKeyManager keyManager = DIDKeyManager.getInstance(tenantId);
byte[] data = "Hello, DID!".getBytes();
byte[] signature = keyManager.sign(data);
```

---

## Testing

### Unit Tests
- DID provider implementations
- Key generation and signing
- DID document parsing

### Integration Tests
- DID resolution over HTTP
- End-to-end signature verification
- Multi-tenant key isolation

Test coverage target: >85%
