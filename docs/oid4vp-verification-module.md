# OID4VP Verification Module

**Artifact ID:** `org.wso2.carbon.identity.openid4vc.oid4vp.verification`  
**Package:** `org.wso2.carbon.identity.openid4vc.oid4vp.verification`  
**Type:** Credential Verification Layer  
**Dependencies:** oid4vp.common, oid4vp.did

## Overview

The Verification module provides cryptographic verification of Verifiable Credentials (VCs) and Verifiable Presentations (VPs). It validates signatures, checks credential status, and ensures credentials meet trust requirements.

## Module Structure

```
org.wso2.carbon.identity.openid4vc.oid4vp.verification/
├── service/          - Verification service interfaces
│   └── impl/        - Concrete verification implementations
└── util/            - Cryptographic utilities
```

## Supported VC Formats

| Format | MIME Type | Signature Algorithm | Specification |
|--------|-----------|---------------------|---------------|
| **JWT VC** | `application/vc+jwt` | EdDSA, ES256K, RS256 | [VC-JWT](https://www.w3.org/TR/vc-data-model/#json-web-token) |
| **JSON-LD VC** | `application/vc+ld+json` | Ed25519Signature2020 | [VC-Data-Model](https://www.w3.org/TR/vc-data-model/) |
| **SD-JWT VC** | `application/vc+sd-jwt` | EdDSA, ES256 | [SD-JWT-VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-03.html) |

## Components

### 1. Services (`service/`)

#### VCVerificationService
Primary service for verifying Verifiable Credentials.

**Interface:**
```java
public interface VCVerificationService {
    VCVerificationResultDTO verify(String vcToken, String format) 
        throws CredentialVerificationException;
    
    VCVerificationResultDTO verifyJWT(String jwtVC) 
        throws CredentialVerificationException;
    
    VCVerificationResultDTO verifyJSONLD(String jsonldVC) 
        throws CredentialVerificationException;
    
    VCVerificationResultDTO verifySDJWT(String sdjwtVC) 
        throws CredentialVerificationException;
    
    boolean isTrustedIssuer(String issuerDID);
}
```

**Implementation (VCVerificationServiceImpl):**

##### JWT VC Verification Process
```java
public VCVerificationResultDTO verifyJWT(String jwtVC) {
    // 1. Parse JWT
    SignedJWT signedJWT = SignedJWT.parse(jwtVC);
    JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
    
    // 2. Extract issuer DID
    String issuerDID = claims.getIssuer();
    
    // 3. Resolve issuer DID document
    DIDDocument issuerDoc = didResolver.resolve(issuerDID);
    
    // 4. Get verification method
    String kid = signedJWT.getHeader().getKeyID();
    VerificationMethod vm = issuerDoc.getVerificationMethod(kid);
    
    // 5. Verify signature
    JWSVerifier verifier = createVerifier(vm);
    boolean signatureValid = signedJWT.verify(verifier);
    
    if (!signatureValid) {
        return createResult(VCVerificationStatus.INVALID_SIGNATURE);
    }
    
    // 6. Check expiration
    Date expirationTime = claims.getExpirationTime();
    if (expirationTime != null && expirationTime.before(new Date())) {
        return createResult(VCVerificationStatus.EXPIRED);
    }
    
    // 7. Check credential status (revocation)
    VCVerificationStatus status = checkCredentialStatus(claims);
    
    // 8. Verify issuer is trusted
    if (!isTrustedIssuer(issuerDID)) {
        return createResult(VCVerificationStatus.ISSUER_NOT_TRUSTED);
    }
    
    // 9. Extract claims
    Map<String, Object> vcClaims = extractClaims(claims);
    
    return createResult(VCVerificationStatus.VALID, vcClaims);
}
```

##### JSON-LD VC Verification Process
```java
public VCVerificationResultDTO verifyJSONLD(String jsonldVC) {
    // 1. Parse JSON-LD
    JsonObject vcJson = JsonParser.parseString(jsonldVC).getAsJsonObject();
    
    // 2. Extract proof object
    JsonObject proof = vcJson.getAsJsonObject("proof");
    String proofType = proof.get("type").getAsString();
    
    // 3. Verify proof based on type
    switch (proofType) {
        case "Ed25519Signature2020":
            return verifyEd25519Signature2020(vcJson, proof);
        case "JsonWebSignature2020":
            return verifyJWS2020(vcJson, proof);
        default:
            throw new CredentialVerificationException("Unsupported proof type");
    }
}

private VCVerificationResultDTO verifyEd25519Signature2020(
        JsonObject vcJson, JsonObject proof) {
    // 1. Extract verification method
    String verificationMethod = proof.get("verificationMethod").getAsString();
    
    // 2. Resolve verification method
    DIDDocument issuerDoc = didResolver.resolve(extractDID(verificationMethod));
    VerificationMethod vm = issuerDoc.getVerificationMethod(verificationMethod);
    
    // 3. Canonicalize VC (without proof)
    JsonObject vcWithoutProof = removeProof(vcJson);
    String canonical = JsonLdUtils.canonicalize(vcWithoutProof);
    
    // 4. Decode signature
    byte[] signature = Base64.getUrlDecoder().decode(
        proof.get("proofValue").getAsString()
    );
    
    // 5. Verify signature
    Ed25519PublicKeyParameters pubKey = parsePublicKey(vm);
    boolean valid = BCEd25519Signer.verify(
        canonical.getBytes(), signature, pubKey
    );
    
    return valid ? 
        createResult(VCVerificationStatus.VALID) : 
        createResult(VCVerificationStatus.INVALID_SIGNATURE);
}
```

##### SD-JWT VC Verification Process
```java
public VCVerificationResultDTO verifySDJWT(String sdjwtVC) {
    // SD-JWT format: <Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<KB-JWT>
    
    // 1. Split components
    String[] parts = sdjwtVC.split("~");
    String issuerJWT = parts[0];
    List<String> disclosures = Arrays.asList(parts).subList(1, parts.length - 1);
    String kbJWT = parts[parts.length - 1];
    
    // 2. Verify issuer-signed JWT
    VCVerificationResultDTO issuerVerification = verifyJWT(issuerJWT);
    if (issuerVerification.getStatus() != VCVerificationStatus.VALID) {
        return issuerVerification;
    }
    
    // 3. Verify key binding JWT (if present)
    if (!kbJWT.isEmpty()) {
        boolean kbValid = verifyKeyBinding(kbJWT, issuerJWT);
        if (!kbValid) {
            return createResult(VCVerificationStatus.INVALID_SIGNATURE);
        }
    }
    
    // 4. Process disclosures
    Map<String, Object> disclosedClaims = processDisclosures(disclosures);
    
    // 5. Merge with claims from issuer JWT
    Map<String, Object> allClaims = mergeClaims(
        issuerVerification.getClaims(), 
        disclosedClaims
    );
    
    return createResult(VCVerificationStatus.VALID, allClaims);
}
```

---

#### StatusListService
Handles credential status checking (revocation).

**Interface:**
```java
public interface StatusListService {
    boolean isRevoked(String credentialId, String statusListUrl) 
        throws CredentialVerificationException;
    
    boolean isRevoked(Map<String, Object> credentialStatus);
}
```

**Supported Status Types:**

##### StatusList2021
Per [VC Status List 2021](https://w3c-ccg.github.io/vc-status-list-2021/).

**VC Structure:**
```json
{
  "credentialSubject": {
    "id": "did:example:123",
    ...
  },
  "credentialStatus": {
    "id": "https://issuer.example.com/status/1#94567",
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "94567",
    "statusListCredential": "https://issuer.example.com/status/1"
  }
}
```

**Verification Process:**
```java
@Override
public boolean isRevoked(Map<String, Object> credentialStatus) {
    String statusListUrl = (String) credentialStatus.get("statusListCredential");
    int index = Integer.parseInt((String) credentialStatus.get("statusListIndex"));
    
    // 1. Fetch status list VC
    String statusListVC = httpClient.get(statusListUrl);
    
    // 2. Verify status list VC signature
    VCVerificationResultDTO result = vcVerificationService.verify(statusListVC);
    if (result.getStatus() != VCVerificationStatus.VALID) {
        throw new CredentialVerificationException("Invalid status list");
    }
    
    // 3. Extract encoded list
    JWTClaimsSet claims = SignedJWT.parse(statusListVC).getJWTClaimsSet();
    String encodedList = (String) claims.getClaim("encodedList");
    
    // 4. Decode and check bit
    byte[] decodedList = Base64.getDecoder().decode(encodedList);
    byte[] uncompressed = decompress(decodedList);  // GZIP
    
    int byteIndex = index / 8;
    int bitIndex = index % 8;
    boolean isRevoked = (uncompressed[byteIndex] & (1 << bitIndex)) != 0;
    
    return isRevoked;
}
```

##### BitstringStatusList (v2)
Per [Bitstring Status List v2](https://www.w3.org/TR/vc-bitstring-status-list/).

Similar to StatusList2021 but with updated encoding format.

---

### 2. Utilities (`util/`)

#### SignatureVerifier
Low-level signature verification utilities.

**Methods:**
```java
public class SignatureVerifier {
    public static boolean verifyEdDSA(byte[] message, byte[] signature, byte[] publicKey);
    public static boolean verifyES256K(byte[] message, byte[] signature, byte[] publicKey);
    public static boolean verifyRS256(byte[] message, byte[] signature, byte[] publicKey);
    
    public static JWSVerifier createVerifier(VerificationMethod vm) 
        throws CredentialVerificationException;
}
```

**Signature Algorithm Support:**

| Algorithm | Curve/Key Type | Key Size | Usage |
|-----------|---------------|----------|-------|
| **EdDSA** | Ed25519 | 256-bit | Default for DIDs |
| **ES256K** | secp256k1 | 256-bit | Ethereum compatibility |
| **RS256** | RSA | 2048-bit+ | Legacy support |
| **ES256** | P-256 | 256-bit | NIST curve |

**Creating JWS Verifier:**
```java
public static JWSVerifier createVerifier(VerificationMethod vm) {
    String keyType = vm.getType();
    
    switch (keyType) {
        case "Ed25519VerificationKey2020":
            byte[] pubKeyBytes = decodeMultibase(vm.getPublicKeyMultibase());
            Ed25519PublicKeyParameters pubKey = new Ed25519PublicKeyParameters(pubKeyBytes, 0);
            return new Ed25519Verifier(pubKey);
            
        case "JsonWebKey2020":
            JWK jwk = JWK.parse(vm.getPublicKeyJwk());
            return new ECDSAVerifier((ECKey) jwk);
            
        case "EcdsaSecp256k1VerificationKey2019":
            // Secp256k1 verification
            return new ES256KVerifier(parseSecp256k1Key(vm));
            
        default:
            throw new CredentialVerificationException("Unsupported key type: " + keyType);
    }
}
```

---

## Verification Workflow

### Complete VC Verification Flow
```
Input: VC Token + Format
        ↓
1. Parse VC based on format
   ├→ JWT: SignedJWT.parse()
   ├→ JSON-LD: JsonParser.parse()
   └→ SD-JWT: Split and parse components
        ↓
2. Extract Issuer DID
   ├→ JWT: From 'iss' claim
   └→ JSON-LD: From 'issuer' field
        ↓
3. Resolve Issuer DID Document
   ├→ DIDResolverService.resolve(issuerDID)
   └→ Cache DID documents
        ↓
4. Get Verification Method
   ├→ Match by key ID ('kid' header)
   └→ Extract public key
        ↓
5. Verify Cryptographic Signature
   ├→ SignatureVerifier.verify()
   └→ Algorithm-specific verification
        ↓
6. Check Temporal Validity
   ├→ Not before (nbf)
   ├→ Expiration (exp)
   └→ Issuance date
        ↓
7. Check Credential Status
   ├→ StatusListService.isRevoked()
   ├→ Fetch and verify status list
   └→ Check revocation bit
        ↓
8. Verify Trust
   ├→ Check issuer against trusted list
   └→ Validate trust chain
        ↓
9. Extract Claims
   ├→ Parse credentialSubject
   └→ Process selective disclosure
        ↓
Output: VCVerificationResultDTO
   ├→ Status (VALID/INVALID/REVOKED/EXPIRED)
   ├→ Claims (Map<String, Object>)
   ├→ Error message (if failed)
   └→ Metadata (issuer, subject, timestamps)
```

---

## Trust Framework Integration

### Trusted Issuer Registry
```java
public class TrustedIssuerRegistry {
    private static final Set<String> TRUSTED_ISSUERS = new HashSet<>();
    
    static {
        // Load from configuration
        TRUSTED_ISSUERS.add("did:web:trusted-issuer.example.com");
        TRUSTED_ISSUERS.add("did:web:gov-issuer.example.org");
    }
    
    public static boolean isTrusted(String issuerDID) {
        return TRUSTED_ISSUERS.contains(issuerDID);
    }
    
    public static void addTrustedIssuer(String issuerDID) {
        TRUSTED_ISSUERS.add(issuerDID);
    }
}
```

### Trust Chain Validation
For hierarchical trust models:
```java
public boolean validateTrustChain(String issuerDID) {
    // 1. Resolve issuer DID
    DIDDocument issuerDoc = didResolver.resolve(issuerDID);
    
    // 2. Check for trust assertions
    List<String> controllers = issuerDoc.getController();
    
    // 3. Validate controllers recursively
    for (String controller : controllers) {
        if (isTrustedAuthority(controller)) {
            return true;
        }
        if (validateTrustChain(controller)) {
            return true;
        }
    }
    
    return false;
}
```

---

## OSGi Service Registration

```java
@Component(
    service = {VCVerificationService.class, StatusListService.class},
    immediate = true
)
public class VCVerificationServiceImpl implements VCVerificationService, StatusListService {
    @Reference
    private DIDResolverService didResolver;
    
    // Implementation
}
```

---

## Configuration

**Properties:**
```properties
# Trusted issuers (comma-separated DIDs)
openid4vp.verification.trusted.issuers=did:web:issuer1.com,did:web:issuer2.com

# Enable/disable revocation checking
openid4vp.verification.check.revocation=true

# Status list cache TTL (seconds)
openid4vp.verification.statuslist.cache.ttl=3600

# Signature algorithms allowed
openid4vp.verification.allowed.algorithms=EdDSA,ES256K,RS256
```

---

## Error Handling

### Verification Exceptions
```java
try {
    VCVerificationResultDTO result = vcVerificationService.verify(vcToken, format);
    
    switch (result.getStatus()) {
        case VALID:
            // Process claims
            processClaims(result.getClaims());
            break;
            
        case INVALID_SIGNATURE:
            throw new CredentialVerificationException("Invalid signature");
            
        case REVOKED:
            throw new CredentialVerificationException("Credential revoked");
            
        case EXPIRED:
            throw new CredentialVerificationException("Credential expired");
            
        case ISSUER_NOT_TRUSTED:
            throw new CredentialVerificationException("Issuer not trusted");
    }
    
} catch (CredentialVerificationException e) {
    log.error("Verification failed: " + e.getMessage());
    // Handle error
}
```

---

## Performance Optimizations

1. **DID Document Caching** - Cache resolved DID documents (TTL: 1 hour)
2. **Status List Caching** - Cache status lists to avoid repeated fetches
3. **Parallel Verification** - Verify multiple VCs concurrently
4. **Signature Batching** - Batch signature verifications where possible

---

## Security Best Practices

1. **Algorithm Whitelist** - Only allow configured signature algorithms
2. **Key Size Enforcement** - Minimum key sizes (RSA: 2048-bit, EC: 256-bit)
3. **Expiration Checking** - Always validate temporal bounds
4. **Revocation Checking** - Enable by default
5. **Trust Validation** - Require issuer to be in trusted registry
6. **Rate Limiting** - Limit DID resolution requests to prevent DoS

---

## Testing

### Unit Tests
- Signature verification for each algorithm
- Status list parsing and checking
- Trust chain validation
- Error handling

### Integration Tests
- End-to-end VC verification
- DID resolution integration
- Status list fetching
- Multi-format VC support

Test coverage target: >90%
