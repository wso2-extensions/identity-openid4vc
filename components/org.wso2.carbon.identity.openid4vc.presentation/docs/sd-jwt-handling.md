# SD-JWT Handling in OpenID4VP

## Overview

This document explains how SD-JWT (Selective Disclosure JWT) credentials are handled in the WSO2 Identity Server OpenID4VP implementation, from presentation request generation to credential verification and claim extraction.

**SD-JWT** enables selective disclosure of claims in Verifiable Credentials, allowing holders to reveal only the necessary information to verifiers while maintaining privacy.

---

## Table of Contents

1. [SD-JWT Format Structure](#sd-jwt-format-structure)
2. [Supported Algorithms](#supported-algorithms)
3. [End-to-End Flow](#end-to-end-flow)
4. [Component Architecture](#component-architecture)
5. [Implementation Details](#implementation-details)
6. [Code Examples](#code-examples)
7. [Verification Process](#verification-process)
8. [Error Handling](#error-handling)

---

## SD-JWT Format Structure

### Basic Format

SD-JWT credentials follow this structure:

```
<issuer-jwt>~<disclosure-1>~<disclosure-2>~...~<disclosure-n>~<key-binding-jwt>
```

### Components

| Component | Description | Required |
|-----------|-------------|----------|
| **Issuer JWT** | Standard 3-part JWT (`header.payload.signature`) containing the credential with hashed claims | ✅ Yes |
| **Disclosures** | Base64url-encoded arrays containing salt, claim name, and claim value | ⚠️ Optional (0 or more) |
| **Key Binding JWT** | JWT proving holder possession of the credential | ⚠️ Optional |

### Disclosure Format

Each disclosure is a Base64url-encoded JSON array:

```json
[
  "<salt>",           // Random salt for privacy
  "<claim_name>",     // Name of the disclosed claim
  <claim_value>       // Value of the disclosed claim
]
```

**Example Disclosure (decoded):**
```json
["6qMQvRL5haj", "given_name", "John"]
```

**Example Disclosure (encoded):**
```
WyI2cU1RdlJMNWhhaiIsICJnaXZlbl9uYW1lIiwgIkpvaG4iXQ
```

---

## Supported Algorithms

### SD-JWT Algorithms

The implementation supports the following algorithms for SD-JWT:

#### Issuer-Signed JWT Algorithms
- `RS256` - RSA with SHA-256
- `ES256` - ECDSA with P-256 and SHA-256
- `ES256K` - ECDSA with secp256k1 and SHA-256
- **`EdDSA`** - Ed25519 signature algorithm

#### Key Binding JWT Algorithms
- `RS256` - RSA with SHA-256
- `ES256` - ECDSA with P-256 and SHA-256
- `ES256K` - ECDSA with secp256k1 and SHA-256
- **`EdDSA`** - Ed25519 signature algorithm

> **Note:** EdDSA is the recommended algorithm for new implementations due to its security and performance benefits.

---

## End-to-End Flow

```mermaid
sequenceDiagram
    participant Verifier as WSO2 IS (Verifier)
    participant Wallet as Wallet App
    participant Issuer as Credential Issuer

    Note over Verifier: 1. VP Request Generation
    Verifier->>Verifier: Create Presentation Definition
    Verifier->>Verifier: Specify vc+sd-jwt format support
    Verifier->>Wallet: Send VP Request (QR/Deep Link)
    
    Note over Wallet: 2. Credential Selection
    Wallet->>Wallet: Parse VP Request
    Wallet->>Wallet: Select SD-JWT credential
    Wallet->>Wallet: Choose claims to disclose
    
    Note over Wallet: 3. VP Token Creation
    Wallet->>Wallet: Extract issuer JWT
    Wallet->>Wallet: Add selected disclosures
    Wallet->>Wallet: Create key binding JWT (optional)
    Wallet->>Wallet: Construct SD-JWT token
    
    Note over Wallet: 4. VP Submission
    Wallet->>Verifier: POST /api/openid4vp/v1/response
    
    Note over Verifier: 5. VP Token Processing
    Verifier->>Verifier: Extract VP token
    Verifier->>Verifier: Detect SD-JWT format (contains ~)
    Verifier->>Verifier: Parse SD-JWT components
    
    Note over Verifier: 6. Verification
    Verifier->>Verifier: Verify issuer JWT signature
    Verifier->>Issuer: Resolve issuer DID (if needed)
    Verifier->>Verifier: Process disclosures
    Verifier->>Verifier: Extract revealed claims
    Verifier->>Verifier: Verify key binding JWT (if present)
    
    Note over Verifier: 7. Validation
    Verifier->>Verifier: Validate against Presentation Definition
    Verifier->>Verifier: Check required claims
    Verifier->>Verifier: Verify credential status
    
    Note over Verifier: 8. Authentication
    Verifier->>Verifier: Map claims to user attributes
    Verifier->>Verifier: Complete authentication
```

---

## Component Architecture

### Key Components

#### 1. **VP Request Generation**
- **File:** [`VPRequestServiceImpl.java`](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/VPRequestServiceImpl.java#L476-L479)
- **Responsibility:** Advertise SD-JWT support in VP request

#### 2. **VP Token Extraction**
- **File:** [`OpenID4VPAuthenticator.java`](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/OpenID4VPAuthenticator.java#L205-L217)
- **Responsibility:** Detect and extract SD-JWT from VP token

#### 3. **SD-JWT Validation**
- **File:** [`VPSubmissionValidator.java`](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/util/VPSubmissionValidator.java#L274-L295)
- **Responsibility:** Validate SD-JWT format structure

#### 4. **SD-JWT Parsing**
- **File:** [`VCVerificationServiceImpl.java`](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/VCVerificationServiceImpl.java#L590-L634)
- **Responsibility:** Parse SD-JWT into structured credential object

#### 5. **Disclosure Processing**
- **File:** [`VCVerificationServiceImpl.java`](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/VCVerificationServiceImpl.java#L636-L666)
- **Responsibility:** Decode disclosures and extract revealed claims

#### 6. **Signature Verification**
- **File:** [`VCVerificationServiceImpl.java`](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/service/impl/VCVerificationServiceImpl.java#L331-L353)
- **Responsibility:** Verify issuer JWT signature

#### 7. **Data Model**
- **File:** [`VerifiableCredential.java`](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/model/VerifiableCredential.java#L90-L92)
- **Responsibility:** Store SD-JWT specific fields (disclosures, key binding JWT)

---

## Implementation Details

### Phase 1: VP Request Generation

**Location:** `VPRequestServiceImpl.createVPRequest()`

The verifier advertises SD-JWT support in the VP request:

```java
// Declare supported VP formats
Map<String, Object> vpFormats = new HashMap<>();

// SD-JWT format support
Map<String, Object> vcSdJwt = new HashMap<>();
vcSdJwt.put("sd-jwt_alg_values", Arrays.asList("RS256", "ES256", "ES256K", "EdDSA"));
vcSdJwt.put("kb-jwt_alg_values", Arrays.asList("RS256", "ES256", "ES256K", "EdDSA"));
vpFormats.put("vc+sd-jwt", vcSdJwt);

clientMetadata.put("vp_formats", vpFormats);
```

**VP Request Example:**
```json
{
  "client_id": "https://verifier.example.com",
  "response_type": "vp_token",
  "presentation_definition": { ... },
  "client_metadata": {
    "vp_formats": {
      "vc+sd-jwt": {
        "sd-jwt_alg_values": ["RS256", "ES256", "ES256K", "EdDSA"],
        "kb-jwt_alg_values": ["RS256", "ES256", "ES256K", "EdDSA"]
      }
    }
  }
}
```

---

### Phase 2: VP Token Extraction

**Location:** `OpenID4VPAuthenticator.processRequest()`

The authenticator detects SD-JWT format by checking for the `~` separator:

```java
// Detect SD-JWT format (contains ~)
if (vpData == null && vpToken.contains("~")) {
    String[] sdParts = vpToken.split("~");
    String issuerJwt = sdParts[0];  // Extract issuer JWT
    
    // Decode JWT payload
    String[] jwtParts = issuerJwt.split("\\.");
    if (jwtParts.length >= 2) {
        String payload = new String(
            Base64.getUrlDecoder().decode(jwtParts[1]), 
            StandardCharsets.UTF_8
        );
        vpData = JsonParser.parseString(payload).getAsJsonObject();
    }
}
```

**Example SD-JWT Token:**
```
eyJhbGc...header.eyJpc3M...payload.signature~
WyI2cU1RdlJMNWhhaiIsICJnaXZlbl9uYW1lIiwgIkpvaG4iXQ~
WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~
eyJhbGc...kb-jwt
```

---

### Phase 3: SD-JWT Validation

**Location:** `VPSubmissionValidator.validateSdJwtVP()`

Basic format validation ensures the SD-JWT structure is correct:

```java
private static void validateSdJwtVP(final String sdJwt) 
        throws VPSubmissionValidationException {
    
    // SD-JWT format: <Issuer-signed JWT>~<Disclosure 1>~...~<KB-JWT>
    String[] parts = sdJwt.split("~");
    if (parts.length < 1) {
        throw new VPSubmissionValidationException("Invalid SD-JWT format");
    }
    
    // First part should be a valid JWT
    if (!isJwtFormat(parts[0])) {
        throw new VPSubmissionValidationException(
            "SD-JWT issuer-signed part is not valid JWT"
        );
    }
}
```

**Validation Checks:**
- ✅ At least one part (issuer JWT) exists
- ✅ First part is valid JWT format (3 parts separated by `.`)
- ✅ Parts are separated by `~`

---

### Phase 4: SD-JWT Parsing

**Location:** `VCVerificationServiceImpl.parseSdJwtCredential()`

The SD-JWT is parsed into a structured `VerifiableCredential` object:

```java
private VerifiableCredential parseSdJwtCredential(String sdJwtString)
        throws CredentialVerificationException {
    
    String[] parts = sdJwtString.split("~");
    if (parts.length < 1) {
        throw new CredentialVerificationException("Invalid SD-JWT format");
    }
    
    // 1. Parse the issuer JWT first
    VerifiableCredential credential = parseJwtCredential(parts[0]);
    credential.setFormat(VerifiableCredential.Format.SD_JWT);
    credential.setRawCredential(sdJwtString);
    
    // 2. Parse disclosures and key binding JWT
    List<String> disclosures = new ArrayList<>();
    for (int i = 1; i < parts.length; i++) {
        String part = parts[i].trim();
        if (!part.isEmpty()) {
            // Check if this is the key binding JWT (last part, contains dots)
            if (i == parts.length - 1 && part.split("\\.").length == 3) {
                credential.setKeyBindingJwt(part);
            } else {
                disclosures.add(part);
            }
        }
    }
    credential.setDisclosures(disclosures);
    
    // 3. Process disclosures to extract revealed claims
    processDisclosures(credential);
    
    return credential;
}
```

**Parsing Steps:**
1. **Split by `~`** - Separate components
2. **Parse Issuer JWT** - Extract standard JWT claims
3. **Collect Disclosures** - Store all disclosure strings
4. **Identify Key Binding JWT** - Last part with 3 dot-separated segments
5. **Process Disclosures** - Decode and extract claims

---

### Phase 5: Disclosure Processing

**Location:** `VCVerificationServiceImpl.processDisclosures()`

Disclosures are decoded to extract the revealed claims:

```java
private void processDisclosures(VerifiableCredential credential) {
    if (credential.getDisclosures() == null) {
        return;
    }
    
    Map<String, Object> claims = credential.getCredentialSubject();
    if (claims == null) {
        claims = new HashMap<>();
        credential.setCredentialSubject(claims);
    }
    
    for (String disclosure : credential.getDisclosures()) {
        try {
            // Disclosure format: base64url([salt, claim_name, claim_value])
            String decoded = new String(
                Base64.getUrlDecoder().decode(disclosure),
                StandardCharsets.UTF_8
            );
            JsonArray arr = JsonParser.parseString(decoded).getAsJsonArray();
            
            if (arr.size() >= 3) {
                String claimName = arr.get(1).getAsString();
                JsonElement claimValue = arr.get(2);
                claims.put(claimName, parseJsonElement(claimValue));
            }
        } catch (Exception e) {
            // Ignore invalid disclosures
        }
    }
}
```

**Processing Steps:**
1. **Base64url Decode** - Decode each disclosure
2. **Parse JSON Array** - Extract `[salt, claim_name, claim_value]`
3. **Extract Claim** - Get claim name and value
4. **Add to Credential Subject** - Store in credential's claims map

**Example:**

```
Input Disclosure: WyI2cU1RdlJMNWhhaiIsICJnaXZlbl9uYW1lIiwgIkpvaG4iXQ

Decoded: ["6qMQvRL5haj", "given_name", "John"]

Extracted:
  - Claim Name: "given_name"
  - Claim Value: "John"

Result: credentialSubject.put("given_name", "John")
```

---

### Phase 6: Signature Verification

**Location:** `VCVerificationServiceImpl.verifySdJwtSignature()`

Only the issuer JWT (first part) is verified:

```java
private boolean verifySdJwtSignature(VerifiableCredential credential)
        throws CredentialVerificationException {
    
    // SD-JWT format: <issuer-jwt>~<disclosure1>~<disclosure2>~...~<kb-jwt>
    String rawCredential = credential.getRawCredential();
    String[] parts = rawCredential.split("~");
    
    if (parts.length < 1) {
        throw new CredentialVerificationException("Invalid SD-JWT format");
    }
    
    // Verify the issuer JWT (first part)
    String issuerJwt = parts[0];
    
    // Create a temporary credential for JWT verification
    VerifiableCredential tempCred = new VerifiableCredential();
    tempCred.setFormat(VerifiableCredential.Format.JWT);
    tempCred.setRawCredential(issuerJwt);
    tempCred.setIssuer(credential.getIssuer());
    tempCred.setIssuerId(credential.getIssuerId());
    
    return verifyJwtSignature(tempCred);
}
```

**Verification Flow:**
1. **Extract Issuer JWT** - Get first part before `~`
2. **Create Temporary Credential** - Wrap as standard JWT
3. **Verify Signature** - Use standard JWT verification
4. **Resolve Issuer DID** - Get public key from DID document
5. **Validate Signature** - Verify using issuer's public key

---

### Phase 7: Data Model

**Location:** `VerifiableCredential.java`

The `VerifiableCredential` class includes SD-JWT specific fields:

```java
public class VerifiableCredential {
    
    // Format enum
    public enum Format {
        JSON_LD("ldp_vc"),
        JWT("jwt_vc"),
        JWT_JSON("jwt_vc_json"),
        SD_JWT("vc+sd-jwt");  // SD-JWT format
        
        // ...
    }
    
    // SD-JWT specific fields
    private List<String> disclosures;      // List of disclosure strings
    private String keyBindingJwt;          // Optional key binding JWT
    
    // Helper methods
    public boolean isSdJwt() {
        return format == Format.SD_JWT;
    }
    
    public List<String> getDisclosures() {
        return disclosures != null ? new ArrayList<>(disclosures) : null;
    }
    
    public void setDisclosures(List<String> disclosures) {
        this.disclosures = disclosures != null ? new ArrayList<>(disclosures) : null;
    }
    
    public String getKeyBindingJwt() {
        return keyBindingJwt;
    }
    
    public void setKeyBindingJwt(String keyBindingJwt) {
        this.keyBindingJwt = keyBindingJwt;
    }
}
```

---

## Code Examples

### Example 1: Complete SD-JWT Token

```
eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCJ9.
eyJpc3MiOiJkaWQ6d2ViOmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6ImRpZDprZXk6ejZNa...",
InZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxz...",
ImlkIjoidXJuOnV1aWQ6MTIzNDU2NzgiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIi...",
ImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJhYmMxMjMiLCJkZWY0NTYiXX19fQ.
signature~
WyI2cU1RdlJMNWhhaiIsICJnaXZlbl9uYW1lIiwgIkpvaG4iXQ~
WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~
eyJhbGciOiJFZERTQSIsInR5cCI6ImtiK2p3dCJ9.eyJub25jZSI6IjEyMzQ1Njc4IiwiaWF0IjoxNjk4NzY1NDMyLCJhdWQiOiJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUuY29tIn0.kb-signature
```

**Components:**
1. **Issuer JWT:** `eyJhbGc...signature`
2. **Disclosure 1:** `WyI2cU1RdlJMNWhhaiIsICJnaXZlbl9uYW1lIiwgIkpvaG4iXQ` (given_name: John)
3. **Disclosure 2:** `WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd` (family_name: Doe)
4. **Key Binding JWT:** `eyJhbGc...kb-signature`

### Example 2: Minimal SD-JWT (No Disclosures)

```
eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCJ9.
eyJpc3MiOiJkaWQ6d2ViOmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6ImRpZDprZXk6ejZNa...",
signature
```

**Note:** No `~` separators means no disclosures or key binding JWT.

### Example 3: SD-JWT with Key Binding Only

```
eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCJ9.
eyJpc3MiOiJkaWQ6d2ViOmlzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6ImRpZDprZXk6ejZNa...",
signature~
eyJhbGciOiJFZERTQSIsInR5cCI6ImtiK2p3dCJ9.eyJub25jZSI6IjEyMzQ1Njc4In0.kb-signature
```

**Note:** Empty disclosures (no claims revealed), but includes key binding JWT.

---

## Verification Process

### Verification Steps

```mermaid
flowchart TD
    A[Receive SD-JWT Token] --> B{Contains ~?}
    B -->|No| C[Treat as Standard JWT]
    B -->|Yes| D[Split by ~]
    
    D --> E[Extract Issuer JWT]
    E --> F[Parse JWT Header & Payload]
    
    F --> G[Resolve Issuer DID]
    G --> H[Get Public Key]
    H --> I[Verify Issuer JWT Signature]
    
    I -->|Invalid| J[Reject: Invalid Signature]
    I -->|Valid| K[Process Disclosures]
    
    K --> L[Decode Each Disclosure]
    L --> M[Extract Claims]
    M --> N[Add to Credential Subject]
    
    N --> O{Key Binding JWT Present?}
    O -->|Yes| P[Verify Key Binding JWT]
    O -->|No| Q[Skip Key Binding]
    
    P --> R[Validate Against Presentation Definition]
    Q --> R
    
    R --> S{All Requirements Met?}
    S -->|Yes| T[Accept Credential]
    S -->|No| U[Reject: Missing Claims]
```

### Verification Checklist

- ✅ **Format Validation** - Correct SD-JWT structure
- ✅ **Issuer JWT Signature** - Valid cryptographic signature
- ✅ **Issuer DID Resolution** - Issuer identity verified
- ✅ **Disclosure Decoding** - All disclosures properly decoded
- ✅ **Claim Extraction** - Claims added to credential subject
- ✅ **Key Binding JWT** - (Optional) Holder possession verified
- ✅ **Presentation Definition** - Required claims present
- ✅ **Expiration Check** - Credential not expired
- ✅ **Revocation Check** - (Optional) Credential not revoked

---

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| **Invalid SD-JWT format** | Missing `~` separator or malformed structure | Ensure token follows `<jwt>~<disc>~...` format |
| **SD-JWT issuer-signed part is not valid JWT** | First part is not a valid 3-part JWT | Verify issuer JWT has `header.payload.signature` |
| **Failed to parse SD-JWT credential** | Disclosure decoding failed | Check Base64url encoding of disclosures |
| **Invalid signature** | Issuer JWT signature verification failed | Verify issuer's public key and algorithm |
| **Failed to resolve issuer DID** | DID resolution error | Ensure issuer DID is resolvable |
| **Missing required claims** | Disclosures don't include required claims | Add necessary disclosures to SD-JWT |

### Error Response Example

```json
{
  "error": "invalid_vp_token",
  "error_description": "Invalid SD-JWT format: SD-JWT issuer-signed part is not valid JWT"
}
```

---

## Best Practices

### For Issuers

1. **Use Strong Algorithms** - Prefer EdDSA for new credentials
2. **Minimize Disclosures** - Only make necessary claims selectively disclosable
3. **Include Credential Status** - Enable revocation checking
4. **Set Expiration** - Include `exp` claim in issuer JWT
5. **Use Unique Salts** - Generate cryptographically random salts for each disclosure

### For Verifiers

1. **Validate Format** - Always check SD-JWT structure before processing
2. **Verify Signatures** - Don't skip signature verification
3. **Check Expiration** - Reject expired credentials
4. **Validate Claims** - Ensure all required claims are disclosed
5. **Handle Errors Gracefully** - Provide clear error messages

### For Wallet Developers

1. **Selective Disclosure UI** - Let users choose which claims to reveal
2. **Key Binding** - Include key binding JWT when required
3. **Format Correctly** - Ensure proper `~` separation
4. **Base64url Encoding** - Use URL-safe Base64 encoding for disclosures
5. **Test Thoroughly** - Verify SD-JWT generation with multiple verifiers

---

## Related Documentation

- [VP Token Processing](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/docs/vp_token_processing.md)
- [DID Handling](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/docs/did-handling.md)
- [Runtime Flows](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/docs/10-runtime-flows.md)
- [Feature Support](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation/docs/11-feature-support.md)

---

## References

- [SD-JWT Specification (IETF Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt)
- [OpenID4VP Specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
- [DID Core Specification](https://www.w3.org/TR/did-core/)
