# DID Well-Known Endpoint Implementation

## Overview
This implementation adds a `/.well-known/did.json` endpoint to WSO2 Identity Server's OpenID4VP component, enabling the server to publish its DID Document using the `did:web` method.

## Features

### 1. DID Document Service
- **DIDDocumentService** interface and **DIDDocumentServiceImpl** implementation
- Generates W3C-compliant DID Documents
- Supports `did:web` method for WSO2 Identity Server
- Tenant-aware key management

### 2. Key Management
- **DIDKeyManager** utility for cryptographic key operations
- Automatically generates ES256 (P-256) key pairs per tenant
- In-memory key caching for performance
- JWK (JSON Web Key) format support

### 3. Well-Known Endpoint
- **WellKnownDIDServlet** serves `/.well-known/did.json`
- CORS support for cross-origin requests
- Multi-tenant support (currently defaults to super tenant)
- Content-Type: `application/did+json`

## Files Created

```
src/main/java/org/wso2/carbon/identity/openid4vc/presentation/
├── service/
│   └── DIDDocumentService.java                    # Service interface
├── service/impl/
│   └── DIDDocumentServiceImpl.java                # Implementation
├── util/
│   └── DIDKeyManager.java                         # Key management utility
├── servlet/
│   └── WellKnownDIDServlet.java                   # Well-known endpoint servlet
└── exception/
    └── DIDDocumentException.java                  # Custom exception

src/main/webapp/WEB-INF/
└── web.xml                                        # Servlet registration (modified)
```

## DID Format

The DID identifier follows the `did:web` specification:

- **Standard HTTP**: `did:web:example.com`
- **With Port**: `did:web:localhost%3A9443` (port encoded as `%3A`)
- **With Path**: `did:web:example.com:path:to:service`

## DID Document Structure

Example DID Document returned by `/.well-known/did.json`:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:web:localhost%3A9443",
  "verificationMethod": [
    {
      "id": "did:web:localhost%3A9443#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:web:localhost%3A9443",
      "publicKeyJwk": {
        "kty": "EC",
        "kid": "key-1",
        "use": "sig",
        "crv": "P-256",
        "x": "...",
        "y": "..."
      }
    }
  ],
  "authentication": [
    "did:web:localhost%3A9443#key-1"
  ],
  "assertionMethod": [
    "did:web:localhost%3A9443#key-1"
  ]
}
```

## API Endpoints

### GET /.well-known/did.json

Returns the DID Document for the current WSO2 IS instance.

**Request:**
```bash
curl https://localhost:9443/.well-known/did.json
```

**Response:**
- **Status**: 200 OK
- **Content-Type**: `application/did+json;charset=UTF-8`
- **Body**: DID Document (JSON)

**Error Responses:**
- **500 Internal Server Error**: Failed to generate DID document

## Integration Points

### VPServiceDataHolder
Updated to include `DIDDocumentService`:

```java
public DIDDocumentService getDIDDocumentService() {
    if (didDocumentService == null) {
        didDocumentService = new DIDDocumentServiceImpl();
    }
    return didDocumentService;
}
```

### Web Configuration
Servlet mapping added to `web.xml`:

```xml
<servlet>
    <servlet-name>WellKnownDIDServlet</servlet-name>
    <servlet-class>org.wso2.carbon.identity.openid4vc.presentation.servlet.WellKnownDIDServlet</servlet-class>
    <load-on-startup>1</load-on-startup>
</servlet>

<servlet-mapping>
    <servlet-name>WellKnownDIDServlet</servlet-name>
    <url-pattern>/.well-known/did.json</url-pattern>
</servlet-mapping>
```

## Usage

### Testing the Endpoint

1. **Start WSO2 Identity Server** with the updated component

2. **Access the DID Document**:
   ```bash
   curl https://localhost:9443/.well-known/did.json
   ```

3. **Verify DID Resolution** (from external resolver):
   ```bash
   # Using a DID resolver
   did-resolver resolve did:web:localhost%3A9443
   ```

### Using in OpenID4VP

The DID Document can be used by:
- **Verifiers** to discover WSO2 IS public keys
- **Wallets** to verify VP presentation requests signed by WSO2 IS
- **External systems** needing to validate signatures from WSO2 IS

## Security Considerations

1. **Key Management**:
   - Keys are currently stored in-memory and regenerated on server restart
   - For production, consider persisting keys or integrating with WSO2 keystore

2. **CORS**:
   - Currently allows all origins (`*`)
   - Restrict to specific domains in production

3. **HTTPS**:
   - `did:web` requires HTTPS in production
   - Ensure proper SSL/TLS configuration

## Future Enhancements

1. **Key Persistence**:
   - Store keys in database or WSO2 keystore
   - Support key rotation

2. **Multi-Tenant Support**:
   - Extract tenant from request context
   - Generate tenant-specific DIDs

3. **Multiple Key Types**:
   - Support RSA keys
   - Support Ed25519 keys

4. **DID Method Support**:
   - Add support for `did:jwk`
   - Add support for `did:key`

5. **Admin API**:
   - Endpoint to regenerate keys
   - Endpoint to manage DID document metadata

## Build & Deployment

### Build
```bash
cd /path/to/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation
mvn clean install -DskipTests
```

### Deploy
Copy the generated JAR to WSO2 IS dropins:
```bash
cp target/org.wso2.carbon.identity.openid4vc.presentation-1.0.0-SNAPSHOT.jar \
   <WSO2_IS_HOME>/repository/components/dropins/
```

Restart WSO2 Identity Server.

## Compliance

- **W3C DID Core Specification**: https://www.w3.org/TR/did-core/
- **DID Web Method Specification**: https://w3c-ccg.github.io/did-method-web/
- **JSON Web Key (JWK)**: RFC 7517
- **Elliptic Curve Cryptography**: NIST P-256 (secp256r1)

## Dependencies

No additional dependencies required. Uses:
- Java Security API for key generation
- Gson for JSON serialization
- Javax Servlet API

## License

Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com)
Licensed under Apache License 2.0
