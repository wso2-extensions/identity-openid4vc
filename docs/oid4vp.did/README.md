# OID4VP DID Module

**Package:** `org.wso2.carbon.identity.openid4vc.oid4vp.did`

## Purpose

Handles Decentralized Identifier (DID) resolution, document generation, and key management. Supports multiple DID methods.

**Dependencies:** `oid4vp.common`

## Supported DID Methods

| Method | Class | Description |
|--------|-------|-------------|
| `did:web` | `DIDWebProvider` | Web-based DID using hosted `did.json` |
| `did:key` | `DIDKeyProvider` | Self-contained DID with embedded public key |
| `did:jwk` | `DIDJwkProvider` | JWK-based DID with embedded JWK |

## Package Structure

| Package | Description |
|---------|-------------|
| `provider` | DID provider interface and factory |
| `provider.impl` | Concrete DID method implementations |
| `service` | DID document and resolution services |
| `service.impl` | Service implementations |
| `util` | Key management and cryptographic utilities |

## Key Classes

### DID Provider Layer
- **`DIDProvider`** – Interface for DID method implementations
- **`DIDProviderFactory`** – Factory that returns the correct provider based on DID method string

### Services
- **`DIDDocumentService`** – Generates DID documents with verification methods
- **`DIDResolverService`** – Resolves external DIDs to DID Documents (for signature verification)

### Key Management
- **`DIDKeyManager`** – Ed25519 key pair generation and storage using Bouncy Castle
- **`BCEd25519Signer`** – Custom JWT signer using Bouncy Castle Ed25519 (avoids Tink dependency issues)

## Configuration

In `deployment.toml`:
```toml
[openid4vp]
did_method = "did:key"          # or "did:web", "did:jwk"
signing_algorithm = "EdDSA"     # Default signing algorithm
```

## Usage Example

```
DIDProviderFactory.getProvider("did:key")
    → DIDKeyProvider
    → Generates Ed25519 key pair
    → Creates DID document with verificationMethod
    → Signs VP request JWT with BCEd25519Signer
```
