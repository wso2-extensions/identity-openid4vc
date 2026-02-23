# OID4VP DID Module — Overview

**Artifact:** `org.wso2.carbon.identity.openid4vc.oid4vp.did`  
**Package root:** `org.wso2.carbon.identity.openid4vc.oid4vp.did`  
**Packaging:** OSGi bundle  
**Java source level:** 21  
**Parent POM version:** `1.0.0-SNAPSHOT`

---

## 1. Purpose

This module provides **Decentralized Identifier (DID)** resolution, DID Document generation, and cryptographic key management for the OpenID4VP flow inside WSO2 Identity Server. When the IS acts as a **Verifier** it needs to:

1. **Present its own DID** — embed it in the VP Request JWT so wallets can verify the Verifier's identity.
2. **Serve a DID Document** — expose `/.well-known/did.json` for `did:web` resolution.
3. **Sign JWTs** — sign VP Request JWTs using the private key that corresponds to the public key published in the DID Document.
4. **Resolve a Holder's DID** — when a VP is submitted, resolve the holder's DID (any method) to extract the verification public key and validate the VP signature.

---

## 2. Module Structure

```
org.wso2.carbon.identity.openid4vc.oid4vp.did/
├── pom.xml
└── src/main/java/org/wso2/carbon/identity/openid4vc/oid4vp/did/
    ├── provider/                          ← DID method abstraction
    │   ├── DIDProvider.java               ← Interface
    │   ├── DIDProviderFactory.java        ← Static factory
    │   └── impl/
    │       ├── DIDJwkProvider.java         ← did:jwk  (Ed25519)
    │       ├── DIDKeyProvider.java         ← did:key  (Ed25519 / P-256)
    │       └── DIDWebProvider.java         ← did:web  (RS256 / EdDSA / ES256)
    ├── service/                           ← High-level service interfaces
    │   ├── DIDDocumentService.java        ← Manages the IS's own DID Doc
    │   ├── DIDResolverService.java        ← Resolves external DIDs
    │   └── impl/
    │       ├── DIDDocumentServiceImpl.java
    │       └── DIDResolverServiceImpl.java
    └── util/                              ← Crypto helpers
        ├── BCEd25519Signer.java           ← Bouncy Castle Ed25519 JWSSigner
        └── DIDKeyManager.java             ← Key storage, generation, encoding
```

---

## 3. Dependencies (pom.xml)

| Dependency | Purpose |
|---|---|
| `org.wso2.carbon.identity.openid4vc.oid4vp.common` | Shared models (`DIDDocument`, `VPException`, etc.) |
| `nimbus-jose-jwt` (WSO2 orbit) | JWK / JWS / JWT processing |
| `bcprov-jdk18on` 1.78 (Bouncy Castle) | Ed25519 signing without Google Tink |
| `org.wso2.carbon.core` | `KeyStoreManager` — access to the IS carbon keystore |
| `gson` | JSON serialisation of DID Documents |
| `commons-lang3` | String utilities |
| `slf4j-api` | Logging facade |
| `org.osgi.service.component.annotations` | OSGi Declarative Services |

### OSGi Bundle Configuration

```
Export-Package: org.wso2.carbon.identity.openid4vc.oid4vp.did.*
Import-Package: org.wso2.carbon.identity.openid4vc.oid4vp.common.*,
                org.osgi.service.component,
                *
DynamicImport-Package: *
```

The `DynamicImport-Package: *` is used so the bundle can pick up Bouncy Castle providers and other transient dependencies at runtime without compile-time wiring.

---

## 4. Supported DID Methods

| Method | Default Algorithm | Key Source | Persistence |
|---|---|---|---|
| `did:web` | RS256 (also EdDSA, ES256) | WSO2 Carbon KeyStore | Persistent (keystore) |
| `did:key` | EdDSA (also ES256) | KeyStore for Ed25519; in-memory for P-256 | Ed25519 persistent; P-256 ephemeral |
| `did:jwk` | EdDSA | KeyStore for Ed25519 | Persistent |

---

## 5. How It Fits Into the OID4VP Flow

```
┌──────────────────────┐      ┌────────────────────┐
│  Presentation Module │      │  Verification      │
│  (VP Request builder)│      │  Module             │
│                      │      │                     │
│ 1. asks DIDProvider  │      │ 4. asks Resolver    │
│    for signer + kid  │      │    to resolve       │
│                      │      │    holder DID       │
│ 2. signs VP Request  │      │                     │
│    JWT               │      │ 5. gets PublicKey   │
│                      │      │    from DID Doc     │
│ 3. includes          │      │                     │
│    "client_id" = DID │      │ 6. verifies VP      │
│    in request        │      │    signature        │
└──────────┬───────────┘      └──────────┬──────────┘
           │                             │
           ▼                             ▼
   ┌──────────────────────────────────────────┐
   │            DID Module (this module)       │
   │                                           │
   │  DIDProviderFactory ──► DIDProvider impls │
   │  DIDDocumentService ──► DID Doc JSON      │
   │  DIDResolverService ──► resolve(did)      │
   │  DIDKeyManager      ──► KeyStore / cache  │
   │  BCEd25519Signer    ──► sign bytes        │
   └───────────────────────────────────────────┘
```

---

## 6. Key Design Decisions

1. **Strategy Pattern for DID Methods** — `DIDProvider` interface + `DIDProviderFactory` allow adding new DID methods without modifying existing code.
2. **Bouncy Castle over Tink** — Nimbus JOSE's built-in `Ed25519Signer` requires Google Tink. `BCEd25519Signer` replaces it with a pure Bouncy Castle implementation, avoiding a heavy transitive dependency.
3. **KeyStore integration** — Ed25519 and RSA keys are persisted in the WSO2 Carbon KeyStore (JKS/PKCS12). P-256 keys are generated ephemerally and cached in a `ConcurrentHashMap`.
4. **In-memory caching** — `DIDKeyManager` caches key pairs per tenant. `DIDResolverServiceImpl` caches resolved DID Documents with a 1-hour TTL.
5. **Multi-algorithm support** — All providers accept an optional `algorithm` parameter so the same DID method can be used with different signing algorithms (e.g., `did:web` can use RS256, EdDSA, or ES256).

---

## 7. Quick Reference — Entry Points

| Use case | Class | Method |
|---|---|---|
| Get a DID provider | `DIDProviderFactory` | `getProvider("web" / "key" / "jwk")` |
| Generate DID Document JSON | `DIDDocumentServiceImpl` | `getDIDDocument(domain, tenantId)` |
| Resolve external DID | `DIDResolverServiceImpl` | `resolve(did)` |
| Get public key from DID | `DIDResolverServiceImpl` | `getPublicKey(did, keyId)` |
| Sign a JWT with Ed25519 | `BCEd25519Signer` | `sign(header, signingInput)` |
| Get tenant's Ed25519 key | `DIDKeyManager` | `getOrGenerateKeyPair(tenantId)` |
