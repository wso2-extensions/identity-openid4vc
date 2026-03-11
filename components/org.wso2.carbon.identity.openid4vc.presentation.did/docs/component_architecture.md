# DID Component Architecture (`org.wso2.carbon.identity.openid4vc.presentation.did`)

This document explains the architecture, purpose, and integration flows of the DID (Decentralized Identifier) component within the WSO2 OpenID4VC implementation. It is intended to provide a comprehensive understanding for developers and reviewers.

## 1. Overview and Purpose (Why)
The DID component is responsible for managing the DID lifecycle within the OpenID4VP (Verifiable Presentation) flow. In the verifiable credentials ecosystem, entities must be identifiable and their cryptographic keys must be discoverable. The primary responsibilities of this component include:

- **Acting as a Verifier/Relying Party (RP):** Providing the WSO2 Identity Server's own DID Document to external wallets. This allows wallets to verify the RP's identity or encrypt responses intended for the RP.
- **Resolving External DIDs:** Fetching and cryptographically resolving DIDs presented by Digital Wallets (within Verifiable Presentations) and Issuers (within Verifiable Credentials) into standard Java `PublicKey` objects for signature validation.

## 2. Core Method Support
The component primarily revolves around the **`did:web`** method. All internal generations of the identity server's DID default to `did:web`. The resolver is implemented to parse `did:web` identifiers, fetching the corresponding `did.json` over HTTPS.

## 3. Internal Component Structure (How)

The internal logic is divided into four main packages: `provider`, `service`, `util`, and their respective `impl` (implementation) sub-packages.

### A. DID Provider (`provider` package)
- **`DIDProvider` (Interface):** Defines the strict contract for providing DID identifiers, retrieving generating DID Documents, and sourcing signing keys.
- **`DIDProviderFactory`:** A registry and factory for managing DID methods. It defaults to the `web` method (`did:web`).
- **`DIDWebProvider`:** The concrete implementation for the `did:web` method.
  - **Logic:** Derives the DID dynamically from the server's base URL (e.g., `did:web:example.com`).
  - **Key Management:** Integrates with WSO2's `KeyStoreManager` (via `KeyStoreUtil`) to fetch the tenant-specific EdDSA (Ed25519) key pair.
  - **Document Generation:** Constructs a standard W3C DID Document. It converts the Java `PublicKey` into a multibase format (`z...`) and embeds it within the `Ed25519VerificationKey2020` verification method type.

### B. DID Document Service (`service` package)
- **`DIDDocumentService` & `DIDDocumentServiceImpl`:**
  - Provides a higher-level abstraction to get the server's DID or DID Document payload as a JSON string.
  - Relies on the `DIDProviderFactory` to fetch the `DIDWebProvider` and format the constructed `DIDDocument` object into a strictly W3C-compliant JSON structure.

### C. DID Resolver Service (`service` package)
- **`DIDResolverService` & `DIDResolverServiceImpl`:**
  - Takes an external DID (e.g., `did:web:wallet.example.com`) and resolves it to a parsed `DIDDocument`.
  - **Network Resolution:** For `did:web`, it translates the identifier into an HTTPS URL (e.g., `https://wallet.example.com/.well-known/did.json` or `https://wallet.example.com/path/did.json`) and fetches the JSON directly over the network.
  - **Key Extraction:** Offers `getPublicKey(did, keyId)` and `getPublicKeyFromReference(verificationMethodRef)`. It traverses the resolved DID Document arrays, finds the requested Verification Method, and converts the raw key material (whether JWK, Multibase, or Base58) into standard Java `PublicKey` instances (RSA, EC, or Ed25519).
  - **Caching:** Utilizes an in-memory `ConcurrentHashMap` cache with a TTL (Time To Live, defaulted to 1 hour) to mitigate repetitive and expensive network calls for frequently seen DIDs.

### D. Utilities (`util` package)
- **`BCEd25519Signer`:** A customized `JWSSigner` implementation explicitly for Ed25519 signatures. It directly interfaces with the Bouncy Castle cryptography library (`Ed25519Signer`). This custom implementation deliberately avoids leveraging Google Tink (the default for `nimbus-jose-jwt` Ed25519 processing) to reduce heavy/conflicting dependencies while maintaining strict Nimbus JOSE + JWT compatibility.

---

## 4. Cross-Component Flow (Integration)

The DID component does not operate in a vacuum. It acts as the anchor of trust for cryptographic validations across the OpenID4VP workflow. Below are the specific integration points with other components:

### A. Exposing the Server's DID (Integration with `presentation.authenticator`)
1. **Scenario:** An external wallet needs to discover the Identity Server's keys during an OpenID4VP authorization request to verify the server or encrypt a response. To do this, it queries the `/.well-known/did.json` endpoint.
2. **Flow:**
   - The `org.wso2.carbon.identity.openid4vc.presentation.authenticator` component registers a `WellKnownDIDServlet` mapped to this endpoint.
   - The Servlet invokes `DIDDocumentService.getDIDDocument(domain, tenantId)`.
   - The DID component uses `DIDWebProvider` to look up the tenant's Keystore, grabs the Ed25519 public key, and formats the `did:web` JSON document, sending it back to the wallet.

### B. Verifying Wallet Submissions (Integration with `presentation.authenticator`)
1. **Scenario:** The wallet submits a Verifiable Presentation (VP) Token. The Relying Party (RP) must cryptographically verify that this VP token was truly signed by the wallet's private key.
2. **Flow:**
   - The request hits the `presentation.authenticator` component, which utilizes a `SignatureVerifier` utility.
   - The verifier extracts the `kid` (Key ID, typically a full verification method reference like `did:web:wallet.com#key-1`) from the header of the VP JWT.
   - The verifier passes this reference to `DIDResolverService.getPublicKeyFromReference(kid)`.
   - The DID component accesses the network, fetches the wallet's DID Document, parses out the exact public key tied to that signature, and passes it back to the Authenticator to complete the JWT validation.

### C. Verifying Issuer Credentials (Integration with `presentation.verification`)
1. **Scenario:** Inside a successfully verified VP token, there are one or more Verifiable Credentials (VCs). To trust these VCs, the server must verify the original Issuer's signature on each credential.
2. **Flow:**
   - The `org.wso2.carbon.identity.openid4vc.presentation.verification` component takes over via `VCVerificationServiceImpl`.
   - It extracts the `iss` (Issuer DID) claim from the VC payload.
   - It invokes `DIDResolverService.getPublicKey(issuerDid, keyId)`.
   - The DID component resolves the Issuer's DID Document, extracts the issuer's public key, and returns it to the Verification component, which subsequently executes the cryptographic proof validation on the VC.
