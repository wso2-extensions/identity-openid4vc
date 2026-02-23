# Flows & Sequence Diagrams

This document traces the end-to-end flows through the DID module.

---

## Flow 1 — Serving the Verifier's DID Document (`did:web`)

**Trigger:** HTTP GET `https://is.example.com/.well-known/did.json`

```
┌──────┐          ┌───────────┐       ┌──────────────────┐      ┌──────────┐      ┌──────────────┐
│Wallet│          │DID Servlet│       │DIDDocumentService│      │DIDWebProv│      │KeyStoreManager│
└──┬───┘          └─────┬─────┘       └────────┬─────────┘      └────┬─────┘      └──────┬───────┘
   │  GET /did.json     │                      │                      │                    │
   │───────────────────►│                      │                      │                    │
   │                    │ getDIDDocument(       │                      │                    │
   │                    │   domain, tenantId)   │                      │                    │
   │                    │─────────────────────►│                      │                    │
   │                    │                      │ getProvider("web")   │                    │
   │                    │                      │─────────────────────►│                    │
   │                    │                      │                      │                    │
   │                    │                      │ getDIDDocument(      │                    │
   │                    │                      │   tenantId, domain)  │                    │
   │                    │                      │─────────────────────►│                    │
   │                    │                      │                      │                    │
   │                    │                      │     ┌────────────────┤ [RSA key]          │
   │                    │                      │     │ getDefaultPrimaryCertificate()      │
   │                    │                      │     │────────────────────────────────────►│
   │                    │                      │     │◄────────────────────────────────────│
   │                    │                      │     │                 │                    │
   │                    │                      │     │ [EdDSA key]    │                    │
   │                    │                      │     │ getDefaultPublicKey("wso2carbon_ed")│
   │                    │                      │     │────────────────────────────────────►│
   │                    │                      │     │◄────────────────────────────────────│
   │                    │                      │     │                 │                    │
   │                    │                      │     │ [P-256 key]    │                    │
   │                    │                      │     │ getOrGenerateECKeyPair() [ephemeral]│
   │                    │                      │     └────────────────┤                    │
   │                    │                      │                      │                    │
   │                    │                      │◄─────────────────────│ DIDDocument        │
   │                    │                      │                      │ (3 verif methods)  │
   │                    │                      │                      │                    │
   │                    │ convertToJson(doc)   │                      │                    │
   │                    │◄─────────────────────│                      │                    │
   │                    │                      │                      │                    │
   │◄───────────────────│ JSON response        │                      │                    │
   │  application/json  │                      │                      │                    │
```

---

## Flow 2 — Signing a VP Request JWT

**Trigger:** The presentation module creates a VP Request to send to a wallet.

```
┌──────────────┐    ┌─────────────────┐    ┌─────────────┐    ┌──────────────┐    ┌───────────────┐
│VP Request    │    │DIDProviderFactory│    │DIDWebProvider│    │DIDKeyManager │    │BCEd25519Signer│
│Builder       │    │                  │    │              │    │              │    │               │
└──────┬───────┘    └────────┬─────────┘    └──────┬───────┘    └──────┬───────┘    └───────┬───────┘
       │                     │                      │                   │                    │
       │ getProvider("web")  │                      │                   │                    │
       │────────────────────►│                      │                   │                    │
       │◄────────────────────│ DIDWebProvider       │                   │                    │
       │                     │                      │                   │                    │
       │ getDID(tid, baseUrl)│                      │                   │                    │
       │─────────────────────────────────────────►  │                   │                    │
       │◄──────────────────────────────────────────│ "did:web:..."     │                    │
       │                     │                      │                   │                    │
       │ getSigningKeyId(tid, baseUrl, "EdDSA")    │                   │                    │
       │─────────────────────────────────────────►  │                   │                    │
       │◄──────────────────────────────────────────│ "did:web:...#ed25519"                  │
       │                     │                      │                   │                    │
       │ getSigningAlgorithm("EdDSA")              │                   │                    │
       │─────────────────────────────────────────►  │                   │                    │
       │◄──────────────────────────────────────────│ JWSAlgorithm.EdDSA│                    │
       │                     │                      │                   │                    │
       │ getSigner(tid, "EdDSA")                   │                   │                    │
       │─────────────────────────────────────────►  │                   │                    │
       │                     │                      │ getEdDSAKeyAlias()│                    │
       │                     │                      │──────────────────►│                    │
       │                     │                      │ convertToOctetKeyPair()               │
       │                     │                      │──────────────────►│                    │
       │                     │                      │◄─────────────────│ OctetKeyPair       │
       │                     │                      │                   │                    │
       │                     │                      │ new BCEd25519Signer(keyPair)           │
       │                     │                      │───────────────────────────────────────►│
       │◄──────────────────────────────────────────│ JWSSigner          │                    │
       │                     │                      │                   │                    │
       │ Build JWSHeader(EdDSA, kid="...#ed25519") │                   │                    │
       │ signer.sign(header, payload)              │                   │                    │
       │───────────────────────────────────────────────────────────────────────────────────►│
       │◄──────────────────────────────────────────────────────────────────────────────────│
       │ Base64URL signature  │                      │                   │                    │
       │                     │                      │                   │                    │
       │ Assemble JWT: header.payload.signature    │                   │                    │
```

---

## Flow 3 — Resolving a Holder's DID for VP Verification

**Trigger:** The verification module receives a VP and needs to verify the holder's signature.

```
┌────────────────┐    ┌──────────────────┐    ┌──────────────────────────────────┐
│Verification    │    │DIDResolverService│    │  Resolution (method-specific)     │
│Module          │    │Impl              │    │                                   │
└───────┬────────┘    └────────┬─────────┘    └────────────────┬─────────────────┘
        │                      │                                │
        │ resolve("did:key:z6Mk...")                            │
        │─────────────────────►│                                │
        │                      │ Check cache → miss             │
        │                      │ getMethod() → "key"            │
        │                      │                                │
        │                      │ resolveDidKey(did)             │
        │                      │───────────────────────────────►│
        │                      │  1. Extract "z6Mk..." after    │
        │                      │     "did:key:"                 │
        │                      │  2. Strip 'z' prefix           │
        │                      │  3. Base58 decode              │
        │                      │  4. Read multicodec: 0xed01    │
        │                      │     → Ed25519                  │
        │                      │  5. Build DIDDocument with     │
        │                      │     Ed25519VerificationKey2020 │
        │                      │◄───────────────────────────────│
        │                      │                                │
        │                      │ Cache document (1hr TTL)       │
        │◄─────────────────────│ DIDDocument                    │
        │                      │                                │
        │ getPublicKey(did,    │                                │
        │   "did:key:z6Mk...#z6Mk...")                         │
        │─────────────────────►│                                │
        │                      │ resolve(did) → cache hit       │
        │                      │ findVerificationMethod(keyId)  │
        │                      │ extractPublicKey(method)       │
        │                      │   → multibaseToPublicKey()     │
        │                      │     → base58Decode + strip     │
        │                      │       multicodec               │
        │                      │     → OctetKeyPair.Builder()   │
        │                      │       .toPublicKey()           │
        │◄─────────────────────│ PublicKey (Ed25519)            │
        │                      │                                │
        │ Verify VP signature  │                                │
        │ using PublicKey      │                                │
```

---

## Flow 4 — Resolving `did:web` (Network Fetch)

```
┌─────────────────┐    ┌───────────────────┐    ┌──────────────────┐
│DIDResolverService│    │ HttpURLConnection │    │ External Server  │
│Impl              │    │                   │    │ (wallet's domain)│
└────────┬─────────┘    └─────────┬─────────┘    └────────┬─────────┘
         │                        │                        │
         │ resolveDidWeb(         │                        │
         │   "did:web:wallet.io") │                        │
         │                        │                        │
         │ Convert to URL:        │                        │
         │ https://wallet.io/     │                        │
         │   .well-known/did.json │                        │
         │                        │                        │
         │ fetchUrl(url)          │                        │
         │───────────────────────►│                        │
         │                        │ GET /.well-known/      │
         │                        │   did.json             │
         │                        │───────────────────────►│
         │                        │                        │
         │                        │◄───────────────────────│
         │                        │ 200 OK                 │
         │                        │ {"id":"did:web:...",   │
         │                        │  "verificationMethod": │
         │                        │  [...]}                │
         │◄───────────────────────│                        │
         │ JSON string            │                        │
         │                        │                        │
         │ parseDIDDocument(      │                        │
         │   did, json)           │                        │
         │  → DIDDocument with    │                        │
         │    all verification    │                        │
         │    methods parsed      │                        │
```

### URL Construction Rules

| DID | Resolved URL |
|---|---|
| `did:web:example.com` | `https://example.com/.well-known/did.json` |
| `did:web:example.com%3A9443` | `https://example.com:9443/.well-known/did.json` |
| `did:web:example.com:path:to:did` | `https://example.com/path/to/did/did.json` |

---

## Flow 5 — Resolving `did:jwk` (Self-Contained)

```
resolve("did:jwk:eyJrdHkiOiJPS1Ai...")

1. Extract Base64URL part: "eyJrdHkiOiJPS1Ai..."
2. Base64URL decode → {"kty":"OKP","crv":"Ed25519","x":"..."}
3. Create DIDDocument:
   - id = the full DID
   - verificationMethod[0]:
     - id = did + "#0"
     - type = "JsonWebKey2020"
     - publicKeyJwk = decoded JWK
   - authentication = [did + "#0"]
   - assertionMethod = [did + "#0"]
```

No network call needed. The public key is fully embedded in the DID string.

---

## Key Lifecycle Summary

```
                     Server Start
                          │
                          ▼
              ┌───────────────────────┐
              │  KeyStore loaded      │
              │  (wso2carbon.jks)     │
              │                       │
              │  Contains:            │
              │  - RSA key (default)  │
              │  - Ed25519 key        │
              │    (wso2carbon_ed)    │
              └───────────┬───────────┘
                          │
            First DID operation for tenant
                          │
                          ▼
              ┌───────────────────────┐
              │  DIDKeyManager        │
              │                       │
              │  1. Fetch from KS     │
              │  2. Convert format    │
              │  3. Cache in HashMap  │
              │                       │
              │  P-256: generate new  │
              │  (no KS, ephemeral)   │
              └───────────┬───────────┘
                          │
              Subsequent operations
                          │
                          ▼
              ┌───────────────────────┐
              │  Served from cache    │
              │  (ConcurrentHashMap)  │
              │                       │
              │  No KS access needed  │
              └───────────────────────┘
                          │
              Server restart / regenerateKeys()
                          │
                          ▼
              ┌───────────────────────┐
              │  Cache cleared        │
              │  Next request re-     │
              │  fetches from KS      │
              │                       │
              │  P-256 key changes!   │
              └───────────────────────┘
```
