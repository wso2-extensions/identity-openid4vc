# Code Review Guide — `oid4vp.did` Module

This document highlights design decisions, potential issues, and areas to discuss during code review.

---

## 1. Architecture & Design

### ✅ Strengths

| Aspect | Notes |
|---|---|
| **Strategy pattern** | `DIDProvider` interface + factory cleanly separates DID method concerns |
| **Default method overloads** | Algorithm-aware `default` methods in `DIDProvider` provide backward compatibility |
| **Bouncy Castle signer** | `BCEd25519Signer` avoids Google Tink dependency — pragmatic choice for WSO2 IS runtime |
| **KeyStore integration** | Ed25519 keys are persisted in the Carbon keystore — survives restarts |
| **Caching** | Both `DIDKeyManager` (key cache) and `DIDResolverServiceImpl` (document cache) use `ConcurrentHashMap` |

### ⚠️ Discussion Points

| Item | File | Details |
|---|---|---|
| **Singleton providers** | `DIDProviderFactory` | Providers are stateless singletons in a plain `HashMap`. The static initialiser is safe, but there's no way to register custom providers at runtime (e.g., via OSGi). Consider whether a `ServiceTracker` or DS component approach is needed. |
| **No interface for DIDKeyManager** | `DIDKeyManager` | All methods are static. This makes unit testing difficult — you can't mock the key manager. Consider extracting an interface and injecting it. |
| **Service implementations not registered as OSGi services** | `DIDDocumentServiceImpl`, `DIDResolverServiceImpl` | Despite the OSGi annotations dependency in `pom.xml`, neither service implementation uses `@Component` / `@Service`. They appear to be instantiated directly. Confirm whether this is intentional or if they should be proper OSGi DS components. |

---

## 2. Security Considerations

### 🔴 Critical Items

| Issue | File | Line Area | Details |
|---|---|---|---|
| **Silent exception swallowing** | `DIDWebProvider.getDIDDocument()` | RSA/EdDSA/ES256 blocks | Each key-type block has `catch (Exception e) {}` with no logging. If the KeyStore is misconfigured, the DID Document silently omits key types with no diagnostic output. At minimum, log at `DEBUG` level. |
| **No TLS certificate pinning** | `DIDResolverServiceImpl.fetchUrl()` | HTTP fetch | `did:web` resolution uses default `HttpURLConnection` with no custom `TrustManager`. In production, consider certificate validation or at least logging the remote certificate chain. |
| **SSRF potential** | `DIDResolverServiceImpl.fetchUrl()` | URL construction | The `did:web` resolver constructs URLs from DID identifiers. A malicious DID like `did:web:localhost` or `did:web:169.254.169.254` could trigger internal network requests. The `@SuppressFBWarnings("URLCONNECTION_SSRF_FD")` annotation acknowledges this. Consider adding a URL allowlist or blocking private IP ranges. |

### 🟡 Moderate Items

| Issue | File | Details |
|---|---|---|
| **Raw byte slicing for key extraction** | `DIDKeyManager.convertToOctetKeyPair()` | Extracts the last 32 bytes from PKCS#8/X.509 encoded keys. This assumes standard encoding from Java 15+ or Bouncy Castle. A more robust approach would parse the ASN.1 structure using `PrivateKeyInfo` / `SubjectPublicKeyInfo`. |
| **P-256 keys are ephemeral** | `DIDKeyManager.getOrGenerateECKeyPair()` | P-256 keys exist only in memory and change on every server restart. Any `did:key` with ES256 or `did:web` with ES256 verification method will be invalid after restart. Document this limitation or implement persistence. |
| **No input validation on `baseUrl`** | `DIDWebProvider.getDID()` | Only checks for null/empty. Doesn't validate the URL format, which could produce malformed DIDs. |

---

## 3. Error Handling

| Pattern | Files | Assessment |
|---|---|---|
| Empty catch blocks | `DIDWebProvider.getDIDDocument()` | 🔴 Should at least log. Key generation failures will silently produce incomplete DID Documents. |
| `@SuppressFBWarnings("REC_CATCH_EXCEPTION")` | Multiple files | Used where broad `catch (Exception e)` is intentional. Each usage should be reviewed for whether a more specific exception type would be better. |
| `VPException` vs `DIDDocumentException` vs `DIDResolutionException` | Throughout | Three different exception hierarchies are used. `DIDResolutionException extends VPException`, but `DIDDocumentException extends Exception` directly. Consider unifying under `VPException`. |
| Factory methods on `DIDResolutionException` | `DIDResolverServiceImpl` | Good pattern — `invalidFormat()`, `unsupportedMethod()`, `networkError()`, `keyNotFound()`, `invalidDocument()` provide clear error categorisation. |

---

## 4. Code Duplication

| Duplicated Code | Location 1 | Location 2 | Recommendation |
|---|---|---|---|
| `base58Encode()` | `DIDWebProvider` (private) | `DIDKeyManager` (private static) | Extract to a shared `Base58Util` class |
| `base58Decode()` | `DIDResolverServiceImpl` (private) | `DIDKeyManager` (public static) | Extract to a shared `Base58Util` class |
| `divmod()` helper | `DIDWebProvider` (private) | `DIDKeyManager` (private static) | Part of Base58 — would be extracted together |
| `convertPublicKeyToMultibase()` | `DIDWebProvider` (private) | `DIDKeyManager.publicKeyToMultibase()` | Use `DIDKeyManager` from `DIDWebProvider` |

**Impact:** If a bug is found in base58 encoding, it must be fixed in 3 places.

---

## 5. Thread Safety

| Component | Thread Safety | Notes |
|---|---|---|
| `DIDProviderFactory.providers` | ✅ Safe | `HashMap` written only in static init, read-only after |
| `DIDKeyManager.keyCache` | ✅ Safe | `ConcurrentHashMap` |
| `DIDKeyManager.ecKeyCache` | ✅ Safe | `ConcurrentHashMap` |
| `DIDResolverServiceImpl.cache` | ✅ Safe | `ConcurrentHashMap` |
| `BCEd25519Signer.privateKey` | ✅ Safe | Immutable `final` field set in constructor |
| `DIDKeyManager.getOrGenerateKeyPair()` | ⚠️ Race condition | Two threads could both miss the cache and both call `KeyStoreManager`. Both would succeed and the second would overwrite the first in cache — no corruption, but redundant work. Consider `computeIfAbsent()`. |
| `DIDKeyManager.getOrGenerateECKeyPair()` | ⚠️ Same race | Same pattern — two threads could generate two different P-256 keys. The second one wins. |

---

## 6. Testing Considerations

| Area | Testability | Suggestion |
|---|---|---|
| `DIDProvider` implementations | Medium | `DIDJwkProvider` and `DIDKeyProvider` can be tested if `DIDKeyManager` is mockable. Currently requires a real KeyStore. |
| `DIDWebProvider` | Low | Depends on `KeyStoreManager.getInstance()` — a static method tied to Carbon runtime. Consider a wrapper. |
| `DIDResolverServiceImpl` | Medium | `resolveDidWeb()` makes HTTP calls. Could extract `fetchUrl()` into an injectable HTTP client. `resolveDidJwk()` and `resolveDidKey()` are pure functions and highly testable. |
| `BCEd25519Signer` | High | Accepts `OctetKeyPair` — can be constructed with test keys. Verify signature output against known test vectors. |
| `DIDKeyManager` | Low | Heavy static method usage + `KeyStoreManager` dependency. Would need PowerMock or refactoring to test. |

---

## 7. Spec Compliance

| Specification | Status | Notes |
|---|---|---|
| [W3C DID Core](https://www.w3.org/TR/did-core/) | ✅ Mostly compliant | DID Document structure follows spec. Missing: `created`/`updated` metadata, `deactivated` status. |
| [did:web Method](https://w3c-ccg.github.io/did-method-web/) | ✅ Compliant | URL construction follows spec. Port encoding uses `%3A`. |
| [did:key Method](https://w3c-ccg.github.io/did-method-key/) | ✅ Compliant | Multibase + multicodec encoding follows spec for Ed25519 and P-256. |
| [did:jwk Method](https://github.com/nicosResworking/did-method-jwk) | ✅ Compliant | Base64URL JWK encoding, `#0` fragment convention. |
| [Multibase](https://www.w3.org/TR/controller-document/#multibase-0) | ✅ | Uses `z` prefix (base58btc). |
| [Multicodec](https://github.com/multiformats/multicodec) | ✅ | Ed25519: `0xed01`, P-256: `0x1200` (varint `0x80 0x24`). |

---

## 8. Performance

| Operation | Cost | Caching |
|---|---|---|
| Key retrieval (Ed25519/RSA) | KeyStore I/O on first call | `ConcurrentHashMap` — O(1) after first call |
| P-256 key generation | CPU: EC key gen (~1ms) | Cached per tenant until restart |
| `did:web` resolution | Network: HTTPS GET (up to 10s timeout) | 1-hour TTL |
| `did:jwk` / `did:key` resolution | CPU only: Base64/Base58 decode | 1-hour TTL |
| DID Document generation | Depends on key retrieval | Not cached (generated per request) |
| Base58 encode/decode | CPU: O(n²) for input length n | No caching |

**Potential improvement:** Cache the generated DID Document in `DIDDocumentServiceImpl` since it only changes when keys change.

---

## 9. Missing Functionality

| Feature | Impact | Priority |
|---|---|---|
| **Persistent P-256 keys** | ES256 verification methods break after restart | Medium |
| **Cache eviction thread** | Expired cache entries stay in memory until next access | Low |
| **DID Document versioning** | No way to track document changes over time | Low |
| **Key rotation support** | No mechanism to rotate keys and update DID Document atomically | Medium |
| **did:web path-based DIDs** | IS only supports domain-level `did:web`, not path-based (`did:web:example.com:department:hr`) | Low |
| **Rate limiting on resolution** | `resolveDidWeb()` has no rate limiting — could be abused to make outbound requests | Medium |
| **Metrics / observability** | No counters for resolution attempts, cache hits/misses, signing operations | Low |

---

## 10. Checklist for Reviewer

- [ ] Verify Ed25519 key alias (`wso2carbon_ed`) exists in the default keystore or is documented as a setup prerequisite
- [ ] Confirm `DynamicImport-Package: *` is acceptable per project OSGi guidelines
- [ ] Check if the `@SuppressFBWarnings` annotations are justified for each usage
- [ ] Validate that `BCEd25519Signer` produces correct signatures against Ed25519 test vectors
- [ ] Confirm `DIDResolverServiceImpl.generateEd25519KeyPair()` static method is intended to be public (appears unused/misplaced)
- [ ] Review whether `DIDDocumentException` should extend `VPException` for consistency
- [ ] Assess SSRF risk in `did:web` resolution for the deployment environment
- [ ] Verify multicodec varint encoding for P-256 (`0x80 0x24` = `0x1200`) against the multicodec table
- [ ] Check that `convertToOctetKeyPair()` byte slicing works with the actual keystore key format in use
- [ ] Confirm that ephemeral P-256 keys are acceptable for the current use cases
