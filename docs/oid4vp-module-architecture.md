# OID4VP Module Architecture

## Overview

The OpenID for Verifiable Presentations (OID4VP) implementation is organized into 4 modular components following a layered architecture pattern. This modular design ensures separation of concerns, reusability, and maintainability.

## Module Dependency Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                    oid4vp.presentation                      │
│         (Authenticator, Servlets, Business Logic)           │
└─────────────────────────────────────────────────────────────┘
                          ▲
                          │ depends on
                          │
┌─────────────────────────┴───────────────────────────────────┐
│                                                              │
│  ┌────────────────────┐        ┌─────────────────────────┐  │
│  │  oid4vp.did        │        │  oid4vp.verification    │  │
│  │  (DID Resolution)  │        │  (VC Verification)      │  │
│  └────────────────────┘        └─────────────────────────┘  │
│            ▲                              ▲                  │
│            │ depends on                   │ depends on       │
│            │                              │                  │
│  ┌─────────┴──────────────────────────────┴───────────────┐ │
│  │              oid4vp.common                             │ │
│  │  (Models, DTOs, Constants, Exceptions, Utilities)     │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## Module Descriptions

### 1. oid4vp.common (Foundation Layer)
**Package:** `org.wso2.carbon.identity.openid4vc.oid4vp.common`

**Purpose:** Provides shared kernel components used across all OID4VP modules.

**Dependencies:** None (base module)

**Contents:**
- **Models:** Domain entities (PresentationDefinition, VPRequest, DIDDocument, etc.)
- **DTOs:** Data transfer objects for API communication
- **Constants:** Configuration keys, endpoints, error codes, cache keys
- **Exceptions:** Custom exception hierarchy for error handling
- **Utilities:** Common helper functions (OpenID4VPUtil, QRCodeUtil, CORSUtil)

### 2. oid4vp.did (DID Layer)
**Package:** `org.wso2.carbon.identity.openid4vc.oid4vp.did`

**Purpose:** Handles DID (Decentralized Identifier) resolution and document management.

**Dependencies:** oid4vp.common

**Contents:**
- **DID Providers:** Support for did:web, did:key, did:jwk methods
- **DID Services:** Document generation, resolution, and validation
- **Key Management:** Ed25519 key generation and management
- **Utilities:** Cryptographic signing (BCEd25519Signer)

### 3. oid4vp.verification (Verification Layer)
**Package:** `org.wso2.carbon.identity.openid4vc.oid4vp.verification`

**Purpose:** Verifies Verifiable Credentials and Presentations.

**Dependencies:** oid4vp.common, oid4vp.did

**Contents:**
- **VC Verification:** JWT VC, JSON-LD VC, SD-JWT VC verification
- **Signature Verification:** Cryptographic signature validation
- **Status List Service:** Credential revocation checking
- **Trust Framework:** Trusted issuer validation

### 4. oid4vp.presentation (Application Layer)
**Package:** `org.wso2.carbon.identity.openid4vc.oid4vp.presentation`

**Purpose:** Implements the OpenID4VP verifier flow for WSO2 Identity Server.

**Dependencies:** oid4vp.common, oid4vp.did, oid4vp.verification

**Contents:**
- **Authenticator:** OpenID4VPAuthenticator (federated authenticator)
- **Servlets:** HTTP endpoints for VP requests, submissions, status checking
- **Services:** Business logic for VP flow orchestration
- **DAOs:** Database access for presentation definitions and VP requests
- **Caches:** In-memory caching for performance
- **Internal:** OSGi service components and data holders

## Module Interactions

### Data Flow Example: VP Authentication Flow

```
1. User initiates login
   ↓
2. OpenID4VPAuthenticator (presentation)
   ├→ Creates VP request using VPRequestService (presentation)
   │  ├→ Loads PresentationDefinition (common.model)
   │  ├→ Generates DID using DIDDocumentService (did)
   │  └→ Stores request in cache/database (presentation.dao)
   ↓
3. QR code generated with authorization request
   ↓
4. Wallet scans QR and submits VP
   ↓
5. VPSubmissionServlet (presentation)
   ├→ Validates submission using VPSubmissionValidator (common.util)
   ├→ Verifies VC using VCVerificationService (verification)
   │  ├→ Resolves issuer DID using DIDResolverService (did)
   │  └→ Checks signature using SignatureVerifier (verification)
   ├→ Extracts claims and creates authenticated user
   └→ Notifies status listeners via LongPollingManager (presentation)
```

## Cross-Module Communication

### Service Discovery
- **OSGi Services:** Components are registered and consumed via OSGi Declarative Services
- **Service References:** Modules declare dependencies through `@Reference` annotations
- **Loose Coupling:** Modules interact through interfaces, not implementations

### Data Sharing
- **Common Models:** All modules use shared models from oid4vp.common
- **DTOs:** Lightweight data transfer between layers
- **Exceptions:** Standardized error handling across all modules

### Configuration
- **Centralized Constants:** All configuration keys defined in oid4vp.common
- **Property Files:** Module-specific properties in resources
- **Cache Keys:** Standardized cache key naming

## Build and Deployment

### Compilation Order
1. `oid4vp.common` (no dependencies)
2. `oid4vp.did` (depends on common)
3. `oid4vp.verification` (depends on common, did)
4. `oid4vp.presentation` (depends on common, did, verification)

### OSGi Bundle Characteristics
- **Common:** Exports all packages (models, DTOs, constants, exceptions, utils)
- **DID:** Exports provider interfaces and services
- **Verification:** Exports verification service interfaces
- **Presentation:** Exports authenticator (as OSGi service)

### Deployment as Dropins
All modules are deployed as OSGi bundles in WSO2 IS dropins directory:
- `org.wso2.carbon.identity.openid4vc.oid4vp.common-1.0.0-SNAPSHOT.jar`
- `org.wso2.carbon.identity.openid4vc.oid4vp.did-1.0.0-SNAPSHOT.jar`
- `org.wso2.carbon.identity.openid4vc.oid4vp.verification-1.0.0-SNAPSHOT.jar`
- `org.wso2.carbon.identity.openid4vc.oid4vp.presentation-1.0.0-SNAPSHOT.jar`

## Benefits of Modular Architecture

1. **Separation of Concerns:** Each module has a single, well-defined responsibility
2. **Reusability:** Common module can be used by other components
3. **Testability:** Modules can be tested independently
4. **Maintainability:** Changes isolated to specific modules
5. **Scalability:** Easy to add new DID methods or verification algorithms
6. **Extensibility:** New modules can be added without affecting existing ones

## Version Compatibility

All modules share the same version: `1.0.0-SNAPSHOT`

Import-Package versions ensure compatibility:
- Common exports: `version="1.0.0.SNAPSHOT"`
- DID imports common: `version="1.0.0.SNAPSHOT"`
- Verification imports common + did: `version="1.0.0.SNAPSHOT"`
- Presentation imports all: `version="1.0.0.SNAPSHOT"`
