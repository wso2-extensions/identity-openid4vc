# OpenID4VP Documentation Index

## WSO2 Identity Server - OpenID4VP Component

This documentation provides comprehensive coverage of the OpenID4VP (OpenID for Verifiable Presentations) implementation.

---

## Quick Links

| Document | Description |
|----------|-------------|
| [01 - Authenticator Package](./01-authenticator-package.md) | WSO2 IS authenticator integration |
| [02 - Servlet Package](./02-servlet-package.md) | HTTP API endpoints |
| [03 - Service Package](./03-service-package.md) | Business logic layer |
| [04 - Model Package](./04-model-package.md) | Domain models |
| [05 - Util Package](./05-util-package.md) | Utility classes |
| [06 - Exception Package](./06-exception-package.md) | Error handling |
| [07 - DAO Package](./07-dao-package.md) | Database access |
| [08 - DTO Package](./08-dto-package.md) | Data transfer objects |
| [09 - Constants & Internal](./09-constants-internal-packages.md) | Configuration |
| [10 - Runtime Flows](./10-runtime-flows.md) | Sequence diagrams |
| [11 - Feature Support](./11-feature-support.md) | OID4VP compliance |
| [12 - Debugging Guide](./12-debugging-guide.md) | Troubleshooting |
| [SD-JWT Handling](./sd-jwt-handling.md) | Selective Disclosure JWT guide |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Presentation Layer                          │
│  ┌──────────────────┐  ┌──────────────────────────────────────┐ │
│  │  Authenticators  │  │            Servlets                  │ │
│  │ OpenID4VPAuth    │  │ VPRequest, VPSubmission, VPResult    │ │
│  │ WalletAuth       │  │ VPDefinition, RequestUri, Status     │ │
│  └────────┬─────────┘  └───────────────┬──────────────────────┘ │
└───────────┼────────────────────────────┼────────────────────────┘
            │                            │
┌───────────▼────────────────────────────▼────────────────────────┐
│                       Service Layer                              │
│  ┌────────────────┐ ┌─────────────────┐ ┌────────────────────┐  │
│  │ VPRequestSvc   │ │ VPSubmissionSvc │ │ VCVerificationSvc  │  │
│  └────────────────┘ └─────────────────┘ └────────────────────┘  │
│  ┌────────────────┐ ┌─────────────────┐ ┌────────────────────┐  │
│  │ PresentDef Svc │ │ DIDResolverSvc  │ │ StatusListSvc      │  │
│  └────────────────┘ └─────────────────┘ └────────────────────┘  │
└───────────┬────────────────────────────┬────────────────────────┘
            │                            │
┌───────────▼────────────────────────────▼────────────────────────┐
│                        Data Layer                                │
│  ┌────────────────┐ ┌─────────────────┐ ┌────────────────────┐  │
│  │ VPRequestDAO   │ │ VPSubmissionDAO │ │ PresentDefDAO      │  │
│  └────────────────┘ └─────────────────┘ └────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Flows

### 1. QR Code Authentication
User scans QR code → Wallet presents credentials → User authenticated

### 2. VP Verification
Wallet POST → Parse VP → Verify signatures → Check revocation → Store

### 3. Polling
Browser polls status endpoint until completion or timeout

---

## Getting Started

### Prerequisites
- WSO2 Identity Server 7.x
- Java 11+
- Database configured

### Installation
1. Build the component: `mvn clean install`
2. Deploy JAR to IS dropins
3. Restart server

### Configuration
See [09 - Constants & Internal](./09-constants-internal-packages.md) for deployment.toml settings.

---

## File Count Summary

| Package | Files | Purpose |
|---------|-------|---------|
| authenticator | 2 | IS auth framework |
| servlet | 11 | HTTP endpoints |
| service | 22 | Business logic |
| model | 12 | Domain objects |
| util | 10 | Helpers |
| exception | 12 | Error handling |
| dao | 5 | DB access |
| dto | 13 | API payloads |
| constant | 1 | Constants |
| internal | 5 | OSGi |
| **Total** | **91** | |
