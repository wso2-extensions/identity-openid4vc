# Connection Management — Presentation Definition Lifecycle

## Overview

In WSO2 IS, an OpenID4VP verifier is configured as a **Connection** (internally an `IdentityProvider`). Each Connection has a **one-to-one relationship** with a `PresentationDefinition` that specifies what credentials the verifier requires from the wallet.

This relationship is managed automatically by the `OpenID4VPIdentityProviderMgtListener`, which hooks into the Connection lifecycle.

---

## Architecture

```mermaid
flowchart LR
    subgraph "WSO2 IS Console UI"
        A[Create / Update / Delete<br/>Connection]
    end

    subgraph "Carbon Identity Framework"
        B[IdentityProviderManager]
    end

    subgraph "OpenID4VP Component"
        C[OpenID4VPIdentityProviderMgtListener]
        D[PresentationDefinitionService]
        E[(IDN_PRESENTATION_DEFINITION)]
    end

    A --> B
    B -- "lifecycle events" --> C
    C --> D
    D --> E
```

---

## The Listener: `OpenID4VPIdentityProviderMgtListener`

**File:** `listener/OpenID4VPIdentityProviderMgtListener.java`

This class extends `AbstractIdentityProviderMgtListener` (execution order: `99`) and intercepts four lifecycle events:

### Hook Methods

| Method | When Fired | Action |
|--------|-----------|--------|
| `doPostAddIdP` | After a new Connection is created | Creates a new `PresentationDefinition` if the `presentationDefinition` IDP property is set |
| `doPostUpdateIdP` | After a Connection is updated | Creates or updates the `PresentationDefinition` for the Connection's `resourceId` |
| `doPreDeleteIdP` | Before a Connection is deleted | Looks up the Connection by name, finds the associated PD by `resourceId`, and deletes it |
| `doPostDeleteIdP` | After a Connection is deleted | No-op (cleanup is handled in `doPreDeleteIdP` because the IDP is already gone from DB by this point) |

### Data Flow: Add / Update

```mermaid
sequenceDiagram
    participant UI as Console UI
    participant IPM as IdentityProviderManager
    participant L as OpenID4VPIdentityProviderMgtListener
    participant PDS as PresentationDefinitionService
    participant DB as IDN_PRESENTATION_DEFINITION

    UI->>IPM: createIdP / updateIdP
    IPM->>L: doPostAddIdP / doPostUpdateIdP(idp, tenantDomain)
    L->>L: Extract "presentationDefinition" from idp.idpProperties
    alt PD JSON found
        L->>PDS: getPresentationDefinitionByResourceId(idp.resourceId)
        alt Existing PD found
            L->>PDS: updatePresentationDefinition(existingPd)
            PDS->>DB: UPDATE IDN_PRESENTATION_DEFINITION
        else No existing PD
            L->>L: Build new PD (UUID, resourceId, name, description)
            L->>PDS: createPresentationDefinition(newPd)
            PDS->>DB: INSERT INTO IDN_PRESENTATION_DEFINITION
        end
    end
```

### Data Flow: Delete

```mermaid
sequenceDiagram
    participant UI as Console UI
    participant IPM as IdentityProviderManager
    participant L as OpenID4VPIdentityProviderMgtListener
    participant AMS as ApplicationManagementService
    participant PDS as PresentationDefinitionService
    participant DB as IDN_PRESENTATION_DEFINITION

    UI->>IPM: deleteIdP(name)
    IPM->>L: doPreDeleteIdP(idPName, tenantDomain)
    L->>AMS: getIdentityProvider(idPName)
    AMS-->>L: IdentityProvider (with resourceId)
    L->>PDS: getPresentationDefinitionByResourceId(resourceId)
    PDS-->>L: existingPd
    L->>PDS: deletePresentationDefinition(existingPd.definitionId)
    PDS->>DB: DELETE FROM IDN_PRESENTATION_DEFINITION
    IPM->>IPM: Delete IDP from DB
    IPM->>L: doPostDeleteIdP (no-op)
```

---

## Connection ↔ Presentation Definition Relationship

| Concept | Field | Storage |
|---------|-------|---------|
| Connection identity | `IdentityProvider.resourceId` | Carbon IDP tables |
| Link to PD | `PresentationDefinition.resourceId` | `IDN_PRESENTATION_DEFINITION.RESOURCE_ID` |
| PD content | `PresentationDefinition.definitionJson` | `IDN_PRESENTATION_DEFINITION.DEFINITION_JSON` (CLOB) |
| IDP property carrying PD | `idpProperties["presentationDefinition"]` | Transient — used by listener, not persisted as IDP property |

The `resourceId` is the foreign key that links a Connection to its Presentation Definition. This is a soft reference (no DB-level FK constraint) stored as a `VARCHAR(255)` with an index (`IDX_PRES_DEF_RESOURCE_ID`).

---

## Connection Configuration Properties

When an OpenID4VP Connection is created from the "Digital Credentials" template, the following authenticator properties are set:

| Property | Purpose | Example |
|----------|---------|---------|
| `didMethod` | DID method for verifier identity | `did:key`, `did:web`, `did:jwk` |
| `signingAlgorithm` | JWT signing algorithm | `EdDSA`, `ES256`, `RS256` |
| `presentationDefinition` | Full PD JSON (transient, consumed by listener) | `{"id":"...","input_descriptors":[...]}` |

These properties are read by `OpenID4VPAuthenticator.createVPRequest()` during authentication to configure the VP request parameters.

---

## OSGi Registration

The listener is registered as an OSGi service in `VPServiceRegistrationComponent.java`:

```java
bundleContext.registerService(IdentityProviderMgtListener.class.getName(),
        new OpenID4VPIdentityProviderMgtListener(), new Hashtable<>());
```

The listener depends on `ApplicationManagementService` (to look up IDPs by name during delete) and `PresentationDefinitionService` (to manage PD records), both accessed via `OpenID4VCPresentationDataHolder`.
