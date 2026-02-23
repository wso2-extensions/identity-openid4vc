# 03 — DAO & Persistence Layer

The module uses a **hybrid persistence strategy**: Presentation Definitions go to a database table; VP Requests live entirely in an in-memory cache.

---

## 1. PresentationDefinitionDAO (Interface, 108 lines)

### Methods

```java
void createPresentationDefinition(PresentationDefinition pd);
PresentationDefinition getPresentationDefinitionById(String id, int tenantId);
PresentationDefinition getPresentationDefinitionByResourceId(String resourceId, int tenantId);
PresentationDefinition getPresentationDefinitionByName(String name, int tenantId);
List<PresentationDefinition> getAllPresentationDefinitions(int tenantId);
void updatePresentationDefinition(PresentationDefinition pd);
void deletePresentationDefinition(String id, int tenantId);
boolean presentationDefinitionExists(String id, int tenantId);
```

---

## 2. PresentationDefinitionDAOImpl (268 lines)

### Database Table

```sql
IDN_PRESENTATION_DEFINITION
├── DEFINITION_ID   VARCHAR(255)  PK    -- UUID
├── RESOURCE_ID     VARCHAR(255)        -- Links to IDP Resource ID
├── NAME            VARCHAR(255)  NOT NULL
├── DESCRIPTION     CLOB
├── DEFINITION_JSON CLOB          NOT NULL  -- Full PD JSON
└── TENANT_ID       INTEGER       DEFAULT -1234
    UNIQUE(NAME, TENANT_ID)
    INDEX(RESOURCE_ID)
```

### Connection Management

Uses `IdentityDatabaseUtil.getDBConnection()` which returns a JDBC `Connection` from the WSO2 Carbon datasource pool (`WSO2_CARBON_DB`). This is the standard WSO2 IS pattern for identity-related tables.

### Transaction Pattern

Every write method follows:
```java
Connection conn = IdentityDatabaseUtil.getDBConnection(true); // autoCommit=true for reads
try {
    PreparedStatement ps = conn.prepareStatement(SQL);
    // bind params
    ps.executeUpdate();
    IdentityDatabaseUtil.commitTransaction(conn);
} catch (SQLException e) {
    IdentityDatabaseUtil.rollbackTransaction(conn);
    throw new VPException("...", e);
} finally {
    IdentityDatabaseUtil.closeConnection(conn);
}
```

### SQL Queries (Hardcoded Constants)

| Operation | SQL |
|---|---|
| Create | `INSERT INTO IDN_PRESENTATION_DEFINITION (DEFINITION_ID, RESOURCE_ID, NAME, DESCRIPTION, DEFINITION_JSON, TENANT_ID) VALUES (?,?,?,?,?,?)` |
| Get by ID | `SELECT * FROM IDN_PRESENTATION_DEFINITION WHERE DEFINITION_ID = ? AND TENANT_ID = ?` |
| Get by Resource ID | `SELECT * FROM IDN_PRESENTATION_DEFINITION WHERE RESOURCE_ID = ? AND TENANT_ID = ?` |
| Get by Name | `SELECT * FROM IDN_PRESENTATION_DEFINITION WHERE NAME = ? AND TENANT_ID = ?` |
| List all | `SELECT * FROM IDN_PRESENTATION_DEFINITION WHERE TENANT_ID = ?` |
| Update | `UPDATE IDN_PRESENTATION_DEFINITION SET NAME=?, DESCRIPTION=?, DEFINITION_JSON=?, RESOURCE_ID=? WHERE DEFINITION_ID=? AND TENANT_ID=?` |
| Delete | `DELETE FROM IDN_PRESENTATION_DEFINITION WHERE DEFINITION_ID = ? AND TENANT_ID = ?` |
| Exists | `SELECT COUNT(*) FROM IDN_PRESENTATION_DEFINITION WHERE DEFINITION_ID = ? AND TENANT_ID = ?` |

### Code Review Notes

- **SQL in Java strings**: All SQL is hardcoded as string constants inside the DAO class. WSO2's usual pattern uses a separate `SQLQueries` constants class — consider extracting.
- **No pagination**: `getAllPresentationDefinitions()` fetches all rows. For tenants with many definitions, this could be problematic.
- **ResultSet mapping**: The `mapResultSetToDefinition()` helper reads all columns and constructs a `PresentationDefinition` via its Builder. This is clean.
- **Tenant isolation**: Every query includes `AND TENANT_ID = ?`, which is correct for multi-tenant WSO2 IS.

---

## 3. VPRequestDAO (Interface, 119 lines)

### Methods

```java
void createVPRequest(VPRequest vpRequest) throws VPException;
VPRequest getVPRequestById(String requestId, int tenantId) throws VPException;
VPRequest getVPRequestByTransactionId(String transactionId, int tenantId) throws VPException;
void updateVPRequestStatus(String requestId, VPRequestStatus status, int tenantId) throws VPException;
void updateVPRequestJwt(String requestId, String jwt, int tenantId) throws VPException;
void deleteVPRequest(String requestId, int tenantId) throws VPException;
List<VPRequest> getExpiredVPRequests(int tenantId) throws VPException;
int markExpiredRequests(int tenantId) throws VPException;
List<VPRequest> getVPRequestsByStatus(VPRequestStatus status, int tenantId) throws VPException;
```

---

## 4. VPRequestDAOImpl (107 lines) — **Cache-Based**

This is the key architectural decision: **`VPRequestDAOImpl` does NOT touch the database**. It delegates entirely to `VPRequestCache`.

### Implementation Pattern

```java
public class VPRequestDAOImpl implements VPRequestDAO {
    private final VPRequestCache cache = VPRequestCache.getInstance();

    @Override
    public void createVPRequest(VPRequest vpRequest) {
        cache.put(vpRequest.getRequestId(), vpRequest);
    }

    @Override
    public VPRequest getVPRequestById(String requestId, int tenantId) {
        return cache.get(requestId);  // tenantId ignored
    }

    // ...
}
```

### Stub Methods

Several methods exist only for interface compatibility:

| Method | Implementation |
|---|---|
| `getExpiredVPRequests()` | Returns `Collections.emptyList()` — cache handles its own expiry |
| `markExpiredRequests()` | Returns `0` — no-op |
| `getVPRequestsByStatus()` | Returns `Collections.emptyList()` — not supported by cache |

### Why Cache Instead of DB?

The code comment states:
> "Replaces DB storage with Cache-based storage as per new architecture"

VP Requests are transient (5-minute TTL), created and consumed within a single authentication flow. Persisting them to a database would add unnecessary I/O overhead for data that's discarded after the flow completes.

### Code Review Notes

- **Tenant ID ignored**: `getVPRequestById(requestId, tenantId)` ignores `tenantId` — the cache is a flat namespace. In a multi-tenant deployment, a requestId collision (unlikely with UUIDs) could theoretically return the wrong tenant's data.
- **Interface impedance mismatch**: Several interface methods are stubs. The interface was designed for DB-backed storage; consider splitting into separate interfaces or using a marker.
- **No persistence on restart**: VP requests are lost if the server restarts. Users in mid-flow will see "Request not found" errors.

---

## Persistence Architecture Summary

```
┌─────────────────────────────────────────┐
│          Service Layer                   │
│  PresentationDefinitionServiceImpl      │
│  VPRequestServiceImpl                   │
└────────────┬───────────────┬────────────┘
             │               │
             ▼               ▼
┌────────────────────┐ ┌──────────────────┐
│PresentationDefDAO  │ │VPRequestDAO      │
│     (Interface)    │ │    (Interface)    │
└────────┬───────────┘ └────────┬─────────┘
         │                      │
         ▼                      ▼
┌────────────────────┐ ┌──────────────────┐
│PresentationDefDAO  │ │VPRequestDAOImpl  │
│     Impl           │ │  (Cache-based)   │
│                    │ │                  │
│  JDBC → H2/MySQL   │ │  → VPRequestCache│
│  IDN_PRESENTATION_ │ │  ConcurrentHash  │
│  DEFINITION table  │ │  Map (in-memory) │
└────────────────────┘ └──────────────────┘
```
