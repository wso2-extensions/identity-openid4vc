# OpenID4VP DAO Package

## Package: `org.wso2.carbon.identity.openid4vc.presentation.dao`

This package contains Data Access Objects for database operations.

---

## DAO Overview

| DAO | Table | Purpose |
|-----|-------|---------|
| VPRequestDAO | IDN_VP_REQUEST | VP request sessions |
| VPSubmissionDAO | IDN_VP_SUBMISSION | Wallet submissions |
| PresentationDefinitionDAO | IDN_PRESENTATION_DEFINITION | Presentation definitions |
| TrustedIssuerDAO | IDN_TRUSTED_ISSUER | Trusted issuers |
| ApplicationPresentationDefinitionMappingDAO | IDN_APPLICATION_PRESENTATION_DEFINITION | App-definition mappings |

---

## Detailed DAO Documentation

### 1. VPRequestDAO.java

**Purpose:** CRUD operations for VP request sessions.

#### Methods

| Method | SQL Operation |
|--------|---------------|
| `create(request)` | INSERT |
| `get(id)` | SELECT by ID |
| `getByState(state)` | SELECT by state |
| `update(request)` | UPDATE |
| `delete(id)` | DELETE |
| `deleteExpired()` | DELETE WHERE expires_at < NOW() |

#### Table Schema

```sql
CREATE TABLE IDN_VP_REQUEST (
    ID VARCHAR(255) PRIMARY KEY,
    NONCE VARCHAR(255) NOT NULL,
    STATE VARCHAR(255) NOT NULL UNIQUE,
    CLIENT_ID VARCHAR(255),
    RESPONSE_URI VARCHAR(1000),
    PRESENTATION_DEFINITION_ID VARCHAR(255),
    STATUS VARCHAR(50) DEFAULT 'PENDING',
    CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    EXPIRES_AT TIMESTAMP NOT NULL,
    TENANT_ID INT NOT NULL
);
```

---

### 2. VPSubmissionDAO.java

**Purpose:** Store and retrieve wallet VP submissions.

#### Methods

| Method | SQL Operation |
|--------|---------------|
| `create(submission)` | INSERT |
| `get(id)` | SELECT by ID |
| `getByRequestId(requestId)` | SELECT by request |
| `delete(id)` | DELETE |

#### Table Schema

```sql
CREATE TABLE IDN_VP_SUBMISSION (
    ID VARCHAR(255) PRIMARY KEY,
    REQUEST_ID VARCHAR(255) NOT NULL,
    VP_TOKEN TEXT NOT NULL,
    PRESENTATION_SUBMISSION TEXT,
    VERIFICATION_RESULT VARCHAR(50),
    SUBMITTED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    WALLET_METADATA TEXT,
    TENANT_ID INT NOT NULL,
    FOREIGN KEY (REQUEST_ID) REFERENCES IDN_VP_REQUEST(ID)
);
```

---

### 3. PresentationDefinitionDAO.java

**Purpose:** Manage presentation definitions.

#### Methods

| Method | SQL Operation |
|--------|---------------|
| `create(definition)` | INSERT |
| `get(id)` | SELECT by ID |
| `list(tenantId)` | SELECT all for tenant |
| `update(definition)` | UPDATE |
| `delete(id)` | DELETE |

#### Table Schema

```sql
CREATE TABLE IDN_PRESENTATION_DEFINITION (
    ID VARCHAR(255) PRIMARY KEY,
    NAME VARCHAR(255) NOT NULL,
    DESCRIPTION VARCHAR(1000),
    DEFINITION_JSON TEXT NOT NULL,
    CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UPDATED_AT TIMESTAMP,
    TENANT_ID INT NOT NULL
);
```

---

### 4. ApplicationPresentationDefinitionMappingDAO.java

**Purpose:** Map applications to presentation definitions.

#### Methods

| Method | SQL Operation |
|--------|---------------|
| `create(mapping)` | INSERT |
| `getByAppId(appId)` | SELECT by application |
| `getByDefinitionId(defId)` | SELECT by definition |
| `delete(appId)` | DELETE |

#### Table Schema

```sql
CREATE TABLE IDN_APPLICATION_PRESENTATION_DEFINITION (
    APP_ID VARCHAR(255) NOT NULL,
    PRESENTATION_DEFINITION_ID VARCHAR(255) NOT NULL,
    TENANT_ID INT NOT NULL,
    PRIMARY KEY (APP_ID, TENANT_ID),
    FOREIGN KEY (PRESENTATION_DEFINITION_ID) 
        REFERENCES IDN_PRESENTATION_DEFINITION(ID)
);
```

---

### 5. TrustedIssuerDAO.java

**Purpose:** Manage trusted credential issuers.

#### Methods

| Method | SQL Operation |
|--------|---------------|
| `create(issuer)` | INSERT |
| `get(id)` | SELECT by ID |
| `getByDid(did)` | SELECT by DID |
| `list(tenantId)` | SELECT all for tenant |
| `delete(id)` | DELETE |

#### Table Schema

```sql
CREATE TABLE IDN_TRUSTED_ISSUER (
    ID VARCHAR(255) PRIMARY KEY,
    ISSUER_DID VARCHAR(255) NOT NULL UNIQUE,
    NAME VARCHAR(255),
    CREDENTIAL_TYPES TEXT,
    CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    TENANT_ID INT NOT NULL
);
```

---

## Connection Handling

DAOs use `IdentityDatabaseUtil` for connection management:

```java
public VPRequest get(String id) throws VPException {
    Connection connection = null;
    PreparedStatement stmt = null;
    ResultSet rs = null;
    
    try {
        connection = IdentityDatabaseUtil.getDBConnection(false);
        stmt = connection.prepareStatement(GET_BY_ID_SQL);
        stmt.setString(1, id);
        rs = stmt.executeQuery();
        
        if (rs.next()) {
            return mapResultSetToVPRequest(rs);
        }
        return null;
        
    } catch (SQLException e) {
        throw new VPException("Error getting VP request", e);
    } finally {
        IdentityDatabaseUtil.closeAllConnections(connection, rs, stmt);
    }
}
```
