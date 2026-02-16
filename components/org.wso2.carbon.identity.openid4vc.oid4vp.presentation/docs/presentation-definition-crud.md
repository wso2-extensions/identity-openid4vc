# Presentation Definition CRUD Reference

This document details the functions, API endpoints, and database tables involved in the CRUD (Create, Read, Update, Delete) operations for **Presentation Definitions** in the OpenID4VP component.

---

## 1. Database Schema

The following tables are used to store Presentation Definitions and their mappings to applications.

### Table: `IDN_PRESENTATION_DEFINITION`
Stores the actual Presentation Exchange definitions.

| Column Name | Type | Description |
|-------------|------|-------------|
| **`ID`** | INTEGER | Auto-incrementing Primary Key (Internal DB ID). |
| **`DEFINITION_ID`** | VARCHAR(255) | Unique public identifier for the definition (e.g., UUID or human-readable ID). |
| **`NAME`** | VARCHAR(255) | Display name of the definition context. |
| **`DESCRIPTION`** | CLOB | Optional description of what this definition requests. |
| **`DEFINITION_JSON`** | CLOB | The actual JSON structure of the Presentation Definition (as per DIF spec). |
| **`IS_DEFAULT`** | BOOLEAN | Flag indicating if this is the default definition for the tenant. |
| **`CREATED_AT`** | BIGINT | Timestamp of creation (epoch milliseconds). |
| **`UPDATED_AT`** | BIGINT | Timestamp of last update. |
| **`TENANT_ID`** | INTEGER | Tenant isolation identifier. |

**Uniqueness Constraints**:
*   `DEFINITION_ID` + `TENANT_ID`
*   `NAME` + `TENANT_ID`

---

### Table: `IDN_APPLICATION_PRESENTATION_DEFINITION`
Maps a Service Provider application to a specific Presentation Definition.

| Column Name | Type | Description |
|-------------|------|-------------|
| **`ID`** | INTEGER | Primary Key. |
| **`APPLICATION_ID`** | VARCHAR(255) | The unique identifier of the Service Provider application (Connector ID). |
| **`PRESENTATION_DEFINITION_ID`** | VARCHAR(255) | The `DEFINITION_ID` from the main table that this app uses. |
| **`TENANT_ID`** | INTEGER | Tenant isolation identifier. |
| **`CREATED_AT`** | BIGINT | Timestamp of mapping creation. |
| **`UPDATED_AT`** | BIGINT | Timestamp of last update. |

---

## 2. CRUD Functions Implementation

The CRUD operations follow a standard layered architecture:
**Servlet (REST API)** -> **Service (Business Logic)** -> **DAO (Data Access)**.

### 2.1 Create Presentation Definition

*   **API Endpoint**: `POST /openid4vp/v1/presentation-definitions`
*   **Servlet Method**: `VPDefinitionServlet.handleCreatePresentationDefinition()`
*   **Service Method**: `PresentationDefinitionService.createPresentationDefinition()`
*   **DAO Method**: `PresentationDefinitionDAO.createPresentationDefinition()`
*   **SQL Query**:
    ```sql
    INSERT INTO IDN_PRESENTATION_DEFINITION (DEFINITION_ID, NAME, DESCRIPTION, DEFINITION_JSON, IS_DEFAULT, CREATED_AT, UPDATED_AT, TENANT_ID) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ```

### 2.2 Get Presentation Definition (By ID)

*   **API Endpoint**: `GET /openid4vp/v1/presentation-definitions/{id}`
*   **Servlet Method**: `VPDefinitionServlet.handleGetDefinition()`
*   **Service Method**: `PresentationDefinitionService.getPresentationDefinitionById()`
*   **DAO Method**: `PresentationDefinitionDAO.getPresentationDefinitionById()`
*   **SQL Query**:
    ```sql
    SELECT * FROM IDN_PRESENTATION_DEFINITION WHERE DEFINITION_ID = ? AND TENANT_ID = ?
    ```

### 2.3 List All Presentation Definitions

*   **API Endpoint**: `GET /openid4vp/v1/presentation-definitions`
*   **Servlet Method**: `VPDefinitionServlet.handleListDefinitions()`
*   **Service Method**: `PresentationDefinitionService.getAllPresentationDefinitions()`
*   **DAO Method**: `PresentationDefinitionDAO.getAllPresentationDefinitions()`
*   **SQL Query**:
    ```sql
    SELECT * FROM IDN_PRESENTATION_DEFINITION WHERE TENANT_ID = ?
    ```

### 2.4 Update Presentation Definition

*   **API Endpoint**: `PUT /openid4vp/v1/presentation-definitions/{id}`
*   **Servlet Method**: `VPDefinitionServlet.doPut()`
*   **Service Method**: `PresentationDefinitionService.updatePresentationDefinition()`
*   **DAO Method**: `PresentationDefinitionDAO.updatePresentationDefinition()`
*   **SQL Query**:
    ```sql
    UPDATE IDN_PRESENTATION_DEFINITION SET NAME = ?, DESCRIPTION = ?, DEFINITION_JSON = ?, IS_DEFAULT = ?, UPDATED_AT = ? WHERE DEFINITION_ID = ? AND TENANT_ID = ?
    ```

### 2.5 Delete Presentation Definition

*   **API Endpoint**: `DELETE /openid4vp/v1/presentation-definitions/{id}`
*   **Servlet Method**: `VPDefinitionServlet.handleDeletePresentationDefinition()`
*   **Service Method**: `PresentationDefinitionService.deletePresentationDefinition()`
*   **DAO Method**: `PresentationDefinitionDAO.deletePresentationDefinition()`
*   **SQL Query**:
    ```sql
    DELETE FROM IDN_PRESENTATION_DEFINITION WHERE DEFINITION_ID = ? AND TENANT_ID = ?
    ```

---

## 3. Application Mapping Functions

Operations to associate a Presentation Definition with an Application.

### 3.1 Get Mapping (Get App's Definition)

*   **API Endpoint**: `GET /openid4vp/v1/presentation-definitions/mapping/{applicationId}`
*   **Service Method**: `ApplicationPresentationDefinitionMappingService.getApplicationMapping()`

### 3.2 Create/Update Mapping

*   **API Endpoint**: `POST /openid4vp/v1/presentation-definitions/mapping`
*   **Service Method**: `ApplicationPresentationDefinitionMappingService.mapPresentationDefinitionToApplication()`

### 3.3 Delete Mapping

*   **API Endpoint**: `DELETE /openid4vp/v1/presentation-definitions/mapping/{applicationId}`
*   **Service Method**: `ApplicationPresentationDefinitionMappingService.removePresentationDefinitionMapping()`
