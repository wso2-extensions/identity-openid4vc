/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.presentation.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Initializes the OpenID4VP database schema on component activation.
 * Creates required tables if they don't exist.
 */
public class DatabaseSchemaInitializer {

    private static final Log LOG = LogFactory.getLog(DatabaseSchemaInitializer.class);

    private static final String TABLE_VP_REQUEST = "IDN_VP_REQUEST";
    private static final String TABLE_VP_SUBMISSION = "IDN_VP_SUBMISSION";
    private static final String TABLE_PRESENTATION_DEFINITION = "IDN_PRESENTATION_DEFINITION";
    private static final String TABLE_APP_PRES_DEF_MAPPING = "IDN_APPLICATION_PRESENTATION_DEFINITION";

    /**
     * Initialize the database schema. Creates tables if they don't exist.
     */
    public static void initializeSchema() {
        LOG.info("[OPENID4VP] Initializing database schema...");

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            if (connection == null) {
                LOG.error("[OPENID4VP] Failed to get database connection for schema initialization");
                return;
            }

            // Create tables in order (due to potential foreign key dependencies)
            createVPRequestTable(connection);
            createVPSubmissionTable(connection);
            createPresentationDefinitionTable(connection);
            createApplicationPresentationDefinitionTable(connection);
            createDIDKeysTable(connection);

            LOG.info("[OPENID4VP] Database schema initialization completed successfully");

        } catch (SQLException e) {
            LOG.error("[OPENID4VP] Error initializing database schema: " + e.getMessage(), e);
        }
    }

    /**
     * Check if a table exists in the database.
     */
    private static boolean tableExists(Connection connection, String tableName) throws SQLException {
        DatabaseMetaData metaData = connection.getMetaData();
        // Check both uppercase and lowercase table names
        try (ResultSet rs = metaData.getTables(null, null, tableName.toUpperCase(), new String[] { "TABLE" })) {
            if (rs.next()) {
                return true;
            }
        }
        try (ResultSet rs = metaData.getTables(null, null, tableName.toLowerCase(), new String[] { "TABLE" })) {
            return rs.next();
        }
    }

    /**
     * Create IDN_VP_REQUEST table.
     */
    private static void createVPRequestTable(Connection connection) throws SQLException {
        if (tableExists(connection, TABLE_VP_REQUEST)) {
            LOG.debug("[OPENID4VP] Table " + TABLE_VP_REQUEST + " already exists");
            return;
        }

        String sql = "CREATE TABLE IF NOT EXISTS IDN_VP_REQUEST (" +
                "ID INTEGER AUTO_INCREMENT, " +
                "REQUEST_ID VARCHAR(255) NOT NULL, " +
                "TRANSACTION_ID VARCHAR(255) NOT NULL, " +
                "CLIENT_ID VARCHAR(255) NOT NULL, " +
                "NONCE VARCHAR(255) NOT NULL, " +
                "PRESENTATION_DEFINITION_ID VARCHAR(255), " +
                "PRESENTATION_DEFINITION CLOB, " +
                "RESPONSE_URI VARCHAR(2048), " +
                "RESPONSE_MODE VARCHAR(50) DEFAULT 'direct_post', " +
                "REQUEST_JWT CLOB, " +
                "STATUS VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', " +
                "CREATED_AT BIGINT NOT NULL, " +
                "EXPIRES_AT BIGINT NOT NULL, " +
                "TENANT_ID INTEGER DEFAULT -1234, " +
                "PRIMARY KEY (ID), " +
                "UNIQUE (REQUEST_ID, TENANT_ID), " +
                "UNIQUE (TRANSACTION_ID, TENANT_ID)" +
                ")";

        executeSQL(connection, sql, TABLE_VP_REQUEST);

        // Create indexes
        executeSQL(connection,
                "CREATE INDEX IF NOT EXISTS IDX_VP_REQ_TRANSACTION_ID ON IDN_VP_REQUEST(TRANSACTION_ID, TENANT_ID)",
                "IDX_VP_REQ_TRANSACTION_ID");
        executeSQL(connection,
                "CREATE INDEX IF NOT EXISTS IDX_VP_REQ_STATUS ON IDN_VP_REQUEST(STATUS, TENANT_ID)",
                "IDX_VP_REQ_STATUS");
        executeSQL(connection,
                "CREATE INDEX IF NOT EXISTS IDX_VP_REQ_EXPIRES ON IDN_VP_REQUEST(EXPIRES_AT, STATUS)",
                "IDX_VP_REQ_EXPIRES");
        executeSQL(connection,
                "CREATE INDEX IF NOT EXISTS IDX_VP_REQ_CLIENT_ID ON IDN_VP_REQUEST(CLIENT_ID, TENANT_ID)",
                "IDX_VP_REQ_CLIENT_ID");
    }

    /**
     * Create IDN_VP_SUBMISSION table.
     */
    private static void createVPSubmissionTable(Connection connection) throws SQLException {
        if (tableExists(connection, TABLE_VP_SUBMISSION)) {
            LOG.debug("[OPENID4VP] Table " + TABLE_VP_SUBMISSION + " already exists");
            return;
        }

        String sql = "CREATE TABLE IF NOT EXISTS IDN_VP_SUBMISSION (" +
                "ID INTEGER AUTO_INCREMENT, " +
                "SUBMISSION_ID VARCHAR(255) NOT NULL, " +
                "REQUEST_ID VARCHAR(255) NOT NULL, " +
                "VP_TOKEN CLOB, " +
                "PRESENTATION_SUBMISSION CLOB, " +
                "ERROR VARCHAR(255), " +
                "ERROR_DESCRIPTION CLOB, " +
                "VERIFICATION_STATUS VARCHAR(50), " +
                "VERIFICATION_RESULT CLOB, " +
                "SUBMITTED_AT BIGINT NOT NULL, " +
                "TENANT_ID INTEGER DEFAULT -1234, " +
                "PRIMARY KEY (ID), " +
                "UNIQUE (SUBMISSION_ID, TENANT_ID)" +
                ")";

        executeSQL(connection, sql, TABLE_VP_SUBMISSION);

        // Create indexes
        executeSQL(connection,
                "CREATE INDEX IF NOT EXISTS IDX_VP_SUB_REQUEST_ID ON IDN_VP_SUBMISSION(REQUEST_ID, TENANT_ID)",
                "IDX_VP_SUB_REQUEST_ID");
        executeSQL(connection,
                "CREATE INDEX IF NOT EXISTS IDX_VP_SUB_VERIFICATION ON " +
                        "IDN_VP_SUBMISSION(VERIFICATION_STATUS, TENANT_ID)",
                "IDX_VP_SUB_VERIFICATION");
    }

    /**
     * Create IDN_PRESENTATION_DEFINITION table.
     */
    private static void createPresentationDefinitionTable(Connection connection) throws SQLException {
        if (tableExists(connection, TABLE_PRESENTATION_DEFINITION)) {
            LOG.debug("[OPENID4VP] Table " + TABLE_PRESENTATION_DEFINITION + " already exists");
            return;
        }

        String sql = "CREATE TABLE IF NOT EXISTS IDN_PRESENTATION_DEFINITION (" +
                "ID INTEGER AUTO_INCREMENT, " +
                "DEFINITION_ID VARCHAR(255) NOT NULL, " +
                "NAME VARCHAR(255) NOT NULL, " +
                "DESCRIPTION CLOB, " +
                "DEFINITION_JSON CLOB NOT NULL, " +
                "IS_DEFAULT BOOLEAN DEFAULT FALSE, " +
                "CREATED_AT BIGINT NOT NULL, " +
                "UPDATED_AT BIGINT, " +
                "TENANT_ID INTEGER DEFAULT -1234, " +
                "PRIMARY KEY (ID), " +
                "UNIQUE (DEFINITION_ID, TENANT_ID), " +
                "UNIQUE (NAME, TENANT_ID)" +
                ")";

        executeSQL(connection, sql, TABLE_PRESENTATION_DEFINITION);

        // Create index
        executeSQL(connection,
                "CREATE INDEX IF NOT EXISTS IDX_PRES_DEF_DEFAULT ON IDN_PRESENTATION_DEFINITION(IS_DEFAULT, TENANT_ID)",
                "IDX_PRES_DEF_DEFAULT");
    }

    /**
     * Create IDN_APPLICATION_PRESENTATION_DEFINITION table.
     */
    private static void createApplicationPresentationDefinitionTable(Connection connection) throws SQLException {
        if (tableExists(connection, TABLE_APP_PRES_DEF_MAPPING)) {
            LOG.debug("[OPENID4VP] Table " + TABLE_APP_PRES_DEF_MAPPING + " already exists");
            return;
        }

        String sql = "CREATE TABLE IF NOT EXISTS IDN_APPLICATION_PRESENTATION_DEFINITION (" +
                "ID INTEGER AUTO_INCREMENT, " +
                "APPLICATION_ID VARCHAR(255) NOT NULL, " +
                "PRESENTATION_DEFINITION_ID VARCHAR(255) NOT NULL, " +
                "TENANT_ID INTEGER DEFAULT -1234, " +
                "CREATED_AT BIGINT NOT NULL, " +
                "UPDATED_AT BIGINT, " +
                "PRIMARY KEY (ID), " +
                "UNIQUE (APPLICATION_ID, TENANT_ID)" +
                ")";

        executeSQL(connection, sql, TABLE_APP_PRES_DEF_MAPPING);

        // Create indexes
        executeSQL(connection,
                "CREATE INDEX IF NOT EXISTS IDX_APP_PRES_DEF_APP_ID ON " +
                        "IDN_APPLICATION_PRESENTATION_DEFINITION(APPLICATION_ID, TENANT_ID)",
                "IDX_APP_PRES_DEF_APP_ID");
        executeSQL(connection,
                "CREATE INDEX IF NOT EXISTS IDX_APP_PRES_DEF_PRES_ID ON " +
                        "IDN_APPLICATION_PRESENTATION_DEFINITION(PRESENTATION_DEFINITION_ID, TENANT_ID)",
                "IDX_APP_PRES_DEF_PRES_ID");
        executeSQL(connection,
                "CREATE INDEX IF NOT EXISTS IDX_APP_PRES_DEF_TENANT ON " +
                        "IDN_APPLICATION_PRESENTATION_DEFINITION(TENANT_ID)",
                "IDX_APP_PRES_DEF_TENANT");
    }

    /**
     * Create IDN_DID_KEYS table.
     */
    private static void createDIDKeysTable(Connection connection) throws SQLException {
        if (tableExists(connection, "IDN_DID_KEYS")) {
            LOG.debug("[OPENID4VP] Table IDN_DID_KEYS already exists");
            return;
        }

        String sql = "CREATE TABLE IF NOT EXISTS IDN_DID_KEYS (" +
                "TENANT_ID INTEGER NOT NULL, " +
                "KEY_ID VARCHAR(255) NOT NULL, " +
                "ALGORITHM VARCHAR(50) NOT NULL, " +
                "PUBLIC_KEY BLOB, " +
                "PRIVATE_KEY BLOB, " +
                "CREATED_AT BIGINT NOT NULL, " +
                "PRIMARY KEY (TENANT_ID, KEY_ID)" +
                ")";

        executeSQL(connection, sql, "IDN_DID_KEYS");
    }

    /**
     * Execute SQL and log the result.
     */
    private static void executeSQL(Connection connection, String sql, String objectName) {
        try (Statement statement = connection.createStatement()) {
            statement.execute(sql);
            LOG.info("[OPENID4VP] Created database object: " + objectName);
        } catch (SQLException e) {
            // Log but don't fail - the object might already exist or be created by another
            // thread
            if (e.getMessage() != null && (e.getMessage().contains("already exists") ||
                    e.getMessage().contains("Duplicate") ||
                    e.getMessage().contains("DUPLICATE"))) {
                LOG.debug("[OPENID4VP] Object " + objectName + " already exists");
            } else {
                LOG.warn("[OPENID4VP] Error creating object " + objectName + ": " + e.getMessage());
            }
        }
    }
}
