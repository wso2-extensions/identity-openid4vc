/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.management.dao.impl;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.management.dao.PresentationDefinitionDAO;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition.ClaimConstraint;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition.RequestedCredential;

import java.lang.reflect.Type;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of PresentationDefinitionDAO using JDBC.
 * Stores presentation definition headers in IDN_PRESENTATION_DEFINITION and
 * requested credentials in IDN_PD_CREDENTIAL.
 */
public class PresentationDefinitionDAOImpl implements PresentationDefinitionDAO {

    private static final Gson GSON = new Gson();
    private static final Type CLAIM_CONSTRAINT_LIST_TYPE =
            new TypeToken<List<ClaimConstraint>>() {}.getType();

    // ---- IDN_PRESENTATION_DEFINITION queries ----
    private static final String SQL_INSERT_DEFINITION =
            "INSERT INTO IDN_PRESENTATION_DEFINITION (DEFINITION_ID, NAME, DESCRIPTION, TENANT_ID) " +
            "VALUES (?, ?, ?, ?)";

    private static final String SQL_SELECT_DEFINITION_BY_ID =
            "SELECT DEFINITION_ID, NAME, DESCRIPTION, TENANT_ID " +
            "FROM IDN_PRESENTATION_DEFINITION WHERE DEFINITION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_SELECT_ALL_DEFINITIONS =
            "SELECT DEFINITION_ID, NAME, DESCRIPTION, TENANT_ID " +
            "FROM IDN_PRESENTATION_DEFINITION WHERE TENANT_ID = ?";

    private static final String SQL_UPDATE_DEFINITION =
            "UPDATE IDN_PRESENTATION_DEFINITION SET NAME = ?, DESCRIPTION = ? " +
            "WHERE DEFINITION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_DELETE_DEFINITION =
            "DELETE FROM IDN_PRESENTATION_DEFINITION WHERE DEFINITION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_EXISTS_DEFINITION =
            "SELECT 1 FROM IDN_PRESENTATION_DEFINITION WHERE DEFINITION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_SELECT_DEFINITION_BY_NAME =
            "SELECT DEFINITION_ID, NAME, DESCRIPTION, TENANT_ID " +
            "FROM IDN_PRESENTATION_DEFINITION WHERE NAME = ? AND TENANT_ID = ?";

    // ---- IDN_PD_CREDENTIAL queries ----
    private static final String SQL_INSERT_CREDENTIAL =
            "INSERT INTO IDN_PD_CREDENTIAL (DEFINITION_ID, CREDENTIAL_TYPE, PURPOSE, ISSUER, CLAIMS, ISSUER_CERT, " +
            "TRUSTED_ISSUERS, ENFORCE_TRUSTED_ISSUERS) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String SQL_SELECT_CREDENTIALS_BY_DEFINITION =
            "SELECT CREDENTIAL_TYPE, PURPOSE, ISSUER, CLAIMS, ISSUER_CERT, TRUSTED_ISSUERS, ENFORCE_TRUSTED_ISSUERS " +
            "FROM IDN_PD_CREDENTIAL WHERE DEFINITION_ID = ?";

    private static final String SQL_DELETE_CREDENTIALS_BY_DEFINITION =
            "DELETE FROM IDN_PD_CREDENTIAL WHERE DEFINITION_ID = ?";

    @Override
    public void createPresentationDefinition(PresentationDefinition presentationDefinition)
            throws VPException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try {
                // 1. Insert header row
                try (PreparedStatement ps = connection.prepareStatement(SQL_INSERT_DEFINITION)) {
                    ps.setString(1, presentationDefinition.getDefinitionId());
                    ps.setString(2, presentationDefinition.getName());
                    ps.setString(3, presentationDefinition.getDescription());
                    ps.setInt(4, presentationDefinition.getTenantId());
                    ps.executeUpdate();
                }

                // 2. Insert credential rows
                insertCredentials(connection, presentationDefinition.getDefinitionId(),
                        presentationDefinition.getRequestedCredentials());

                IdentityDatabaseUtil.commitTransaction(connection);

            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                String msg = "Error creating presentation definition: " +
                        presentationDefinition.getDefinitionId();
                if (e.getMessage() != null && e.getMessage().contains("CONSTRAINT_INDEX")) {
                    msg = "Presentation definition with name '" +
                            presentationDefinition.getName() + "' already exists.";
                }
                throw new VPException(msg, e);
            }
        } catch (SQLException e) {
            throw new VPException("Error obtaining DB connection for createPresentationDefinition", e);
        }
    }

    @Override
    public PresentationDefinition getPresentationDefinitionById(String definitionId, int tenantId)
            throws VPException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            PresentationDefinition definition = null;
            try (PreparedStatement ps = connection.prepareStatement(SQL_SELECT_DEFINITION_BY_ID)) {
                ps.setString(1, definitionId);
                ps.setInt(2, tenantId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        definition = mapHeaderRow(rs);
                    }
                }
            }
            if (definition != null) {
                definition.setRequestedCredentials(queryCredentials(connection, definitionId));
            }
            return definition;
        } catch (SQLException e) {
            throw new VPException("Error retrieving presentation definition: " + definitionId, e);
        }
    }

    @Override
    public List<PresentationDefinition> getAllPresentationDefinitions(int tenantId)
            throws VPException {

        List<PresentationDefinition> definitions = new ArrayList<>();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_SELECT_ALL_DEFINITIONS)) {
                ps.setInt(1, tenantId);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        PresentationDefinition def = mapHeaderRow(rs);
                        def.setRequestedCredentials(queryCredentials(connection, def.getDefinitionId()));
                        definitions.add(def);
                    }
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error retrieving all presentation definitions", e);
        }
        return definitions;
    }

    @Override
    public void updatePresentationDefinition(PresentationDefinition presentationDefinition)
            throws VPException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try {
                // 1. Update header
                try (PreparedStatement ps = connection.prepareStatement(SQL_UPDATE_DEFINITION)) {
                    ps.setString(1, presentationDefinition.getName());
                    ps.setString(2, presentationDefinition.getDescription());
                    ps.setString(3, presentationDefinition.getDefinitionId());
                    ps.setInt(4, presentationDefinition.getTenantId());
                    int rowsAffected = ps.executeUpdate();
                    if (rowsAffected == 0) {
                        IdentityDatabaseUtil.rollbackTransaction(connection);
                        throw new VPException("No presentation definition found to update with ID: " +
                                presentationDefinition.getDefinitionId());
                    }
                }

                // 2. Replace credentials: delete existing, insert updated list
                if (presentationDefinition.getRequestedCredentials() != null) {
                    try (PreparedStatement ps = connection.prepareStatement(
                            SQL_DELETE_CREDENTIALS_BY_DEFINITION)) {
                        ps.setString(1, presentationDefinition.getDefinitionId());
                        ps.executeUpdate();
                    }
                    insertCredentials(connection, presentationDefinition.getDefinitionId(),
                            presentationDefinition.getRequestedCredentials());
                }

                IdentityDatabaseUtil.commitTransaction(connection);

            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new VPException("Error updating presentation definition: " +
                    presentationDefinition.getDefinitionId(), e);
        }
    }

    @Override
    public void deletePresentationDefinition(String definitionId, int tenantId) throws VPException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_DELETE_DEFINITION)) {
                ps.setString(1, definitionId);
                ps.setInt(2, tenantId);
                ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new VPException("Error deleting presentation definition: " + definitionId, e);
        }
    }

    @Override
    public boolean presentationDefinitionExists(String definitionId, int tenantId)
            throws VPException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_EXISTS_DEFINITION)) {
                ps.setString(1, definitionId);
                ps.setInt(2, tenantId);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next();
                }
            }
        } catch (SQLException e) {
            throw new VPException(
                    "Error checking presentation definition existence: " + definitionId, e);
        }
    }

    @Override
    public PresentationDefinition getPresentationDefinitionByName(String name, int tenantId)
            throws VPException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            PresentationDefinition definition = null;
            try (PreparedStatement ps = connection.prepareStatement(SQL_SELECT_DEFINITION_BY_NAME)) {
                ps.setString(1, name);
                ps.setInt(2, tenantId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        definition = mapHeaderRow(rs);
                    }
                }
            }
            if (definition != null) {
                definition.setRequestedCredentials(
                        queryCredentials(connection, definition.getDefinitionId()));
            }
            return definition;
        } catch (SQLException e) {
            throw new VPException("Error retrieving presentation definition by name: " + name, e);
        }
    }

    // ---- Private helpers ----

    /**
     * Insert a list of requested credentials for a definition within an existing connection/transaction.
     */
    private void insertCredentials(Connection connection, String definitionId,
            List<RequestedCredential> credentials) throws SQLException {

        if (credentials == null || credentials.isEmpty()) {
            return;
        }
        try (PreparedStatement ps = connection.prepareStatement(SQL_INSERT_CREDENTIAL)) {
            for (RequestedCredential cred : credentials) {
                ps.setString(1, definitionId);
                ps.setString(2, cred.getType());
                ps.setString(3, cred.getPurpose());
                ps.setString(4, cred.getIssuer());
                ps.setString(5, serializeClaimConstraints(cred.getClaims()));
                ps.setString(6, cred.getIssuerCertPem());
                ps.setString(7, serializeClaims(cred.getTrustedIssuers()));
                ps.setString(8, cred.isEnforceTrustedIssuers() ? "1" : "0");
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }

    /**
     * Query credential rows for a definition and return as list.
     */
    private List<RequestedCredential> queryCredentials(Connection connection, String definitionId)
            throws SQLException {

        List<RequestedCredential> credentials = new ArrayList<>();
        try (PreparedStatement ps = connection.prepareStatement(
                SQL_SELECT_CREDENTIALS_BY_DEFINITION)) {
            ps.setString(1, definitionId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    RequestedCredential cred = new RequestedCredential();
                    cred.setType(rs.getString("CREDENTIAL_TYPE"));
                    cred.setPurpose(rs.getString("PURPOSE"));
                    cred.setIssuer(rs.getString("ISSUER"));
                    cred.setClaims(deserializeClaimConstraints(rs.getString("CLAIMS")));
                    cred.setIssuerCertPem(rs.getString("ISSUER_CERT"));
                    cred.setTrustedIssuers(deserializeClaims(rs.getString("TRUSTED_ISSUERS")));
                    cred.setEnforceTrustedIssuers("1".equals(rs.getString("ENFORCE_TRUSTED_ISSUERS")));
                    credentials.add(cred);
                }
            }
        }
        return credentials;
    }



    /**
     * Map a ResultSet row from IDN_PRESENTATION_DEFINITION to a PresentationDefinition (no credentials).
     */
    private PresentationDefinition mapHeaderRow(ResultSet rs) throws SQLException {

        return new PresentationDefinition.Builder()
                .definitionId(rs.getString("DEFINITION_ID"))
                .name(rs.getString("NAME"))
                .description(rs.getString("DESCRIPTION"))
                .tenantId(rs.getInt("TENANT_ID"))
                .build();
    }

    /**
     * Serialize a list of ClaimConstraint objects to a JSON string.
     */
    private String serializeClaimConstraints(List<ClaimConstraint> claims) {

        if (claims == null || claims.isEmpty()) {
            return null;
        }
        return GSON.toJson(claims);
    }

    /**
     * Deserialize a claims string to a list of ClaimConstraint objects.
     * Supports both the new JSON format and the legacy comma-separated format.
     * Legacy entries are treated as mandatory claims with no allowed values.
     */
    private List<ClaimConstraint> deserializeClaimConstraints(String claimsStr) {

        if (claimsStr == null || claimsStr.trim().isEmpty()) {
            return new ArrayList<>();
        }
        String trimmed = claimsStr.trim();
        if (trimmed.startsWith("[")) {
            try {
                List<ClaimConstraint> result = GSON.fromJson(trimmed, CLAIM_CONSTRAINT_LIST_TYPE);
                return result != null ? result : new ArrayList<>();
            } catch (JsonSyntaxException e) {
                // Fall through to legacy CSV parsing
            }
        }
        // Legacy: comma-separated claim names — treat each as mandatory with no allowed values
        List<ClaimConstraint> result = new ArrayList<>();
        for (String token : trimmed.split(",")) {
            String name = token.trim();
            if (!name.isEmpty()) {
                ClaimConstraint cc = new ClaimConstraint(name);
                cc.setMandatory(true);
                result.add(cc);
            }
        }
        return result;
    }

    private String serializeClaims(List<String> values) {

        if (values == null || values.isEmpty()) {
            return null;
        }
        return String.join(",", values);
    }

    private List<String> deserializeClaims(String valuesStr) {

        if (valuesStr == null || valuesStr.trim().isEmpty()) {
            return new ArrayList<>();
        }
        List<String> result = new ArrayList<>();
        for (String token : valuesStr.split(",")) {
            String v = token.trim();
            if (!v.isEmpty()) {
                result.add(v);
            }
        }
        return result;
    }
}
