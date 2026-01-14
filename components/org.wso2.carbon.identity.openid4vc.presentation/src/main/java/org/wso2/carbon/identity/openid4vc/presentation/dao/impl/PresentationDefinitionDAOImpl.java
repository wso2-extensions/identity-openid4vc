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

package org.wso2.carbon.identity.openid4vc.presentation.dao.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.openid4vc.presentation.dao.PresentationDefinitionDAO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.PresentationDefinition;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of PresentationDefinitionDAO using JDBC.
 */
public class PresentationDefinitionDAOImpl implements PresentationDefinitionDAO {

    private static final Log log = LogFactory.getLog(PresentationDefinitionDAOImpl.class);

    // SQL Queries
    private static final String SQL_INSERT_PRESENTATION_DEFINITION = "INSERT INTO IDN_PRESENTATION_DEFINITION (DEFINITION_ID, NAME, DESCRIPTION, "
            +
            "DEFINITION_JSON, IS_DEFAULT, CREATED_AT, UPDATED_AT, TENANT_ID) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String SQL_SELECT_PRESENTATION_DEFINITION_BY_ID = "SELECT * FROM IDN_PRESENTATION_DEFINITION WHERE DEFINITION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_SELECT_ALL_PRESENTATION_DEFINITIONS = "SELECT * FROM IDN_PRESENTATION_DEFINITION WHERE TENANT_ID = ?";

    private static final String SQL_SELECT_DEFAULT_PRESENTATION_DEFINITION = "SELECT * FROM IDN_PRESENTATION_DEFINITION WHERE IS_DEFAULT = ? AND TENANT_ID = ?";

    private static final String SQL_UPDATE_PRESENTATION_DEFINITION = "UPDATE IDN_PRESENTATION_DEFINITION SET NAME = ?, DESCRIPTION = ?, DEFINITION_JSON = ?, "
            +
            "IS_DEFAULT = ?, UPDATED_AT = ? WHERE DEFINITION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_DELETE_PRESENTATION_DEFINITION = "DELETE FROM IDN_PRESENTATION_DEFINITION WHERE DEFINITION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_CHECK_PRESENTATION_DEFINITION_EXISTS = "SELECT 1 FROM IDN_PRESENTATION_DEFINITION WHERE DEFINITION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_CLEAR_DEFAULT = "UPDATE IDN_PRESENTATION_DEFINITION SET IS_DEFAULT = ? WHERE TENANT_ID = ?";

    private static final String SQL_SET_AS_DEFAULT = "UPDATE IDN_PRESENTATION_DEFINITION SET IS_DEFAULT = ? WHERE DEFINITION_ID = ? AND TENANT_ID = ?";

    @Override
    public void createPresentationDefinition(PresentationDefinition presentationDefinition)
            throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(
                    SQL_INSERT_PRESENTATION_DEFINITION)) {
                ps.setString(1, presentationDefinition.getDefinitionId());
                ps.setString(2, presentationDefinition.getName());
                ps.setString(3, presentationDefinition.getDescription());
                ps.setString(4, presentationDefinition.getDefinitionJson());
                ps.setBoolean(5, presentationDefinition.isDefault());
                ps.setLong(6, presentationDefinition.getCreatedAt());
                ps.setObject(7, presentationDefinition.getUpdatedAt());
                ps.setInt(8, presentationDefinition.getTenantId());

                ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

                if (log.isDebugEnabled()) {
                    log.debug("Created presentation definition: " +
                            presentationDefinition.getDefinitionId());
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            String validationMsg = "Error creating presentation definition: " +
                    presentationDefinition.getDefinitionId();
            if (e.getMessage() != null && e.getMessage().contains("CONSTRAINT_INDEX_6F6")) {
                validationMsg = "Presentation definition with name '" +
                        presentationDefinition.getName() + "' already exists.";
            }
            throw new VPException(validationMsg, e);
        }
    }

    @Override
    public PresentationDefinition getPresentationDefinitionById(String definitionId, int tenantId)
            throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(
                    SQL_SELECT_PRESENTATION_DEFINITION_BY_ID)) {
                ps.setString(1, definitionId);
                ps.setInt(2, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return mapResultSetToPresentationDefinition(rs);
                    }
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error retrieving presentation definition: " + definitionId, e);
        }
        return null;
    }

    @Override
    public List<PresentationDefinition> getAllPresentationDefinitions(int tenantId)
            throws VPException {
        List<PresentationDefinition> definitions = new ArrayList<>();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(
                    SQL_SELECT_ALL_PRESENTATION_DEFINITIONS)) {
                ps.setInt(1, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        definitions.add(mapResultSetToPresentationDefinition(rs));
                    }
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error retrieving all presentation definitions", e);
        }
        return definitions;
    }

    @Override
    public PresentationDefinition getDefaultPresentationDefinition(int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(
                    SQL_SELECT_DEFAULT_PRESENTATION_DEFINITION)) {
                ps.setBoolean(1, true);
                ps.setInt(2, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return mapResultSetToPresentationDefinition(rs);
                    }
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error retrieving default presentation definition", e);
        }
        return null;
    }

    @Override
    public void updatePresentationDefinition(PresentationDefinition presentationDefinition)
            throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(
                    SQL_UPDATE_PRESENTATION_DEFINITION)) {
                ps.setString(1, presentationDefinition.getName());
                ps.setString(2, presentationDefinition.getDescription());
                ps.setString(3, presentationDefinition.getDefinitionJson());
                ps.setBoolean(4, presentationDefinition.isDefault());
                ps.setLong(5, System.currentTimeMillis());
                ps.setString(6, presentationDefinition.getDefinitionId());
                ps.setInt(7, presentationDefinition.getTenantId());

                int updated = ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

                if (log.isDebugEnabled()) {
                    log.debug("Updated presentation definition: " +
                            presentationDefinition.getDefinitionId() + ", rows affected: " + updated);
                }
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
            try (PreparedStatement ps = connection.prepareStatement(
                    SQL_DELETE_PRESENTATION_DEFINITION)) {
                ps.setString(1, definitionId);
                ps.setInt(2, tenantId);

                int deleted = ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

                if (log.isDebugEnabled()) {
                    log.debug("Deleted presentation definition: " + definitionId +
                            ", rows affected: " + deleted);
                }
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
            try (PreparedStatement ps = connection.prepareStatement(
                    SQL_CHECK_PRESENTATION_DEFINITION_EXISTS)) {
                ps.setString(1, definitionId);
                ps.setInt(2, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next();
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error checking presentation definition existence: " +
                    definitionId, e);
        }
    }

    @Override
    public void setAsDefault(String definitionId, int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try {
                // First, clear all defaults
                try (PreparedStatement ps = connection.prepareStatement(SQL_CLEAR_DEFAULT)) {
                    ps.setBoolean(1, false);
                    ps.setInt(2, tenantId);
                    ps.executeUpdate();
                }

                // Then set the specified definition as default
                try (PreparedStatement ps = connection.prepareStatement(SQL_SET_AS_DEFAULT)) {
                    ps.setBoolean(1, true);
                    ps.setString(2, definitionId);
                    ps.setInt(3, tenantId);
                    ps.executeUpdate();
                }

                IdentityDatabaseUtil.commitTransaction(connection);

                if (log.isDebugEnabled()) {
                    log.debug("Set presentation definition as default: " + definitionId);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new VPException("Error setting presentation definition as default: " +
                    definitionId, e);
        }
    }

    /**
     * Map ResultSet to PresentationDefinition object.
     */
    private PresentationDefinition mapResultSetToPresentationDefinition(ResultSet rs)
            throws SQLException {
        Long updatedAt = rs.getObject("UPDATED_AT") != null ? rs.getLong("UPDATED_AT") : null;

        return new PresentationDefinition.Builder()
                .id(rs.getInt("ID"))
                .definitionId(rs.getString("DEFINITION_ID"))
                .name(rs.getString("NAME"))
                .description(rs.getString("DESCRIPTION"))
                .definitionJson(rs.getString("DEFINITION_JSON"))
                .isDefault(rs.getBoolean("IS_DEFAULT"))
                .createdAt(rs.getLong("CREATED_AT"))
                .updatedAt(updatedAt)
                .tenantId(rs.getInt("TENANT_ID"))
                .build();
    }
}
