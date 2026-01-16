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
import org.wso2.carbon.identity.openid4vc.presentation.dao.ApplicationPresentationDefinitionMappingDAO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.ApplicationPresentationDefinitionMapping;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Implementation of ApplicationPresentationDefinitionMappingDAO using JDBC.
 */
public class ApplicationPresentationDefinitionMappingDAOImpl 
        implements ApplicationPresentationDefinitionMappingDAO {

    private static final Log log = LogFactory.getLog(ApplicationPresentationDefinitionMappingDAOImpl.class);

    // SQL Queries
    private static final String SQL_INSERT_MAPPING = 
            "INSERT INTO IDN_APPLICATION_PRESENTATION_DEFINITION " +
            "(APPLICATION_ID, PRESENTATION_DEFINITION_ID, TENANT_ID, CREATED_AT, UPDATED_AT) " +
            "VALUES (?, ?, ?, ?, ?)";

    private static final String SQL_UPDATE_MAPPING =
            "UPDATE IDN_APPLICATION_PRESENTATION_DEFINITION SET " +
            "PRESENTATION_DEFINITION_ID = ?, UPDATED_AT = ? " +
            "WHERE APPLICATION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_SELECT_MAPPING_BY_APP_ID =
            "SELECT APPLICATION_ID, PRESENTATION_DEFINITION_ID, TENANT_ID, CREATED_AT, UPDATED_AT " +
            "FROM IDN_APPLICATION_PRESENTATION_DEFINITION " +
            "WHERE APPLICATION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_SELECT_PRES_DEF_ID =
            "SELECT PRESENTATION_DEFINITION_ID FROM IDN_APPLICATION_PRESENTATION_DEFINITION " +
            "WHERE APPLICATION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_DELETE_MAPPING =
            "DELETE FROM IDN_APPLICATION_PRESENTATION_DEFINITION " +
            "WHERE APPLICATION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_CHECK_MAPPING_EXISTS =
            "SELECT 1 FROM IDN_APPLICATION_PRESENTATION_DEFINITION " +
            "WHERE APPLICATION_ID = ? AND TENANT_ID = ?";

    @Override
    public void createOrUpdateMapping(ApplicationPresentationDefinitionMapping mapping) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try {
                // Check if mapping exists
                if (mappingExists(mapping.getApplicationId(), mapping.getTenantId())) {
                    // Update existing mapping
                    updateMapping(connection, mapping);
                } else {
                    // Create new mapping
                    createMapping(connection, mapping);
                }
                IdentityDatabaseUtil.commitTransaction(connection);
                
                if (log.isDebugEnabled()) {
                    log.debug("Mapping created/updated successfully for application: " + 
                            mapping.getApplicationId());
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new VPException("Error creating or updating application-presentation definition mapping", e);
        }
    }

    @Override
    public String getPresentationDefinitionIdByApplicationId(String applicationId, int tenantId) 
            throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_SELECT_PRES_DEF_ID)) {
                ps.setString(1, applicationId);
                ps.setInt(2, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return rs.getString("PRESENTATION_DEFINITION_ID");
                    }
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error retrieving presentation definition ID for application: " + 
                    applicationId, e);
        }
        return null;
    }

    @Override
    public ApplicationPresentationDefinitionMapping getMappingByApplicationId(String applicationId, 
                                                                               int tenantId) 
            throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_SELECT_MAPPING_BY_APP_ID)) {
                ps.setString(1, applicationId);
                ps.setInt(2, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return mapResultSetToMapping(rs);
                    }
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error retrieving mapping for application: " + applicationId, e);
        }
        return null;
    }

    @Override
    public void deleteMapping(String applicationId, int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_DELETE_MAPPING)) {
                ps.setString(1, applicationId);
                ps.setInt(2, tenantId);

                int deleted = ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

                if (log.isDebugEnabled()) {
                    log.debug("Mapping deleted for application: " + applicationId + 
                            ". Rows affected: " + deleted);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new VPException("Error deleting mapping for application: " + applicationId, e);
        }
    }

    @Override
    public boolean mappingExists(String applicationId, int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_CHECK_MAPPING_EXISTS)) {
                ps.setString(1, applicationId);
                ps.setInt(2, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next();
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error checking if mapping exists for application: " + 
                    applicationId, e);
        }
    }

    /**
     * Create a new mapping in the database.
     */
    private void createMapping(Connection connection, 
                               ApplicationPresentationDefinitionMapping mapping) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(SQL_INSERT_MAPPING)) {
            ps.setString(1, mapping.getApplicationId());
            ps.setString(2, mapping.getPresentationDefinitionId());
            ps.setInt(3, mapping.getTenantId());
            ps.setLong(4, System.currentTimeMillis());
            ps.setLong(5, System.currentTimeMillis());

            ps.executeUpdate();
        }
    }

    /**
     * Update an existing mapping in the database.
     */
    private void updateMapping(Connection connection, 
                               ApplicationPresentationDefinitionMapping mapping) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(SQL_UPDATE_MAPPING)) {
            ps.setString(1, mapping.getPresentationDefinitionId());
            ps.setLong(2, System.currentTimeMillis());
            ps.setString(3, mapping.getApplicationId());
            ps.setInt(4, mapping.getTenantId());

            ps.executeUpdate();
        }
    }

    /**
     * Map ResultSet to ApplicationPresentationDefinitionMapping.
     */
    private ApplicationPresentationDefinitionMapping mapResultSetToMapping(ResultSet rs) 
            throws SQLException {
        return new ApplicationPresentationDefinitionMapping.Builder()
                .applicationId(rs.getString("APPLICATION_ID"))
                .presentationDefinitionId(rs.getString("PRESENTATION_DEFINITION_ID"))
                .tenantId(rs.getInt("TENANT_ID"))
                .createdAt(rs.getLong("CREATED_AT"))
                .updatedAt(rs.getLong("UPDATED_AT"))
                .build();
    }
}
