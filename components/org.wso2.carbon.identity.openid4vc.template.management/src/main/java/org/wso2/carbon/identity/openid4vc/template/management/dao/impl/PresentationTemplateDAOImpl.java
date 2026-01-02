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

package org.wso2.carbon.identity.openid4vc.template.management.dao.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.openid4vc.template.management.constant.SQLConstants;
import org.wso2.carbon.identity.openid4vc.template.management.dao.PresentationTemplateDAO;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtException;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationTemplate;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * DAO implementation for Presentation Template operations.
 */
public class PresentationTemplateDAOImpl implements PresentationTemplateDAO {

    private static final Log log = LogFactory.getLog(PresentationTemplateDAOImpl.class);
    private static final String VERSION_CURRENT = "current";

    @Override
    public PresentationTemplate createTemplate(PresentationTemplate template, int tenantId)
            throws VCTemplateMgtException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement stmt = connection.prepareStatement(SQLConstants.CREATE_PRESENTATION_TEMPLATE)) {

                String id = UUID.randomUUID().toString();
                Timestamp now = new Timestamp(System.currentTimeMillis());

                stmt.setString(1, id);
                stmt.setInt(2, tenantId);
                stmt.setString(3, template.getClientId());
                stmt.setString(4, template.getVersion() != null ? template.getVersion() : VERSION_CURRENT);
                stmt.setString(5, template.getTemplateJson());
                stmt.setBoolean(6, template.isPublic());
                stmt.setString(7, template.getStatus() != null ? template.getStatus() : "active");
                stmt.setTimestamp(8, now);
                stmt.setTimestamp(9, now);

                stmt.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

                template.setId(id);
                template.setCreatedAt(now);
                template.setUpdatedAt(now);

                if (log.isDebugEnabled()) {
                    log.debug("Created presentation template: " + id + " for client: " + template.getClientId());
                }

                return template;
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new VCTemplateMgtException("Error creating presentation template", e);
            }
        } catch (SQLException e) {
            throw new VCTemplateMgtException("Error getting database connection", e);
        }
    }

    @Override
    public PresentationTemplate getTemplateByClientId(String clientId, String version, int tenantId)
            throws VCTemplateMgtException {

        if (version == null || version.isEmpty()) {
            version = VERSION_CURRENT;
        }

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement stmt = connection.prepareStatement(SQLConstants.GET_PRESENTATION_TEMPLATE)) {

            stmt.setString(1, clientId);
            stmt.setString(2, version);
            stmt.setInt(3, tenantId);

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return mapResultSetToTemplate(rs);
                }
            }
        } catch (SQLException e) {
            throw new VCTemplateMgtException("Error retrieving presentation template", e);
        }

        return null;
    }

    @Override
    public PresentationTemplate updateTemplate(PresentationTemplate template, int tenantId)
            throws VCTemplateMgtException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement stmt = connection.prepareStatement(SQLConstants.UPDATE_PRESENTATION_TEMPLATE)) {

                Timestamp now = new Timestamp(System.currentTimeMillis());

                stmt.setString(1, template.getTemplateJson());
                stmt.setBoolean(2, template.isPublic());
                stmt.setString(3, template.getStatus());
                stmt.setTimestamp(4, now);
                stmt.setString(5, template.getClientId());
                stmt.setString(6, template.getVersion() != null ? template.getVersion() : VERSION_CURRENT);
                stmt.setInt(7, tenantId);

                int rowsAffected = stmt.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

                if (rowsAffected == 0) {
                    throw new VCTemplateMgtException("Template not found for update");
                }

                template.setUpdatedAt(now);

                if (log.isDebugEnabled()) {
                    log.debug("Updated presentation template for client: " + template.getClientId());
                }

                return template;
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new VCTemplateMgtException("Error updating presentation template", e);
            }
        } catch (SQLException e) {
            throw new VCTemplateMgtException("Error getting database connection", e);
        }
    }

    @Override
    public void deleteTemplate(String clientId, String version, int tenantId) throws VCTemplateMgtException {

        if (version == null || version.isEmpty()) {
            version = VERSION_CURRENT;
        }

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement stmt = connection.prepareStatement(SQLConstants.DELETE_PRESENTATION_TEMPLATE)) {

                stmt.setString(1, clientId);
                stmt.setString(2, version);
                stmt.setInt(3, tenantId);

                stmt.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

                if (log.isDebugEnabled()) {
                    log.debug("Deleted presentation template for client: " + clientId);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new VCTemplateMgtException("Error deleting presentation template", e);
            }
        } catch (SQLException e) {
            throw new VCTemplateMgtException("Error getting database connection", e);
        }
    }

    @Override
    public List<PresentationTemplate> listTemplates(int tenantId) throws VCTemplateMgtException {

        List<PresentationTemplate> templates = new ArrayList<>();

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement stmt = connection.prepareStatement(SQLConstants.LIST_PRESENTATION_TEMPLATES)) {

            stmt.setInt(1, tenantId);

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    templates.add(mapResultSetToTemplate(rs));
                }
            }
        } catch (SQLException e) {
            throw new VCTemplateMgtException("Error listing presentation templates", e);
        }

        return templates;
    }

    @Override
    public boolean templateExists(String clientId, String version, int tenantId) throws VCTemplateMgtException {

        if (version == null || version.isEmpty()) {
            version = VERSION_CURRENT;
        }

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement stmt = connection.prepareStatement(SQLConstants.EXISTS_PRESENTATION_TEMPLATE)) {

            stmt.setString(1, clientId);
            stmt.setString(2, version);
            stmt.setInt(3, tenantId);

            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw new VCTemplateMgtException("Error checking template existence", e);
        }
    }

    private PresentationTemplate mapResultSetToTemplate(ResultSet rs) throws SQLException {
        PresentationTemplate template = new PresentationTemplate();
        template.setId(rs.getString("ID"));
        template.setTenantDomain(String.valueOf(rs.getInt("TENANT_ID")));
        template.setClientId(rs.getString("CLIENT_ID"));
        template.setVersion(rs.getString("VERSION"));
        template.setTemplateJson(rs.getString("TEMPLATE_JSON"));
        template.setPublic(rs.getBoolean("IS_PUBLIC"));
        template.setStatus(rs.getString("STATUS"));
        template.setCreatedAt(rs.getTimestamp("CREATED_AT"));
        template.setUpdatedAt(rs.getTimestamp("UPDATED_AT"));
        return template;
    }
}

