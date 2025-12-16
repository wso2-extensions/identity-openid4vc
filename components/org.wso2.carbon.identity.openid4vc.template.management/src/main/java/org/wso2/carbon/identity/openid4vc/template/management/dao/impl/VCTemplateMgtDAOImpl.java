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

import org.apache.commons.collections.CollectionUtils;
import org.wso2.carbon.identity.core.model.ExpressionNode;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.openid4vc.template.management.constant.SQLConstants;
import org.wso2.carbon.identity.openid4vc.template.management.dao.VCTemplateMgtDAO;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtClientException;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtException;
import org.wso2.carbon.identity.openid4vc.template.management.model.VCTemplate;
import org.wso2.carbon.identity.openid4vc.template.management.util.VCTemplateFilterQueryBuilder;
import org.wso2.carbon.identity.openid4vc.template.management.util.VCTemplateFilterUtil;
import org.wso2.carbon.identity.openid4vc.template.management.util.VCTemplateMgtExceptionHandler;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.AFTER;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.BEFORE;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_DELETION_ERROR;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_PERSISTENCE_ERROR;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_RETRIEVAL_ERROR;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_TEMPLATE_NOT_FOUND;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_TRANSACTION_ERROR;

/**
 * JDBC implementation of {@link VCTemplateMgtDAO}.
 */
public class VCTemplateMgtDAOImpl implements VCTemplateMgtDAO {

    @Override
    public List<VCTemplate> list(int tenantId) throws VCTemplateMgtException {

        List<VCTemplate> results = new ArrayList<>();
        String sql = SQLConstants.LIST_TEMPLATES;
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, tenantId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    results.add(buildConfigurationListItem(rs));
                }
            }
        } catch (SQLException e) {
            throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_RETRIEVAL_ERROR, e);
        }
        return results;
    }

    @Override
    public List<VCTemplate> list(Integer limit, Integer tenantId, String sortOrder,
                                 List<ExpressionNode> expressionNodes) throws VCTemplateMgtException {

        List<VCTemplate> results = new ArrayList<>();
        try {
            VCTemplateFilterQueryBuilder filterQueryBuilder =
                    VCTemplateFilterUtil.getFilterQueryBuilder(expressionNodes);
            Map<Integer, String> filterAttributeValue = filterQueryBuilder.getFilterAttributeValue();

            try (Connection conn = IdentityDatabaseUtil.getDBConnection(false)) {
                String databaseName = conn.getMetaData().getDatabaseProductName();
                String sqlStmt = buildGetConfigurationsSqlStatement(databaseName, tenantId,
                        filterQueryBuilder.getFilterQuery(), sortOrder, limit);
                
                try (PreparedStatement ps = conn.prepareStatement(sqlStmt)) {
                    if (filterAttributeValue != null) {
                        for (Map.Entry<Integer, String> entry : filterAttributeValue.entrySet()) {
                            ps.setString(entry.getKey(), entry.getValue());
                        }
                    }
                    
                    try (ResultSet rs = ps.executeQuery()) {
                        while (rs.next()) {
                            VCTemplate cfg = buildConfigurationListItem(rs);
                            cfg.setCursorKey(rs.getInt("CURSOR_KEY"));
                            results.add(cfg);
                        }
                    }
                }
            }
        } catch (VCTemplateMgtClientException e) {
            throw e;
        } catch (SQLException e) {
            throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_RETRIEVAL_ERROR, e);
        }
        return results;
    }

    @Override
    public Integer getTemplatesCount(Integer tenantId, List<ExpressionNode> expressionNodes)
            throws VCTemplateMgtException {

        try {
            // Remove after/before from expression nodes for count query.
            List<ExpressionNode> expressionNodesCopy = new ArrayList<>(expressionNodes);
            expressionNodesCopy.removeIf(expressionNode ->
                    AFTER.equals(expressionNode.getAttributeValue()) ||
                    BEFORE.equals(expressionNode.getAttributeValue()));

            VCTemplateFilterQueryBuilder filterQueryBuilder =
                    VCTemplateFilterUtil.getFilterQueryBuilder(expressionNodesCopy);
            Map<Integer, String> filterAttributeValue = filterQueryBuilder.getFilterAttributeValue();

            String sqlStmt = SQLConstants.GET_VC_TEMPLATES_COUNT + filterQueryBuilder.getFilterQuery() +
                    SQLConstants.GET_VC_TEMPLATES_COUNT_TAIL;

            try (Connection conn = IdentityDatabaseUtil.getDBConnection(false);
                 PreparedStatement ps = conn.prepareStatement(sqlStmt)) {
                
                if (filterAttributeValue != null) {
                    for (Map.Entry<Integer, String> entry : filterAttributeValue.entrySet()) {
                        ps.setString(entry.getKey(), entry.getValue());
                    }
                }
                ps.setInt((filterAttributeValue != null ? filterAttributeValue.size() : 0) + 1, tenantId);
                
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return rs.getInt(1);
                    }
                }
            }
        } catch (VCTemplateMgtClientException e) {
            throw e;
        } catch (SQLException e) {
            throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_RETRIEVAL_ERROR, e);
        }
        return 0;
    }

    @Override
    public VCTemplate get(String id, int tenantId) throws VCTemplateMgtException {

        String sql = SQLConstants.GET_TEMPLATE_BY_ID;
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return buildConfiguration(rs, conn);
                }
            }
        } catch (SQLException e) {
            throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_RETRIEVAL_ERROR, e);
        }
        return null;
    }

    @Override
    public VCTemplate getByIdentifier(String identifier, int tenantId) throws VCTemplateMgtException {
        String sql = SQLConstants.GET_TEMPLATE_BY_IDENTIFIER;
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, identifier);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return buildConfiguration(rs, conn);
                }
            }
        } catch (SQLException e) {
            throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_RETRIEVAL_ERROR, e);
        }
        return null;
    }

    @Override
    public VCTemplate getByOfferId(String offerId, int tenantId) throws VCTemplateMgtException {

        String sql = SQLConstants.GET_TEMPLATE_BY_OFFER_ID;
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, offerId);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return buildConfiguration(rs, conn);
                }
            }
        } catch (SQLException e) {
            throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_RETRIEVAL_ERROR, e);
        }
        return null;
    }

    @Override
    public boolean existsByIdentifier(String identifier, int tenantId) throws VCTemplateMgtException {

        String sql = SQLConstants.EXISTS_BY_IDENTIFIER;
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, tenantId);
            ps.setString(2, identifier);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_RETRIEVAL_ERROR, e);
        }
    }

    @Override
    public VCTemplate add(VCTemplate template, int tenantId)
            throws VCTemplateMgtException {

        String insertCfg = SQLConstants.INSERT_TEMPLATE;
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(true);
             PreparedStatement ps = conn.prepareStatement(insertCfg)) {
            try {
                String id = UUID.randomUUID().toString();
                ps.setString(1, id);
                ps.setInt(2, tenantId);
                ps.setString(3, template.getIdentifier());
                ps.setString(4, template.getDisplayName());
                ps.setString(5, template.getDescription());
                ps.setString(6, template.getFormat());
                ps.setString(7, template.getSigningAlgorithm());
                ps.setInt(8, template.getExpiresIn());
                ps.setString(9, template.getOfferId());
                ps.executeUpdate();

                if (CollectionUtils.isNotEmpty(template.getClaims())) {
                    addClaims(conn, id, template.getClaims());
                }

                IdentityDatabaseUtil.commitTransaction(conn);
                return get(id, tenantId);
            } catch (SQLException | VCTemplateMgtException e) {
                IdentityDatabaseUtil.rollbackTransaction(conn);
                if (e instanceof VCTemplateMgtException) {
                    throw (VCTemplateMgtException) e;
                }
                throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_TRANSACTION_ERROR, e);
            }
        } catch (SQLException e) {
            throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_PERSISTENCE_ERROR, e);
        }
    }

    @Override
    public VCTemplate update(String id, VCTemplate template, int tenantId)
            throws VCTemplateMgtException {

        String updateCfg = SQLConstants.UPDATE_TEMPLATE;
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(true);
             PreparedStatement ps = conn.prepareStatement(updateCfg)) {
            try {
                ps.setString(1, template.getIdentifier());
                ps.setString(2, template.getDisplayName());
                ps.setString(3, template.getDescription());
                ps.setString(4, template.getFormat());
                ps.setString(5, template.getSigningAlgorithm());
                ps.setInt(6, template.getExpiresIn());
                ps.setString(7, template.getOfferId());
                ps.setInt(8, tenantId);
                ps.setString(9, id);
                int updated = ps.executeUpdate();
                if (updated == 0) {
                    throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_TEMPLATE_NOT_FOUND);
                }

                deleteClaims(conn, id);
                if (CollectionUtils.isNotEmpty(template.getClaims())) {
                    addClaims(conn, id, template.getClaims());
                }

                IdentityDatabaseUtil.commitTransaction(conn);
                return get(id, tenantId);
            } catch (SQLException | VCTemplateMgtException e) {
                IdentityDatabaseUtil.rollbackTransaction(conn);
                if (e instanceof VCTemplateMgtException) {
                    throw (VCTemplateMgtException) e;
                }
                throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_PERSISTENCE_ERROR, e);
            }
        } catch (SQLException e) {
            throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_PERSISTENCE_ERROR, e);
        }
    }

    @Override
    public void delete(String id, int tenantId) throws VCTemplateMgtException {

        String deleteCfg = SQLConstants.DELETE_TEMPLATE;
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(true);
             PreparedStatement ps = conn.prepareStatement(deleteCfg)) {
            try {
                ps.setInt(1, tenantId);
                ps.setString(2, id);
                ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(conn);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(conn);
                throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_TRANSACTION_ERROR, e);
            }
        } catch (SQLException e) {
            throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_DELETION_ERROR, e);
        }
    }

    @Override
    public void updateOfferId(String configId, String offerId, int tenantId) throws VCTemplateMgtException {

        String sql = SQLConstants.UPDATE_OFFER_ID;
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(true);
             PreparedStatement ps = conn.prepareStatement(sql)) {
            try {
                ps.setString(1, offerId);
                ps.setInt(2, tenantId);
                ps.setString(3, configId);
                int updated = ps.executeUpdate();
                if (updated == 0) {
                    throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_TEMPLATE_NOT_FOUND);
                }
                IdentityDatabaseUtil.commitTransaction(conn);
            } catch (SQLException | VCTemplateMgtException e) {
                IdentityDatabaseUtil.rollbackTransaction(conn);
                if (e instanceof VCTemplateMgtException) {
                    throw (VCTemplateMgtException) e;
                }
                throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_PERSISTENCE_ERROR, e);
            }
        } catch (SQLException e) {
            throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_PERSISTENCE_ERROR, e);
        }
    }

    /**
     * Build SQL statement to get configurations with pagination.
     *
     * @param databaseName Database name.
     * @param tenantId     Tenant ID.
     * @param filterQuery  Filter query.
     * @param sortOrder    Sort order.
     * @param limit        Limit.
     * @return SQL statement to retrieve configurations.
     */
    private String buildGetConfigurationsSqlStatement(String databaseName, Integer tenantId, String filterQuery,
                                                      String sortOrder, Integer limit) {

        if (databaseName.contains(SQLConstants.MICROSOFT)) {
            return String.format(SQLConstants.GET_VC_TEMPLATES_MSSQL, limit) + filterQuery +
                    String.format(SQLConstants.GET_VC_TEMPLATES_TAIL_MSSQL, tenantId, sortOrder);
        } else if (databaseName.contains(SQLConstants.ORACLE)) {
            return SQLConstants.GET_VC_TEMPLATES + filterQuery +
                    String.format(SQLConstants.GET_VC_TEMPLATES_TAIL_ORACLE, tenantId, sortOrder, limit);
        }
        return SQLConstants.GET_VC_TEMPLATES + filterQuery +
                String.format(SQLConstants.GET_VC_TEMPLATES_TAIL, tenantId, sortOrder, limit);
    }

    /**
     * Build VC credential template from result set.
     *
     * @param rs   Result set
     * @param conn DB connection
     * @return VC credential template
     * @throws SQLException on SQL errors
     */
    private VCTemplate buildConfiguration(ResultSet rs, Connection conn) throws SQLException {

        VCTemplate cfg = new VCTemplate();
        cfg.setId(rs.getString("ID"));
        cfg.setIdentifier(rs.getString("IDENTIFIER"));
        cfg.setDisplayName(rs.getString("DISPLAY_NAME"));
        cfg.setDescription(rs.getString("DESCRIPTION"));
        cfg.setFormat(rs.getString("FORMAT"));
        cfg.setSigningAlgorithm(rs.getString("SIGNING_ALG"));
        int expiresIn = rs.getInt("EXPIRES_IN");
        if (!rs.wasNull()) {
            cfg.setExpiresIn(expiresIn);
        }
        String offerId = rs.getString("OFFER_ID");
        if (!rs.wasNull()) {
            cfg.setOfferId(offerId);
        }
        cfg.setClaims(getClaimsByConfigId(conn, cfg.getId()));
        return cfg;
    }

    /**
     * Build VC credential template from result set.
     *
     * @param rs Result set
     * @return VC credential template
     * @throws SQLException on SQL errors
     */
    private VCTemplate buildConfigurationListItem(ResultSet rs) throws SQLException {

        VCTemplate cfg = new VCTemplate();
        cfg.setId(rs.getString("ID"));
        cfg.setIdentifier(rs.getString("IDENTIFIER"));
        cfg.setDisplayName(rs.getString("DISPLAY_NAME"));
        cfg.setDescription(rs.getString("DESCRIPTION"));
        return cfg;
    }

    /**
     * Get claims by template primary key.
     *
     * @param conn     DB connection
     * @param configId Template primary key
     * @return List of claim URIs
     * @throws SQLException on SQL errors
     */
    private List<String> getClaimsByConfigId(Connection conn, String configId) throws SQLException {

        String sql = SQLConstants.LIST_CLAIMS_BY_TEMPLATE_ID;
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, configId);
            try (ResultSet rs = ps.executeQuery()) {
                List<String> list = new ArrayList<>();
                while (rs.next()) {
                    list.add(rs.getString("CLAIM_URI"));
                }
                return list;
            }
        }
    }

    /**
     * Add claims for a template.
     *
     * @param conn     DB connection
     * @param configId Template primary key
     * @param claims   List of claim URIs
     * @throws SQLException on SQL errors
     */
    private void addClaims(Connection conn, String configId, List<String> claims) throws SQLException {

        String insert = SQLConstants.INSERT_CLAIM;
        try (PreparedStatement ps = conn.prepareStatement(insert)) {
            for (String claim : claims) {
                ps.setString(1, configId);
                ps.setString(2, claim);
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }

    /**
     * Delete claims for a template.
     *
     * @param conn     DB connection
     * @param configId Template primary key
     * @throws SQLException on SQL errors
     */
    private void deleteClaims(Connection conn, String configId) throws SQLException {

        try (PreparedStatement ps = conn.prepareStatement(SQLConstants.DELETE_CLAIMS_BY_TEMPLATE_ID)) {
            ps.setString(1, configId);
            ps.executeUpdate();
        }
    }
}
