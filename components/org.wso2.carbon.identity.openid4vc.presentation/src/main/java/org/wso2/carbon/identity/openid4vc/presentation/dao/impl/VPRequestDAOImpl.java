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

import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.openid4vc.presentation.dao.VPRequestDAO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequestStatus;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of VPRequestDAO using JDBC.
 */
public class VPRequestDAOImpl implements VPRequestDAO {

    // SQL Queries
    private static final String SQL_INSERT_VP_REQUEST = "INSERT INTO IDN_VP_REQUEST (REQUEST_ID, TRANSACTION_ID, " +
            "CLIENT_ID, NONCE, PRESENTATION_DEFINITION_ID, PRESENTATION_DEFINITION, RESPONSE_URI, RESPONSE_MODE, " +
            "REQUEST_JWT, STATUS, CREATED_AT, EXPIRES_AT, TENANT_ID) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String SQL_SELECT_VP_REQUEST_BY_ID = "SELECT * FROM IDN_VP_REQUEST " +
            "WHERE REQUEST_ID = ? AND TENANT_ID = ?";

    private static final String SQL_SELECT_VP_REQUEST_BY_TRANSACTION_ID = "SELECT * FROM IDN_VP_REQUEST " +
            "WHERE TRANSACTION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_SELECT_REQUEST_IDS_BY_TRANSACTION_ID = "SELECT REQUEST_ID FROM IDN_VP_REQUEST " +
            "WHERE TRANSACTION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_UPDATE_VP_REQUEST_STATUS = "UPDATE IDN_VP_REQUEST SET STATUS = ? " +
            "WHERE REQUEST_ID = ? AND TENANT_ID = ?";

    private static final String SQL_UPDATE_VP_REQUEST_JWT = "UPDATE IDN_VP_REQUEST SET REQUEST_JWT = ? " +
            "WHERE REQUEST_ID = ? AND TENANT_ID = ?";

    private static final String SQL_DELETE_VP_REQUEST = "DELETE FROM IDN_VP_REQUEST " +
            "WHERE REQUEST_ID = ? AND TENANT_ID = ?";

    private static final String SQL_SELECT_EXPIRED_VP_REQUESTS = "SELECT * FROM IDN_VP_REQUEST " +
            "WHERE EXPIRES_AT < ? AND STATUS = ? AND TENANT_ID = ?";

    private static final String SQL_MARK_EXPIRED_REQUESTS = "UPDATE IDN_VP_REQUEST SET STATUS = ? " +
            "WHERE EXPIRES_AT < ? AND STATUS = ? AND TENANT_ID = ?";

    private static final String SQL_SELECT_VP_REQUESTS_BY_STATUS = "SELECT * FROM IDN_VP_REQUEST " +
            "WHERE STATUS = ? AND TENANT_ID = ?";

    @Override
    public void createVPRequest(VPRequest vpRequest) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_INSERT_VP_REQUEST)) {
                ps.setString(1, vpRequest.getRequestId());
                ps.setString(2, vpRequest.getTransactionId());
                ps.setString(3, vpRequest.getClientId());
                ps.setString(4, vpRequest.getNonce());
                ps.setString(5, vpRequest.getPresentationDefinitionId());
                ps.setString(6, vpRequest.getPresentationDefinition());
                ps.setString(7, vpRequest.getResponseUri());
                ps.setString(8, vpRequest.getResponseMode());
                ps.setString(9, vpRequest.getRequestJwt());
                ps.setString(10, vpRequest.getStatus().getValue());
                ps.setLong(11, vpRequest.getCreatedAt());
                ps.setLong(12, vpRequest.getExpiresAt());
                ps.setInt(13, vpRequest.getTenantId());

                ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new VPException("Error creating VP request: " + vpRequest.getRequestId(), e);
        }
    }

    @Override
    public VPRequest getVPRequestById(String requestId, int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_SELECT_VP_REQUEST_BY_ID)) {
                ps.setString(1, requestId);
                ps.setInt(2, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return mapResultSetToVPRequest(rs);
                    }
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error retrieving VP request: " + requestId, e);
        }
        return null;
    }

    @Override
    public VPRequest getVPRequestByTransactionId(String transactionId, int tenantId)
            throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(
                    SQL_SELECT_VP_REQUEST_BY_TRANSACTION_ID)) {
                ps.setString(1, transactionId);
                ps.setInt(2, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return mapResultSetToVPRequest(rs);
                    }
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error retrieving VP request by transaction: " + transactionId, e);
        }
        return null;
    }

    @Override
    public List<String> getRequestIdsByTransactionId(String transactionId, int tenantId)
            throws VPException {
        List<String> requestIds = new ArrayList<>();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(
                    SQL_SELECT_REQUEST_IDS_BY_TRANSACTION_ID)) {
                ps.setString(1, transactionId);
                ps.setInt(2, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        requestIds.add(rs.getString("REQUEST_ID"));
                    }
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error retrieving request IDs for transaction: " +
                    transactionId, e);
        }
        return requestIds;
    }

    @Override
    public void updateVPRequestStatus(String requestId, VPRequestStatus status, int tenantId)
            throws VPException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_UPDATE_VP_REQUEST_STATUS)) {
                ps.setString(1, status.getValue());
                ps.setString(2, requestId);
                ps.setInt(3, tenantId);

                int updated = ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

                if (updated == 0) {
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new VPException("Error updating VP request status: " + requestId, e);
        }
    }

    @Override
    public void updateVPRequestJwt(String requestId, String requestJwt, int tenantId)
            throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_UPDATE_VP_REQUEST_JWT)) {
                ps.setString(1, requestJwt);
                ps.setString(2, requestId);
                ps.setInt(3, tenantId);

                ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new VPException("Error updating VP request JWT: " + requestId, e);
        }
    }

    @Override
    public void deleteVPRequest(String requestId, int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_DELETE_VP_REQUEST)) {
                ps.setString(1, requestId);
                ps.setInt(2, tenantId);

                IdentityDatabaseUtil.commitTransaction(connection);

            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new VPException("Error deleting VP request: " + requestId, e);
        }
    }

    @Override
    public List<VPRequest> getExpiredVPRequests(int tenantId) throws VPException {
        List<VPRequest> expiredRequests = new ArrayList<>();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_SELECT_EXPIRED_VP_REQUESTS)) {
                ps.setLong(1, System.currentTimeMillis());
                ps.setString(2, VPRequestStatus.ACTIVE.getValue());
                ps.setInt(3, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        expiredRequests.add(mapResultSetToVPRequest(rs));
                    }
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error retrieving expired VP requests", e);
        }
        return expiredRequests;
    }

    @Override
    public int markExpiredRequests(int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_MARK_EXPIRED_REQUESTS)) {
                ps.setString(1, VPRequestStatus.EXPIRED.getValue());
                ps.setLong(2, System.currentTimeMillis());
                ps.setString(3, VPRequestStatus.ACTIVE.getValue());
                ps.setInt(4, tenantId);

                int updated = ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

                return updated;
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new VPException("Error marking expired VP requests", e);
        }
    }

    @Override
    public List<VPRequest> getVPRequestsByStatus(VPRequestStatus status, int tenantId)
            throws VPException {
        List<VPRequest> requests = new ArrayList<>();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(
                    SQL_SELECT_VP_REQUESTS_BY_STATUS)) {
                ps.setString(1, status.getValue());
                ps.setInt(2, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        requests.add(mapResultSetToVPRequest(rs));
                    }
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error retrieving VP requests by status: " + status, e);
        }
        return requests;
    }

    /**
     * Map ResultSet to VPRequest object.
     */
    private VPRequest mapResultSetToVPRequest(ResultSet rs) throws SQLException {
        return new VPRequest.Builder()
                .requestId(rs.getString("REQUEST_ID"))
                .transactionId(rs.getString("TRANSACTION_ID"))
                .clientId(rs.getString("CLIENT_ID"))
                .nonce(rs.getString("NONCE"))
                .presentationDefinitionId(rs.getString("PRESENTATION_DEFINITION_ID"))
                .presentationDefinition(rs.getString("PRESENTATION_DEFINITION"))
                .responseUri(rs.getString("RESPONSE_URI"))
                .responseMode(rs.getString("RESPONSE_MODE"))
                .requestJwt(rs.getString("REQUEST_JWT"))
                .status(VPRequestStatus.fromValue(rs.getString("STATUS")))
                .createdAt(rs.getLong("CREATED_AT"))
                .expiresAt(rs.getLong("EXPIRES_AT"))
                .tenantId(rs.getInt("TENANT_ID"))
                .build();
    }
}
