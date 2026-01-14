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
import org.wso2.carbon.identity.openid4vc.presentation.dao.VPSubmissionDAO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.VCVerificationStatus;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPSubmission;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Implementation of VPSubmissionDAO using JDBC.
 */
public class VPSubmissionDAOImpl implements VPSubmissionDAO {

    private static final Log log = LogFactory.getLog(VPSubmissionDAOImpl.class);

    // SQL Queries
    private static final String SQL_INSERT_VP_SUBMISSION = "INSERT INTO IDN_VP_SUBMISSION (SUBMISSION_ID, REQUEST_ID, VP_TOKEN, "
            +
            "PRESENTATION_SUBMISSION, ERROR, ERROR_DESCRIPTION, VERIFICATION_STATUS, " +
            "VERIFICATION_RESULT, SUBMITTED_AT, TENANT_ID) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String SQL_SELECT_VP_SUBMISSION_BY_ID = "SELECT * FROM IDN_VP_SUBMISSION WHERE SUBMISSION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_SELECT_VP_SUBMISSION_BY_REQUEST_ID = "SELECT * FROM IDN_VP_SUBMISSION WHERE REQUEST_ID = ? AND TENANT_ID = ?";

    private static final String SQL_UPDATE_VERIFICATION_STATUS = "UPDATE IDN_VP_SUBMISSION SET VERIFICATION_STATUS = ?, VERIFICATION_RESULT = ? "
            +
            "WHERE SUBMISSION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_DELETE_VP_SUBMISSION = "DELETE FROM IDN_VP_SUBMISSION WHERE SUBMISSION_ID = ? AND TENANT_ID = ?";

    private static final String SQL_DELETE_VP_SUBMISSIONS_BY_REQUEST_ID = "DELETE FROM IDN_VP_SUBMISSION WHERE REQUEST_ID = ? AND TENANT_ID = ?";

    private static final String SQL_CHECK_SUBMISSION_EXISTS = "SELECT 1 FROM IDN_VP_SUBMISSION WHERE REQUEST_ID = ? AND TENANT_ID = ?";

    @Override
    public void createVPSubmission(VPSubmission vpSubmission) throws VPException {
        log.info("[VP_SUBMISSION_DAO] Creating VP submission in database...");
        log.info("[VP_SUBMISSION_DAO] Submission ID: " + vpSubmission.getSubmissionId());
        log.info("[VP_SUBMISSION_DAO] Request ID: " + vpSubmission.getRequestId());
        log.info("[VP_SUBMISSION_DAO] Tenant ID: " + vpSubmission.getTenantId());

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_INSERT_VP_SUBMISSION)) {
                ps.setString(1, vpSubmission.getSubmissionId());
                ps.setString(2, vpSubmission.getRequestId());
                ps.setString(3, vpSubmission.getVpToken());
                ps.setString(4, vpSubmission.getPresentationSubmission());
                ps.setString(5, vpSubmission.getError());
                ps.setString(6, vpSubmission.getErrorDescription());
                ps.setString(7,
                        vpSubmission.getVerificationStatus() != null ? vpSubmission.getVerificationStatus().getValue()
                                : null);
                ps.setString(8, vpSubmission.getVerificationResult());
                ps.setLong(9, vpSubmission.getSubmittedAt());
                ps.setInt(10, vpSubmission.getTenantId());

                int rowsAffected = ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

                log.info("[VP_SUBMISSION_DAO] VP submission created successfully - Rows affected: " + rowsAffected);
            } catch (SQLException e) {
                log.error("[VP_SUBMISSION_DAO] SQL error creating VP submission: " + e.getMessage(), e);
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            log.error("[VP_SUBMISSION_DAO] Database error creating VP submission: " +
                    vpSubmission.getSubmissionId(), e);
            throw new VPException("Error creating VP submission: " +
                    vpSubmission.getSubmissionId(), e);
        }
    }

    @Override
    public VPSubmission getVPSubmissionById(String submissionId, int tenantId) throws VPException {
        if (log.isDebugEnabled()) {
            log.debug("[VP_SUBMISSION_DAO] Querying VP submission by ID: " + submissionId);
        }

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_SELECT_VP_SUBMISSION_BY_ID)) {
                ps.setString(1, submissionId);
                ps.setInt(2, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        if (log.isDebugEnabled()) {
                            log.debug("[VP_SUBMISSION_DAO] VP submission found: " + submissionId);
                        }
                        return mapResultSetToVPSubmission(rs);
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("[VP_SUBMISSION_DAO] VP submission not found: " + submissionId);
                        }
                    }
                }
            }
        } catch (SQLException e) {
            log.error("[VP_SUBMISSION_DAO] Database error retrieving VP submission: " + submissionId, e);
            throw new VPException("Error retrieving VP submission: " + submissionId, e);
        }
        return null;
    }

    @Override
    public VPSubmission getVPSubmissionByRequestId(String requestId, int tenantId)
            throws VPException {
        if (log.isDebugEnabled()) {
            log.debug("[VP_SUBMISSION_DAO] Querying VP submission by request ID: " + requestId);
        }

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(
                    SQL_SELECT_VP_SUBMISSION_BY_REQUEST_ID)) {
                ps.setString(1, requestId);
                ps.setInt(2, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        if (log.isDebugEnabled()) {
                            log.debug("[VP_SUBMISSION_DAO] VP submission found for request: " + requestId);
                        }
                        return mapResultSetToVPSubmission(rs);
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("[VP_SUBMISSION_DAO] No VP submission found for request: " + requestId);
                        }
                    }
                }
            }
        } catch (SQLException e) {
            log.error("[VP_SUBMISSION_DAO] Database error retrieving VP submission for request: " + requestId, e);
            throw new VPException("Error retrieving VP submission for request: " + requestId, e);
        }
        return null;
    }

    @Override
    public List<VPSubmission> getVPSubmissionsByRequestIds(List<String> requestIds, int tenantId)
            throws VPException {
        if (requestIds == null || requestIds.isEmpty()) {
            return Collections.emptyList();
        }

        List<VPSubmission> submissions = new ArrayList<>();

        // Build dynamic IN clause
        StringBuilder placeholders = new StringBuilder();
        for (int i = 0; i < requestIds.size(); i++) {
            placeholders.append(i > 0 ? ", ?" : "?");
        }

        String sql = "SELECT * FROM IDN_VP_SUBMISSION WHERE REQUEST_ID IN (" +
                placeholders + ") AND TENANT_ID = ?";

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(sql)) {
                int paramIndex = 1;
                for (String requestId : requestIds) {
                    ps.setString(paramIndex++, requestId);
                }
                ps.setInt(paramIndex, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        submissions.add(mapResultSetToVPSubmission(rs));
                    }
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error retrieving VP submissions for request IDs", e);
        }
        return submissions;
    }

    @Override
    public void updateVerificationStatus(String submissionId, VCVerificationStatus verificationStatus,
            String verificationResult, int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_UPDATE_VERIFICATION_STATUS)) {
                ps.setString(1, verificationStatus.getValue());
                ps.setString(2, verificationResult);
                ps.setString(3, submissionId);
                ps.setInt(4, tenantId);

                int updated = ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

                if (log.isDebugEnabled()) {
                    log.debug("Updated verification status for submission: " + submissionId +
                            " to " + verificationStatus + ", rows affected: " + updated);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new VPException("Error updating verification status: " + submissionId, e);
        }
    }

    @Override
    public void deleteVPSubmission(String submissionId, int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_DELETE_VP_SUBMISSION)) {
                ps.setString(1, submissionId);
                ps.setInt(2, tenantId);

                int deleted = ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

                if (log.isDebugEnabled()) {
                    log.debug("Deleted VP submission: " + submissionId +
                            ", rows affected: " + deleted);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new VPException("Error deleting VP submission: " + submissionId, e);
        }
    }

    @Override
    public void deleteVPSubmissionsByRequestId(String requestId, int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(
                    SQL_DELETE_VP_SUBMISSIONS_BY_REQUEST_ID)) {
                ps.setString(1, requestId);
                ps.setInt(2, tenantId);

                int deleted = ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

                if (log.isDebugEnabled()) {
                    log.debug("Deleted VP submissions for request: " + requestId +
                            ", rows affected: " + deleted);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new VPException("Error deleting VP submissions for request: " + requestId, e);
        }
    }

    @Override
    public boolean hasSubmissionForRequest(String requestId, int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_CHECK_SUBMISSION_EXISTS)) {
                ps.setString(1, requestId);
                ps.setInt(2, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next();
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error checking submission existence for request: " +
                    requestId, e);
        }
    }

    /**
     * Map ResultSet to VPSubmission object.
     */
    private VPSubmission mapResultSetToVPSubmission(ResultSet rs) throws SQLException {
        String statusStr = rs.getString("VERIFICATION_STATUS");
        VCVerificationStatus status = statusStr != null ? VCVerificationStatus.fromValue(statusStr) : null;

        return new VPSubmission.Builder()
                .submissionId(rs.getString("SUBMISSION_ID"))
                .requestId(rs.getString("REQUEST_ID"))
                .vpToken(rs.getString("VP_TOKEN"))
                .presentationSubmission(rs.getString("PRESENTATION_SUBMISSION"))
                .error(rs.getString("ERROR"))
                .errorDescription(rs.getString("ERROR_DESCRIPTION"))
                .verificationStatus(status)
                .verificationResult(rs.getString("VERIFICATION_RESULT"))
                .submittedAt(rs.getLong("SUBMITTED_AT"))
                .tenantId(rs.getInt("TENANT_ID"))
                .build();
    }
}
