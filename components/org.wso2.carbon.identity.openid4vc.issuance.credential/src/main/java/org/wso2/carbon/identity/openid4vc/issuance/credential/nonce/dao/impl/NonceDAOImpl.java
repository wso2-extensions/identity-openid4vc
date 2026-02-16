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

package org.wso2.carbon.identity.openid4vc.issuance.credential.nonce.dao.impl;

import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.nonce.constant.NonceSQLConstants;
import org.wso2.carbon.identity.openid4vc.issuance.credential.nonce.dao.NonceDAO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;

/**
 * JDBC-backed implementation of {@link NonceDAO}.
 * Uses the shared WSO2 identity database via {@link IdentityDatabaseUtil}.
 */
public class NonceDAOImpl implements NonceDAO {

    @Override
    public void storeNonce(String nonceValue, int tenantId, Timestamp expiryTime)
            throws CredentialIssuanceException {

        try (Connection conn = IdentityDatabaseUtil.getDBConnection(true);
             PreparedStatement ps = conn.prepareStatement(NonceSQLConstants.STORE_NONCE)) {
            ps.setInt(1, tenantId);
            ps.setString(2, nonceValue);
            ps.setTimestamp(3, new Timestamp(System.currentTimeMillis()));
            ps.setTimestamp(4, expiryTime);
            ps.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(conn);
        } catch (SQLException e) {
            throw new CredentialIssuanceException("Error storing nonce in database", e);
        }
    }

    @Override
    public boolean validateAndConsumeNonce(String nonceValue, int tenantId)
            throws CredentialIssuanceException {

        try (Connection conn = IdentityDatabaseUtil.getDBConnection(true);
             PreparedStatement ps = conn.prepareStatement(NonceSQLConstants.VALIDATE_AND_CONSUME_NONCE)) {
            ps.setString(1, nonceValue);
            ps.setInt(2, tenantId);
            ps.setTimestamp(3, new Timestamp(System.currentTimeMillis()));
            int rowsDeleted = ps.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(conn);
            return rowsDeleted == 1;
        } catch (SQLException e) {
            throw new CredentialIssuanceException("Error validating and consuming nonce", e);
        }
    }

    @Override
    public void deleteExpiredNonces() throws CredentialIssuanceException {

        try (Connection conn = IdentityDatabaseUtil.getDBConnection(true);
             PreparedStatement ps = conn.prepareStatement(NonceSQLConstants.DELETE_EXPIRED_NONCES)) {
            ps.setTimestamp(1, new Timestamp(System.currentTimeMillis()));
            ps.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(conn);
        } catch (SQLException e) {
            throw new CredentialIssuanceException("Error deleting expired nonces", e);
        }
    }
}
