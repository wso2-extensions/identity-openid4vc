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
import org.wso2.carbon.identity.openid4vc.presentation.dao.DIDKeysDAO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.DIDKey;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Implementation of DIDKeysDAO using JDBC.
 */
public class DIDKeysDAOImpl implements DIDKeysDAO {

    private static final String SQL_INSERT_DID_KEY = "INSERT INTO IDN_DID_KEYS " +
            "(TENANT_ID, KEY_ID, ALGORITHM, PUBLIC_KEY, PRIVATE_KEY, CREATED_AT) VALUES (?, ?, ?, ?, ?, ?)";
    private static final String SQL_SELECT_DID_KEY = "SELECT * FROM IDN_DID_KEYS WHERE KEY_ID = ? AND TENANT_ID = ?";
    private static final String SQL_SELECT_DID_KEY_BY_TENANT = "SELECT * FROM IDN_DID_KEYS " +
            "WHERE TENANT_ID = ? ORDER BY CREATED_AT DESC LIMIT 1";
    private static final String SQL_SELECT_DID_KEY_BY_TENANT_AND_ALGO = "SELECT * FROM IDN_DID_KEYS " +
            "WHERE TENANT_ID = ? AND ALGORITHM = ? ORDER BY CREATED_AT DESC LIMIT 1";
    private static final String SQL_DELETE_DID_KEY = "DELETE FROM IDN_DID_KEYS WHERE KEY_ID = ? AND TENANT_ID = ?";
    private static final String SQL_CHECK_DID_KEY_EXISTS = "SELECT 1 FROM IDN_DID_KEYS " +
            "WHERE KEY_ID = ? AND TENANT_ID = ?";

    @Override
    public void addDIDKey(DIDKey didKey) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_INSERT_DID_KEY)) {
                ps.setInt(1, didKey.getTenantId());
                ps.setString(2, didKey.getKeyId());
                ps.setString(3, didKey.getAlgorithm());
                ps.setBytes(4, didKey.getPublicKey());
                ps.setBytes(5, didKey.getPrivateKey());
                ps.setLong(6, didKey.getCreatedAt());

                ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new VPException("Error adding DID key: " + didKey.getKeyId(), e);
        }
    }

    @Override
    public DIDKey getDIDKey(String keyId, int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_SELECT_DID_KEY)) {
                ps.setString(1, keyId);
                ps.setInt(2, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return new DIDKey(
                                rs.getString("KEY_ID"),
                                rs.getInt("TENANT_ID"),
                                rs.getString("ALGORITHM"),
                                rs.getBytes("PUBLIC_KEY"),
                                rs.getBytes("PRIVATE_KEY"));
                    }
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error retrieving DID key: " + keyId, e);
        }
        return null;
    }

    @Override
    public DIDKey getDIDKeyByTenant(int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            // Check specific DB type to handle LIMIT syntax if needed, but
            // H2/MySQL/Postgres support LIMIT
            // If Oracle support is needed, query might need adjustment (ROWNUM)
            try (PreparedStatement ps = connection.prepareStatement(SQL_SELECT_DID_KEY_BY_TENANT)) {
                ps.setInt(1, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return new DIDKey(
                                rs.getString("KEY_ID"),
                                rs.getInt("TENANT_ID"),
                                rs.getString("ALGORITHM"),
                                rs.getBytes("PUBLIC_KEY"),
                                rs.getBytes("PRIVATE_KEY"));
                    }
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error retrieving DID key for tenant: " + tenantId, e);
        }
        return null;
    }

    @Override
    public DIDKey getDIDKeyByTenantAndAlgo(int tenantId, String algorithm) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_SELECT_DID_KEY_BY_TENANT_AND_ALGO)) {
                ps.setInt(1, tenantId);
                ps.setString(2, algorithm);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return new DIDKey(
                                rs.getString("KEY_ID"),
                                rs.getInt("TENANT_ID"),
                                rs.getString("ALGORITHM"),
                                rs.getBytes("PUBLIC_KEY"),
                                rs.getBytes("PRIVATE_KEY"));
                    }
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error retrieving DID key for tenant: " + tenantId + " and algo: " + algorithm,
                    e);
        }
        return null;
    }

    @Override
    public void deleteDIDKey(String keyId, int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_DELETE_DID_KEY)) {
                ps.setString(1, keyId);
                ps.setInt(2, tenantId);

                ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);

            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new VPException("Error deleting DID key: " + keyId, e);
        }
    }

    @Override
    public boolean isDIDKeyExists(String keyId, int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(SQL_CHECK_DID_KEY_EXISTS)) {
                ps.setString(1, keyId);
                ps.setInt(2, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next();
                }
            }
        } catch (SQLException e) {
            throw new VPException("Error checking existence of DID key: " + keyId, e);
        }
    }
}
