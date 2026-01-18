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
import org.wso2.carbon.identity.openid4vc.presentation.dao.TrustedIssuerDAO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.TrustedIssuer;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

/**
 * DAO implementation for managing trusted credential issuers.
 */
public class TrustedIssuerDAOImpl implements TrustedIssuerDAO {

    private static final Log LOG = LogFactory.getLog(TrustedIssuerDAOImpl.class);

    // SQL Queries
    private static final String IS_ISSUER_TRUSTED =
            "SELECT ID FROM IDN_OPENID4VP_TRUSTED_ISSUER WHERE ISSUER_DID = ? AND TENANT_ID = ? AND ACTIVE = 1";

    private static final String ADD_TRUSTED_ISSUER =
            "INSERT INTO IDN_OPENID4VP_TRUSTED_ISSUER (ISSUER_DID, TENANT_ID, ADDED_BY, ADDED_TIME, DESCRIPTION, ACTIVE) " +
            "VALUES (?, ?, ?, ?, ?, ?)";

    private static final String REMOVE_TRUSTED_ISSUER =
            "DELETE FROM IDN_OPENID4VP_TRUSTED_ISSUER WHERE ISSUER_DID = ? AND TENANT_ID = ?";

    private static final String GET_TRUSTED_ISSUERS =
            "SELECT ISSUER_DID FROM IDN_OPENID4VP_TRUSTED_ISSUER WHERE TENANT_ID = ? AND ACTIVE = 1";

    private static final String GET_TRUSTED_ISSUERS_WITH_DETAILS =
            "SELECT ISSUER_DID, TENANT_ID, ADDED_BY, ADDED_TIME, DESCRIPTION, ACTIVE " +
            "FROM IDN_OPENID4VP_TRUSTED_ISSUER WHERE TENANT_ID = ? AND ACTIVE = 1";

    private static final String UPDATE_DESCRIPTION =
            "UPDATE IDN_OPENID4VP_TRUSTED_ISSUER SET DESCRIPTION = ? WHERE ISSUER_DID = ? AND TENANT_ID = ?";

    private static final String GET_TRUSTED_ISSUER =
            "SELECT ISSUER_DID, TENANT_ID, ADDED_BY, ADDED_TIME, DESCRIPTION, ACTIVE " +
            "FROM IDN_OPENID4VP_TRUSTED_ISSUER WHERE ISSUER_DID = ? AND TENANT_ID = ?";

    @Override
    public boolean isIssuerTrusted(String issuerDid, int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement statement = connection.prepareStatement(IS_ISSUER_TRUSTED)) {

            statement.setString(1, issuerDid);
            statement.setInt(2, tenantId);

            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next();
            }

        } catch (SQLException e) {
            throw new VPException("Error checking if issuer is trusted: " + issuerDid, e);
        }
    }

    @Override
    public void addTrustedIssuer(TrustedIssuer trustedIssuer) throws VPException {
        // Check if already exists
        if (isIssuerTrusted(trustedIssuer.getIssuerDid(), trustedIssuer.getTenantId())) {
            throw new VPException("Issuer already exists in trusted list: " + trustedIssuer.getIssuerDid());
        }

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true);
             PreparedStatement statement = connection.prepareStatement(ADD_TRUSTED_ISSUER)) {

            statement.setString(1, trustedIssuer.getIssuerDid());
            statement.setInt(2, trustedIssuer.getTenantId());
            statement.setString(3, trustedIssuer.getAddedBy());
            statement.setTimestamp(4, new Timestamp(trustedIssuer.getAddedTimestamp()));
            statement.setString(5, trustedIssuer.getDescription());
            statement.setBoolean(6, trustedIssuer.isActive());

            statement.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(connection);

            LOG.info("Added trusted issuer: " + trustedIssuer.getIssuerDid() + 
                    " for tenant ID: " + trustedIssuer.getTenantId());

        } catch (SQLException e) {
            throw new VPException("Error adding trusted issuer: " + trustedIssuer.getIssuerDid(), e);
        }
    }

    @Override
    public void removeTrustedIssuer(String issuerDid, int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true);
             PreparedStatement statement = connection.prepareStatement(REMOVE_TRUSTED_ISSUER)) {

            statement.setString(1, issuerDid);
            statement.setInt(2, tenantId);

            int rowsAffected = statement.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(connection);

            if (rowsAffected == 0) {
                LOG.warn("No trusted issuer found to remove: " + issuerDid);
            } else {
                LOG.info("Removed trusted issuer: " + issuerDid + " for tenant ID: " + tenantId);
            }

        } catch (SQLException e) {
            throw new VPException("Error removing trusted issuer: " + issuerDid, e);
        }
    }

    @Override
    public List<String> getTrustedIssuers(int tenantId) throws VPException {
        List<String> issuers = new ArrayList<>();

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement statement = connection.prepareStatement(GET_TRUSTED_ISSUERS)) {

            statement.setInt(1, tenantId);

            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    issuers.add(resultSet.getString("ISSUER_DID"));
                }
            }

        } catch (SQLException e) {
            throw new VPException("Error retrieving trusted issuers for tenant ID: " + tenantId, e);
        }

        return issuers;
    }

    @Override
    public List<TrustedIssuer> getTrustedIssuersWithDetails(int tenantId) throws VPException {
        List<TrustedIssuer> issuers = new ArrayList<>();

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement statement = connection.prepareStatement(GET_TRUSTED_ISSUERS_WITH_DETAILS)) {

            statement.setInt(1, tenantId);

            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    TrustedIssuer issuer = new TrustedIssuer();
                    issuer.setIssuerDid(resultSet.getString("ISSUER_DID"));
                    issuer.setTenantId(resultSet.getInt("TENANT_ID"));
                    issuer.setAddedBy(resultSet.getString("ADDED_BY"));
                    issuer.setAddedTimestamp(resultSet.getTimestamp("ADDED_TIME").getTime());
                    issuer.setDescription(resultSet.getString("DESCRIPTION"));
                    issuer.setActive(resultSet.getBoolean("ACTIVE"));
                    issuers.add(issuer);
                }
            }

        } catch (SQLException e) {
            throw new VPException("Error retrieving trusted issuers with details for tenant ID: " + tenantId, e);
        }

        return issuers;
    }

    @Override
    public void updateTrustedIssuerDescription(String issuerDid, int tenantId, String description) 
            throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true);
             PreparedStatement statement = connection.prepareStatement(UPDATE_DESCRIPTION)) {

            statement.setString(1, description);
            statement.setString(2, issuerDid);
            statement.setInt(3, tenantId);

            int rowsAffected = statement.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(connection);

            if (rowsAffected == 0) {
                throw new VPException("Trusted issuer not found: " + issuerDid);
            }

            LOG.info("Updated description for trusted issuer: " + issuerDid);

        } catch (SQLException e) {
            throw new VPException("Error updating trusted issuer description: " + issuerDid, e);
        }
    }

    @Override
    public TrustedIssuer getTrustedIssuer(String issuerDid, int tenantId) throws VPException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement statement = connection.prepareStatement(GET_TRUSTED_ISSUER)) {

            statement.setString(1, issuerDid);
            statement.setInt(2, tenantId);

            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    TrustedIssuer issuer = new TrustedIssuer();
                    issuer.setIssuerDid(resultSet.getString("ISSUER_DID"));
                    issuer.setTenantId(resultSet.getInt("TENANT_ID"));
                    issuer.setAddedBy(resultSet.getString("ADDED_BY"));
                    issuer.setAddedTimestamp(resultSet.getTimestamp("ADDED_TIME").getTime());
                    issuer.setDescription(resultSet.getString("DESCRIPTION"));
                    issuer.setActive(resultSet.getBoolean("ACTIVE"));
                    return issuer;
                }
            }

        } catch (SQLException e) {
            throw new VPException("Error retrieving trusted issuer: " + issuerDid, e);
        }

        return null;
    }
}
