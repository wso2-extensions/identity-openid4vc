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

package org.wso2.carbon.identity.openid4vc.presentation.dao;

import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.TrustedIssuer;

import java.util.List;

/**
 * DAO interface for managing trusted credential issuers in the database.
 */
public interface TrustedIssuerDAO {

    /**
     * Check if an issuer is trusted for a tenant.
     * 
     * @param issuerDid Issuer DID
     * @param tenantId Tenant ID
     * @return true if trusted
     * @throws VPException if database operation fails
     */
    boolean isIssuerTrusted(String issuerDid, int tenantId) throws VPException;

    /**
     * Add a trusted issuer to the database.
     * 
     * @param trustedIssuer Trusted issuer object
     * @throws VPException if insertion fails or issuer already exists
     */
    void addTrustedIssuer(TrustedIssuer trustedIssuer) throws VPException;

    /**
     * Remove a trusted issuer from the database.
     * 
     * @param issuerDid Issuer DID
     * @param tenantId Tenant ID
     * @throws VPException if deletion fails
     */
    void removeTrustedIssuer(String issuerDid, int tenantId) throws VPException;

    /**
     * Get all trusted issuers for a tenant.
     * 
     * @param tenantId Tenant ID
     * @return List of trusted issuer DIDs
     * @throws VPException if retrieval fails
     */
    List<String> getTrustedIssuers(int tenantId) throws VPException;

    /**
     * Get detailed information about all trusted issuers.
     * 
     * @param tenantId Tenant ID
     * @return List of TrustedIssuer objects
     * @throws VPException if retrieval fails
     */
    List<TrustedIssuer> getTrustedIssuersWithDetails(int tenantId) throws VPException;

    /**
     * Update trusted issuer description.
     * 
     * @param issuerDid Issuer DID
     * @param tenantId Tenant ID
     * @param description New description
     * @throws VPException if update fails
     */
    void updateTrustedIssuerDescription(String issuerDid, int tenantId, String description) 
            throws VPException;

    /**
     * Get a trusted issuer by DID.
     * 
     * @param issuerDid Issuer DID
     * @param tenantId Tenant ID
     * @return TrustedIssuer object or null if not found
     * @throws VPException if retrieval fails
     */
    TrustedIssuer getTrustedIssuer(String issuerDid, int tenantId) throws VPException;
}
