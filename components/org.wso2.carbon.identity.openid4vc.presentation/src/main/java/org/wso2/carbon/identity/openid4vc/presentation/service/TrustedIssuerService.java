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

package org.wso2.carbon.identity.openid4vc.presentation.service;

import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.TrustedIssuer;

import java.util.List;

/**
 * Service interface for managing trusted credential issuers.
 * Provides allowlist-based issuer verification to ensure only credentials
 * from trusted issuers are accepted during VP verification.
 * 
 * This is a critical security component that prevents acceptance of credentials
 * from untrusted or malicious issuers.
 */
public interface TrustedIssuerService {

    /**
     * Check if an issuer DID is in the trusted allowlist.
     * 
     * @param issuerDid DID of the credential issuer (e.g., "did:web:example.com")
     * @param tenantDomain Tenant domain for multi-tenant support
     * @return true if the issuer is trusted, false otherwise
     */
    boolean isIssuerTrusted(String issuerDid, String tenantDomain);

    /**
     * Add an issuer to the trusted allowlist.
     * Only administrators should be able to call this method.
     * 
     * @param issuerDid DID to trust
     * @param tenantDomain Tenant domain
     * @param addedBy Username of the administrator adding the trust
     * @param description Optional description of why this issuer is trusted
     * @throws VPException if addition fails or issuer already exists
     */
    void addTrustedIssuer(String issuerDid, String tenantDomain, String addedBy, String description) 
            throws VPException;

    /**
     * Remove an issuer from the trusted allowlist.
     * Only administrators should be able to call this method.
     * 
     * @param issuerDid DID to remove from trust list
     * @param tenantDomain Tenant domain
     * @throws VPException if removal fails or issuer doesn't exist
     */
    void removeTrustedIssuer(String issuerDid, String tenantDomain) throws VPException;

    /**
     * Get all trusted issuers for a tenant.
     * 
     * @param tenantDomain Tenant domain
     * @return List of trusted issuer DIDs
     * @throws VPException if retrieval fails
     */
    List<String> getTrustedIssuers(String tenantDomain) throws VPException;

    /**
     * Get detailed information about all trusted issuers for a tenant.
     * Includes metadata like who added the trust and when.
     * 
     * @param tenantDomain Tenant domain
     * @return List of TrustedIssuer objects with full details
     * @throws VPException if retrieval fails
     */
    List<TrustedIssuer> getTrustedIssuersWithDetails(String tenantDomain) throws VPException;

    /**
     * Check if issuer trust enforcement is enabled.
     * Allows for feature toggle of issuer verification.
     * 
     * @param tenantDomain Tenant domain
     * @return true if issuer trust checking is enabled
     */
    boolean isTrustEnforcementEnabled(String tenantDomain);

    /**
     * Update an existing trusted issuer's description.
     * 
     * @param issuerDid DID of the issuer
     * @param tenantDomain Tenant domain
     * @param description New description
     * @throws VPException if update fails
     */
    void updateTrustedIssuerDescription(String issuerDid, String tenantDomain, String description) 
            throws VPException;
}
