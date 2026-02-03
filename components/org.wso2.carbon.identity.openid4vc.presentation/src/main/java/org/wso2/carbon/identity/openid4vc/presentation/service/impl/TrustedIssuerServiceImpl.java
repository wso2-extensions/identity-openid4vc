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

package org.wso2.carbon.identity.openid4vc.presentation.service.impl;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.openid4vc.presentation.dao.TrustedIssuerDAO;
import org.wso2.carbon.identity.openid4vc.presentation.dao.impl.TrustedIssuerDAOImpl;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.model.TrustedIssuer;
import org.wso2.carbon.identity.openid4vc.presentation.service.TrustedIssuerService;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.List;

/**
 * Implementation of TrustedIssuerService for managing trusted credential
 * issuers.
 * Provides allowlist-based issuer verification.
 */
public class TrustedIssuerServiceImpl implements TrustedIssuerService {

    private final TrustedIssuerDAO trustedIssuerDAO;

    private static final boolean DEFAULT_TRUST_ENFORCEMENT = true;

    /**
     * Default constructor.
     */
    public TrustedIssuerServiceImpl() {
        this.trustedIssuerDAO = new TrustedIssuerDAOImpl();
    }

    /**
     * Constructor with DAO injection for testing.
     *
     * @param trustedIssuerDAO DAO instance
     */
    public TrustedIssuerServiceImpl(TrustedIssuerDAO trustedIssuerDAO) {
        this.trustedIssuerDAO = trustedIssuerDAO;
    }

    @Override
    public boolean isIssuerTrusted(String issuerDid, String tenantDomain) {
        if (issuerDid == null || issuerDid.trim().isEmpty()) {
            return false;
        }

        if (!isTrustEnforcementEnabled(tenantDomain)) {
            return true;
        }

        try {
            int tenantId = getTenantId(tenantDomain);
            boolean trusted = trustedIssuerDAO.isIssuerTrusted(issuerDid, tenantId);

            return trusted;

        } catch (VPException e) {
            return false; // Fail closed - if we can't verify trust, don't trust
        }
    }

    @Override
    public void addTrustedIssuer(String issuerDid, String tenantDomain, String addedBy, String description)
            throws VPException {

        if (issuerDid == null || issuerDid.trim().isEmpty()) {
            throw new VPException("Issuer DID cannot be null or empty");
        }

        if (!issuerDid.startsWith("did:")) {
            throw new VPException("Invalid DID format: " + issuerDid);
        }

        int tenantId = getTenantId(tenantDomain);

        TrustedIssuer trustedIssuer = new TrustedIssuer();
        trustedIssuer.setIssuerDid(issuerDid.trim());
        trustedIssuer.setTenantDomain(tenantDomain);
        trustedIssuer.setTenantId(tenantId);
        trustedIssuer.setAddedBy(addedBy);
        trustedIssuer.setAddedTimestamp(System.currentTimeMillis());
        trustedIssuer.setDescription(description);
        trustedIssuer.setActive(true);

        trustedIssuerDAO.addTrustedIssuer(trustedIssuer);

    }

    @Override
    public void removeTrustedIssuer(String issuerDid, String tenantDomain) throws VPException {
        if (issuerDid == null || issuerDid.trim().isEmpty()) {
            throw new VPException("Issuer DID cannot be null or empty");
        }

        int tenantId = getTenantId(tenantDomain);
        trustedIssuerDAO.removeTrustedIssuer(issuerDid.trim(), tenantId);

    }

    @Override
    public List<String> getTrustedIssuers(String tenantDomain) throws VPException {
        int tenantId = getTenantId(tenantDomain);
        return trustedIssuerDAO.getTrustedIssuers(tenantId);
    }

    @Override
    public List<TrustedIssuer> getTrustedIssuersWithDetails(String tenantDomain) throws VPException {
        int tenantId = getTenantId(tenantDomain);
        List<TrustedIssuer> issuers = trustedIssuerDAO.getTrustedIssuersWithDetails(tenantId);

        // Set tenant domain for each issuer
        for (TrustedIssuer issuer : issuers) {
            issuer.setTenantDomain(tenantDomain);
        }

        return issuers;
    }

    @Override
    public boolean isTrustEnforcementEnabled(String tenantDomain) {
        // For now, return default. In production, this would check tenant-specific
        // configuration
        // from identity.xml or deployment.toml
        return DEFAULT_TRUST_ENFORCEMENT;
    }

    @Override
    public void updateTrustedIssuerDescription(String issuerDid, String tenantDomain, String description)
            throws VPException {

        if (issuerDid == null || issuerDid.trim().isEmpty()) {
            throw new VPException("Issuer DID cannot be null or empty");
        }

        int tenantId = getTenantId(tenantDomain);
        trustedIssuerDAO.updateTrustedIssuerDescription(issuerDid.trim(), tenantId, description);

    }

    /**
     * Get tenant ID from tenant domain.
     *
     * @param tenantDomain Tenant domain
     * @return Tenant ID
     * @throws VPException if tenant resolution fails
     */
    private int getTenantId(String tenantDomain) throws VPException {
        try {
            if (tenantDomain == null || tenantDomain.trim().isEmpty()) {
                // Use current tenant from thread local
                return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
            }

            RealmService realmService = VPServiceDataHolder.getInstance().getRealmService();

            if (realmService == null) {
                throw new VPException("RealmService is not available");
            }

            return realmService.getTenantManager().getTenantId(tenantDomain);

        } catch (UserStoreException e) {
            throw new VPException("Error resolving tenant ID for domain: " + tenantDomain, e);
        }
    }

    /**
     * Pre-populate trusted issuers for a tenant.
     * Useful for initial setup or migration.
     *
     * @param issuerDids   List of issuer DIDs to trust
     * @param tenantDomain Tenant domain
     * @param addedBy      User adding the trust
     * @throws VPException if population fails
     */
    public void populateTrustedIssuers(List<String> issuerDids, String tenantDomain, String addedBy)
            throws VPException {

        int successCount = 0;
        int failureCount = 0;

        for (String issuerDid : issuerDids) {
            try {
                addTrustedIssuer(issuerDid, tenantDomain, addedBy, "Pre-populated trusted issuer");
                successCount++;
            } catch (VPException e) {
                failureCount++;
            }
        }

    }
}
