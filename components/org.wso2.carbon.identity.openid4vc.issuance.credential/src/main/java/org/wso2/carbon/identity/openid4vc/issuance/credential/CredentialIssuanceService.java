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

package org.wso2.carbon.identity.openid4vc.issuance.credential;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.openid4vc.config.management.VCCredentialConfigManager;
import org.wso2.carbon.identity.openid4vc.config.management.exception.VCConfigMgtException;
import org.wso2.carbon.identity.openid4vc.config.management.model.VCCredentialConfiguration;
import org.wso2.carbon.identity.openid4vc.issuance.credential.dto.CredentialIssuanceReqDTO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.dto.CredentialIssuanceRespDTO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.internal.CredentialIssuanceDataHolder;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.CredentialIssuer;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.CredentialIssuerContext;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Map;

/**
 * Default implementation for credential issuance processing.
 */
public class CredentialIssuanceService {

    private static final Log log = LogFactory.getLog(CredentialIssuanceService.class);
    private final CredentialIssuer credentialIssuer;

    public CredentialIssuanceService() {
        this.credentialIssuer = new CredentialIssuer();
    }

    public CredentialIssuanceRespDTO issueCredential(CredentialIssuanceReqDTO reqDTO)
            throws CredentialIssuanceException {

        if (reqDTO == null) {
            throw new CredentialIssuanceException("Credential issuance request cannot be null");
        }

        VCCredentialConfigManager configManager =
                CredentialIssuanceDataHolder.getInstance().getVcCredentialConfigManager();
        if (configManager == null) {
            throw new CredentialIssuanceException("VC credential configuration manager is not available");
        }

        AccessTokenDO accessTokenDO;
        try {
            accessTokenDO = CredentialIssuanceDataHolder.getInstance().getTokenProvider()
                    .getVerifiedAccessToken(reqDTO.getToken(), false);
        } catch (IdentityOAuth2Exception e) {
            throw new CredentialIssuanceException("Error verifying access token", e);
        }

        String[] scopes  = accessTokenDO.getScope();
        AuthenticatedUser authenticatedUser = accessTokenDO.getAuthzUser();

        try {
            VCCredentialConfiguration credentialConfiguration = configManager
                    .getByIdentifier(reqDTO.getCredentialConfigurationId(), reqDTO.getTenantDomain());

            if (credentialConfiguration == null) {
                throw new CredentialIssuanceException("No credential configuration found for identifier: "
                        + reqDTO.getCredentialConfigurationId() + " in tenant: " + reqDTO.getTenantDomain());
            }

            // Validate scope - check if the required scope exists in JWT token
            validateScope(scopes, credentialConfiguration.getIdentifier());


            UserRealm realm = getUserRealm(reqDTO.getTenantDomain());
            AbstractUserStoreManager userStore = getUserStoreManager(reqDTO.getTenantDomain(), realm);
            Map<String, String> claims =  userStore.getUserClaimValuesWithID(authenticatedUser.getUserId(),
                    credentialConfiguration.getClaims().toArray(new String[0]), null);
            claims.put("id", authenticatedUser.getUserId());

            CredentialIssuerContext issuerContext = new CredentialIssuerContext();
            issuerContext.setConfigurationId(credentialConfiguration.getId());
            issuerContext.setCredentialConfiguration(credentialConfiguration);
            issuerContext.setTenantDomain(reqDTO.getTenantDomain());
            issuerContext.setClaims(claims);

            String credential = credentialIssuer.issueCredential(issuerContext);
            CredentialIssuanceRespDTO respDTO = new CredentialIssuanceRespDTO();
            respDTO.setCredential(credential);
            return respDTO;


        } catch (VCConfigMgtException e) {
            throw new CredentialIssuanceException("Error retrieving credential configurations for tenant: "
                    + reqDTO.getTenantDomain(), e);
        } catch (IdentityException e) {
            throw new CredentialIssuanceException("Error retrieving user realm for tenant: "
                    + reqDTO.getTenantDomain(), e);
        } catch (UserStoreException e) {
            throw new CredentialIssuanceException("Error retrieving user claims for user: "
                    + authenticatedUser.toFullQualifiedUsername(), e);
        }
    }

    /**
     * Validates if the required scope from credential configuration exists in the JWT token scope.
     *
     * @param scopes the scopes from token
     * @param requiredScope the scope required by the credential configuration
     * @throws CredentialIssuanceException if the required scope is not present in JWT token
     */
    private void validateScope(String[] scopes, String requiredScope) throws CredentialIssuanceException {

        for (String scope : scopes) {
            if (requiredScope.equals(scope)) {
                if (log.isDebugEnabled()) {
                    log.debug("Required scope: " + requiredScope + " is present in access token scopes");
                }
                return;
            }
        }

        throw new CredentialIssuanceException("Access token does not contain the required scope: "
                + requiredScope);
    }

    private UserRealm getUserRealm(String tenantDomain) throws CredentialIssuanceException {
        UserRealm realm;
        try {
            RealmService realmService = CredentialIssuanceDataHolder.getInstance().getRealmService();
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);

            realm = (org.wso2.carbon.user.core.UserRealm) realmService.getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw new CredentialIssuanceException("Error occurred while retrieving the Realm for " +
                    tenantDomain + " to handle local claims", e);
        }
        return realm;
    }

    private AbstractUserStoreManager getUserStoreManager(String tenantDomain, UserRealm realm) throws
            CredentialIssuanceException {
        AbstractUserStoreManager userStore;
        try {
            userStore = (AbstractUserStoreManager) realm.getUserStoreManager();
        } catch (UserStoreException e) {
            throw new CredentialIssuanceException("Error occurred while retrieving the UserStoreManager " +
                    "from Realm for " + tenantDomain + " to handle local claims", e);
        }
        return userStore;
    }
}
