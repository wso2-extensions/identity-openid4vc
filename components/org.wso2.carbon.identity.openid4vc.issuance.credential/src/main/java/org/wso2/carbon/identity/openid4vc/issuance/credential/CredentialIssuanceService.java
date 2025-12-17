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
import org.wso2.carbon.identity.openid4vc.issuance.credential.dto.CredentialIssuanceReqDTO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.dto.CredentialIssuanceRespDTO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceClientException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceServerException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.internal.CredentialIssuanceDataHolder;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.CredentialIssuer;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.CredentialIssuerContext;
import org.wso2.carbon.identity.openid4vc.issuance.credential.util.CredentialIssuanceExceptionHandler;
import org.wso2.carbon.identity.openid4vc.template.management.VCTemplateManager;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtException;
import org.wso2.carbon.identity.openid4vc.template.management.model.VCTemplate;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Arrays;
import java.util.Map;

import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.CredentialIssuerMetadata.SUBJECT_IDENTIFIER;
import static org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceErrorCode.INSUFFICIENT_SCOPE;
import static org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceErrorCode.INTERNAL_SERVER_ERROR;
import static org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceErrorCode.INVALID_CREDENTIAL_REQUEST;
import static org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceErrorCode.INVALID_TOKEN;
import static org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceErrorCode.UNKNOWN_CREDENTIAL_CONFIGURATION;
import static org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceErrorCode.USER_REALM_ERROR;
import static org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceErrorCode.USER_STORE_ERROR;
import static org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceErrorCode.VC_TEMPLATE_MANAGER_NOT_AVAILABLE;

/**
 * This class handles Verifiable Credential issuance service. This is responsible for issuing verifiable credentials
 */
public class CredentialIssuanceService {

    private static final Log LOG = LogFactory.getLog(CredentialIssuanceService.class);
    private final CredentialIssuer credentialIssuer;

    public CredentialIssuanceService() {

        this.credentialIssuer = new CredentialIssuer();
    }

    /**
     * Issue verifiable credential based on the request.
     *
     * @param reqDTO Credential issuance request DTO
     * @return CredentialIssuanceRespDTO Credential issuance response DTO
     * @throws CredentialIssuanceException If an error occurs during credential issuance
     */
    public CredentialIssuanceRespDTO issueCredential(CredentialIssuanceReqDTO reqDTO)
            throws CredentialIssuanceException {

        if (reqDTO == null) {
            throw CredentialIssuanceExceptionHandler.handleClientException(INVALID_CREDENTIAL_REQUEST);
        }

        VCTemplateManager templateManager =
                CredentialIssuanceDataHolder.getInstance().getVCTemplateManager();
        if (templateManager == null) {
            throw CredentialIssuanceExceptionHandler.handleServerException(VC_TEMPLATE_MANAGER_NOT_AVAILABLE, null);
        }

        validateAccessToken(reqDTO);

        try {
            VCTemplate template = templateManager
                    .getByIdentifier(reqDTO.getCredentialConfigurationId(), reqDTO.getTenantDomain());

            if (template == null) {
                throw CredentialIssuanceExceptionHandler.handleClientException(UNKNOWN_CREDENTIAL_CONFIGURATION,
                        "identifier: %s in tenant: %s", reqDTO.getCredentialConfigurationId(),
                        reqDTO.getTenantDomain());
            }

            CredentialIssuerContext issuerContext = new CredentialIssuerContext();
            issuerContext.setConfigurationId(template.getId());
            issuerContext.setVCTemplate(template);
            issuerContext.setTenantDomain(reqDTO.getTenantDomain());
            issuerContext.setClaims(getClaims(reqDTO, template));

            String credential = credentialIssuer.issueCredential(issuerContext);
            CredentialIssuanceRespDTO respDTO = new CredentialIssuanceRespDTO();
            respDTO.setCredential(credential);
            return respDTO;


        } catch (VCTemplateMgtException e) {
            throw CredentialIssuanceExceptionHandler.handleServerException(INTERNAL_SERVER_ERROR, e,
                    "tenant: %s", reqDTO.getTenantDomain());
        }
    }

    /**
     * Validate the access token from the request.
     *
     * @param reqDTO Credential issuance request DTO
     * @throws CredentialIssuanceClientException If the access token is invalid
     */
    private void validateAccessToken(CredentialIssuanceReqDTO reqDTO) throws CredentialIssuanceClientException {

        AccessTokenDO accessTokenDO;
        try {
            accessTokenDO = CredentialIssuanceDataHolder.getInstance().getTokenProvider()
                    .getVerifiedAccessToken(reqDTO.getToken(), false);
        } catch (IdentityOAuth2Exception e) {
            throw CredentialIssuanceExceptionHandler.handleClientException(INVALID_TOKEN);
        }

        if (accessTokenDO == null) {
            throw CredentialIssuanceExceptionHandler.handleClientException(INVALID_TOKEN);
        }

        String[] scopes  = accessTokenDO.getScope();
        validateScope(scopes, reqDTO.getCredentialConfigurationId());
        AuthenticatedUser authenticatedUser = accessTokenDO.getAuthzUser();
        reqDTO.setAuthenticatedUser(authenticatedUser);
    }

    /**
     * Retrieve user claims required for the credential from the user store.
     *
     * @param reqDTO            Credential issuance request DTO
     * @param template          Verifiable Credential template
     * @return Map of user claims
     * @throws CredentialIssuanceException If an error occurs while retrieving claims
     */
    private Map<String, String> getClaims(CredentialIssuanceReqDTO reqDTO, VCTemplate template)
            throws CredentialIssuanceException {

        AuthenticatedUser authenticatedUser = reqDTO.getAuthenticatedUser();
        try {
            UserRealm realm = getUserRealm(reqDTO.getTenantDomain());
            AbstractUserStoreManager userStore = getUserStoreManager(reqDTO.getTenantDomain(), realm);
            Map<String, String> claims =  userStore.getUserClaimValuesWithID(authenticatedUser.getUserId(),
                    template.getClaims().toArray(new String[0]), null);
            claims.put(SUBJECT_IDENTIFIER, authenticatedUser.getUserId());
            return claims;
        } catch (IdentityException e) {
            throw CredentialIssuanceExceptionHandler.handleServerException(USER_REALM_ERROR, e,
                    "tenant: %s", reqDTO.getTenantDomain());
        } catch (UserStoreException e) {
            throw CredentialIssuanceExceptionHandler.handleServerException(USER_STORE_ERROR, e,
                    "user: %s", authenticatedUser.toFullQualifiedUsername());
        }
    }

    /**
     * Validates if the required scope from template exists in the JWT token scope.
     *
     * @param scopes the scopes from token
     * @param requiredScope the scope required by the template
     * @throws CredentialIssuanceClientException if the required scope is not present in JWT token
     */
    private void validateScope(String[] scopes, String requiredScope) throws CredentialIssuanceClientException {

        boolean scopePresent = scopes != null && Arrays.asList(scopes).contains(requiredScope);
        if (scopePresent) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Required scope: " + requiredScope + " is present in access token scopes");
            }
            return;
        }

        throw CredentialIssuanceExceptionHandler.handleClientException(INSUFFICIENT_SCOPE, "scope: %s", requiredScope);
    }

    /**
     * Retrieve the UserRealm for the given tenant domain.
     *
     * @param tenantDomain Tenant domain.
     * @return UserRealm of the tenant.
     * @throws CredentialIssuanceServerException If an error occurs while retrieving the UserRealm.
     */
    private UserRealm getUserRealm(String tenantDomain) throws CredentialIssuanceServerException {
        UserRealm realm;
        try {
            RealmService realmService = CredentialIssuanceDataHolder.getInstance().getRealmService();
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);

            realm = (org.wso2.carbon.user.core.UserRealm) realmService.getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw CredentialIssuanceExceptionHandler.handleServerException(USER_REALM_ERROR, e,
                    "tenant: %s", tenantDomain);
        }
        return realm;
    }

    /**
     * Retrieve the UserStoreManager for the given tenant domain.
     *
     * @param tenantDomain Tenant domain.
     * @param realm        UserRealm of the tenant.
     * @return UserStoreManager of the tenant.
     * @throws CredentialIssuanceServerException If an error occurs while retrieving the UserStoreManager.
     */
    private AbstractUserStoreManager getUserStoreManager(String tenantDomain, UserRealm realm) throws
            CredentialIssuanceServerException {
        AbstractUserStoreManager userStore;
        try {
            userStore = (AbstractUserStoreManager) realm.getUserStoreManager();
        } catch (UserStoreException e) {
            throw CredentialIssuanceExceptionHandler.handleServerException(USER_STORE_ERROR, e,
                    "tenant: %s", tenantDomain);
        }
        return userStore;
    }
}
