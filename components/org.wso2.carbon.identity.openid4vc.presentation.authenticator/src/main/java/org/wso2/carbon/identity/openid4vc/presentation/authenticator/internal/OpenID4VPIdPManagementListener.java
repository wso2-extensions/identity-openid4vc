/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.listener.AbstractIdentityProviderMgtListener;
import org.wso2.carbon.utils.security.KeystoreUtils;

import java.security.KeyStore;
import java.util.Arrays;

import static org.wso2.carbon.keystore.mgt.util.TenantKeyPairConstants.EC_KEY_ALG;
import static org.wso2.carbon.keystore.mgt.util.TenantKeyPairConstants.EC_SHA256;
import static org.wso2.carbon.keystore.mgt.util.TenantKeyPairUtil.addKeyEntry;

/**
 * Provisions an ECDSA keypair into the tenant keystore whenever a new IdP backed by
 * {@code OpenID4VPAuthenticator} is created.
 */
public class OpenID4VPIdPManagementListener extends AbstractIdentityProviderMgtListener {

    private static final Log LOG = LogFactory.getLog(OpenID4VPIdPManagementListener.class);

    private static final String OID4VP_AUTHENTICATOR_NAME = "OpenID4VPAuthenticator";

    @Override
    public int getDefaultOrderId() {

        return 110;
    }

    @Override
    public boolean doPostAddIdP(IdentityProvider identityProvider, String tenantDomain)
            throws IdentityProviderManagementException {

        if (!isOid4vpIdP(identityProvider)) {
            return true;
        }

        try {
            LOG.info("OpenID4VP IdP created for tenant [" + tenantDomain
                    + "]. Checking ECDSA keypair.");
            provisionEcdsaKeyPairIfAbsent(tenantDomain);
        } catch (Exception e) {
            // Non-fatal: IdP creation succeeds; log the failure so it can be diagnosed.
            LOG.error("Failed to provision ECDSA keypair for tenant [" + tenantDomain
                    + "]. The IdP was created but VP request signing may be unavailable.", e);
        }

        return true;
    }

    private boolean isOid4vpIdP(IdentityProvider identityProvider) {

        if (identityProvider == null) {
            return false;
        }
        FederatedAuthenticatorConfig[] configs = identityProvider.getFederatedAuthenticatorConfigs();
        if (configs == null) {
            return false;
        }
        return Arrays.stream(configs)
                .anyMatch(c -> OID4VP_AUTHENTICATOR_NAME.equals(c.getName()));
    }

    private void provisionEcdsaKeyPairIfAbsent(String tenantDomain) throws Exception {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        String keyStoreName = KeystoreUtils.getKeyStoreFileLocation(tenantDomain);
        KeyStoreManager ksm = KeyStoreManager.getInstance(tenantId);
        KeyStore tenantKeyStore = ksm.getKeyStore(keyStoreName);
        String ecAlias = KeyStoreUtil.getTenantECKeyAlias(tenantDomain);
        if (tenantKeyStore.containsAlias(ecAlias) && tenantKeyStore.isKeyEntry(ecAlias)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Tenant EC key already exists for tenantDomain: " + tenantDomain
                        + " with alias: " + ecAlias);
            }
            return;
        }
        addKeyEntry(tenantDomain, ksm.getKeyStorePassword(keyStoreName), tenantKeyStore,
                ecAlias, EC_KEY_ALG, EC_SHA256);
        ksm.updateKeyStore(keyStoreName, tenantKeyStore);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Generated and persisted tenant EC key pair for tenantDomain: "
                    + tenantDomain + " with alias: " + ecAlias);
        }
    }
}
