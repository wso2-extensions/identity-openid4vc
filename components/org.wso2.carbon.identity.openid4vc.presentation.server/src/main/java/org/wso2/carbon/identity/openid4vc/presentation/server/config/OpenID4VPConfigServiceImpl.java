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

package org.wso2.carbon.identity.openid4vc.presentation.server.config;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.config.OpenID4VPConfigMgtException;
import org.wso2.carbon.identity.openid4vc.presentation.common.config.OpenID4VPConfigService;
import org.wso2.carbon.identity.openid4vc.presentation.common.config.OpenID4VPTenantConfig;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.service.RegistryService;

import java.nio.charset.StandardCharsets;

/**
 * Governance-registry-backed implementation of {@link OpenID4VPConfigService}.
 * Stores per-tenant config at {@value #REGISTRY_PATH} in the governance registry.
 */
public class OpenID4VPConfigServiceImpl implements OpenID4VPConfigService {

    private static final Log LOG = LogFactory.getLog(OpenID4VPConfigServiceImpl.class);

    static final String REGISTRY_PATH = "identity/openid4vp/config";
    static final String REGISTRY_PATH_REG_CERT = "identity/openid4vp/config/registrationCertificate";

    private static final String PROP_CLIENT_ID_SCHEME = "clientIdScheme";
    private static final String PROP_CLIENT_ID = "clientId";
    private static final String PROP_RESPONSE_MODE = "responseMode";
    private static final String PROP_REJECT_VC_WITHOUT_STATUS_CLAIM = "rejectVcWithoutStatusClaim";

    @Override
    public OpenID4VPTenantConfig getConfig(String tenantDomain) throws OpenID4VPConfigMgtException {

        OpenID4VPTenantConfig config = new OpenID4VPTenantConfig();
        try {
            Registry registry = getGovernanceRegistry(tenantDomain);
            if (!registry.resourceExists(REGISTRY_PATH)) {
                return config;
            }
            Resource resource = registry.get(REGISTRY_PATH);
            config.setClientIdScheme(resource.getProperty(PROP_CLIENT_ID_SCHEME));
            config.setClientId(resource.getProperty(PROP_CLIENT_ID));
            config.setResponseMode(resource.getProperty(PROP_RESPONSE_MODE));
            if (registry.resourceExists(REGISTRY_PATH_REG_CERT)) {
                Resource certResource = registry.get(REGISTRY_PATH_REG_CERT);
                Object content = certResource.getContent();
                if (content instanceof byte[]) {
                    config.setRegistrationCertificate(new String((byte[]) content, StandardCharsets.UTF_8));
                }
            }
            String rejectFlag = resource.getProperty(PROP_REJECT_VC_WITHOUT_STATUS_CLAIM);
            if (rejectFlag != null) {
                config.setRejectVcWithoutStatusClaim(Boolean.parseBoolean(rejectFlag));
            }
        } catch (RegistryException e) {
            throw new OpenID4VPConfigMgtException("OID4VP-60001",
                    "Failed to retrieve OpenID4VP config for tenant: " + tenantDomain, e);
        }
        return config;
    }

    @Override
    public void setConfig(OpenID4VPTenantConfig config, String tenantDomain) throws OpenID4VPConfigMgtException {

        try {
            Registry registry = getGovernanceRegistry(tenantDomain);
            Resource resource;
            if (registry.resourceExists(REGISTRY_PATH)) {
                resource = registry.get(REGISTRY_PATH);
            } else {
                resource = registry.newResource();
            }
            setOrClear(resource, PROP_CLIENT_ID_SCHEME, config.getClientIdScheme());
            setOrClear(resource, PROP_CLIENT_ID, config.getClientId());
            setOrClear(resource, PROP_RESPONSE_MODE, config.getResponseMode());
            setOrClear(resource, PROP_REJECT_VC_WITHOUT_STATUS_CLAIM,
                    config.getRejectVcWithoutStatusClaim() != null
                            ? config.getRejectVcWithoutStatusClaim().toString() : null);
            registry.put(REGISTRY_PATH, resource);
            if (StringUtils.isNotBlank(config.getRegistrationCertificate())) {
                Resource certResource;
                if (registry.resourceExists(REGISTRY_PATH_REG_CERT)) {
                    certResource = registry.get(REGISTRY_PATH_REG_CERT);
                } else {
                    certResource = registry.newResource();
                }
                certResource.setContent(config.getRegistrationCertificate().getBytes(StandardCharsets.UTF_8));
                certResource.setMediaType("text/plain");
                registry.put(REGISTRY_PATH_REG_CERT, certResource);
            } else if (registry.resourceExists(REGISTRY_PATH_REG_CERT)) {
                registry.delete(REGISTRY_PATH_REG_CERT);
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Saved tenant config for " + tenantDomain
                        + ": clientIdScheme=" + config.getClientIdScheme()
                        + " responseMode=" + config.getResponseMode());
            }
        } catch (RegistryException e) {
            throw new OpenID4VPConfigMgtException("OID4VP-60002",
                    "Failed to persist OpenID4VP config for tenant: " + tenantDomain, e);
        }
    }

    @Override
    public OpenID4VPTenantConfig getConfigByTenantId(int tenantId) throws OpenID4VPConfigMgtException {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        return getConfig(tenantDomain);
    }

    private Registry getGovernanceRegistry(String tenantDomain) throws RegistryException {

        RegistryService registryService = IdentityTenantUtil.getRegistryService();
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        return registryService.getGovernanceSystemRegistry(tenantId);
    }

    private void setOrClear(Resource resource, String key, String value) {

        if (value != null) {
            resource.setProperty(key, value);
        } else {
            resource.removeProperty(key);
        }
    }
}
