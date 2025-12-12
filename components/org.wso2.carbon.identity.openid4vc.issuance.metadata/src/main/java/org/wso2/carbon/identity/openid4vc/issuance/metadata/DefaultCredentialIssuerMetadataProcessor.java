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

package org.wso2.carbon.identity.openid4vc.issuance.metadata;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.openid4vc.config.management.VCCredentialConfigManager;
import org.wso2.carbon.identity.openid4vc.config.management.exception.VCConfigMgtException;
import org.wso2.carbon.identity.openid4vc.config.management.model.VCCredentialConfiguration;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.issuance.common.util.CommonUtil;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.exception.CredentialIssuerMetadataException;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.internal.CredentialIssuerMetadataDataHolder;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.model.CredentialConfigurationMetadataBuilder;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.response.CredentialIssuerMetadataResponse;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/**
 * Default implementation for credential issuer metadata processing.
 */
public class DefaultCredentialIssuerMetadataProcessor implements CredentialIssuerMetadataProcessor {

    private static final Log log = LogFactory.getLog(DefaultCredentialIssuerMetadataProcessor.class);
    private static final DefaultCredentialIssuerMetadataProcessor defaultCredentialIssuerMetadataProcessor =
            new DefaultCredentialIssuerMetadataProcessor();

    private DefaultCredentialIssuerMetadataProcessor() {

        if (log.isDebugEnabled()) {
            log.debug("Initializing DefaultCredentialIssuerMetadataProcessor for " +
                    "CredentialIssuerMetadataProcessor.");
        }
    }

    public static DefaultCredentialIssuerMetadataProcessor getInstance() {

        return defaultCredentialIssuerMetadataProcessor;
    }

    @Override
    public CredentialIssuerMetadataResponse getMetadataResponse(String tenantDomain)
            throws CredentialIssuerMetadataException {

        String effectiveTenant = resolveTenant(tenantDomain);
        try {
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put(Constants.CredentialIssuerMetadata.CREDENTIAL_ISSUER,
                    buildCredentialIssuerUrl(effectiveTenant));
            metadata.put(Constants.CredentialIssuerMetadata.CREDENTIAL_ENDPOINT,
                    buildCredentialEndpointUrl(effectiveTenant));
            metadata.put(Constants.CredentialIssuerMetadata.AUTHORIZATION_SERVERS,
                    Collections.singletonList(buildAuthorizationServerUrl(effectiveTenant)));
            Map<String, Object> credentialConfigurations = getCredentialConfigurations(effectiveTenant);
            metadata.put(Constants.CredentialIssuerMetadata.CREDENTIAL_CONFIGURATIONS_SUPPORTED,
                    credentialConfigurations);

            return new CredentialIssuerMetadataResponse(metadata);
        } catch (URLBuilderException e) {
            throw new CredentialIssuerMetadataException("Error while constructing credential issuer metadata URLs", e);
        }
    }

    private String resolveTenant(String tenantDomain) {

        if (tenantDomain == null || tenantDomain.trim().isEmpty()) {
            return MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return tenantDomain;
    }

    private String buildCredentialIssuerUrl(String tenantDomain) throws URLBuilderException {

        return CommonUtil.buildServiceUrl(tenantDomain, Constants.CONTEXT_OPENID4VCI).getAbsolutePublicURL();
    }

    private String buildCredentialEndpointUrl(String tenantDomain) throws URLBuilderException {

        return CommonUtil.buildServiceUrl(tenantDomain, Constants.CONTEXT_OPENID4VCI, Constants.SEGMENT_CREDENTIAL)
                .getAbsolutePublicURL();
    }

    private String buildAuthorizationServerUrl(String tenantDomain) throws URLBuilderException {

        return CommonUtil.buildServiceUrl(tenantDomain, Constants.SEGMENT_OAUTH2, Constants.SEGMENT_TOKEN)
                .getAbsolutePublicURL();
    }

    protected Map<String, Object> getCredentialConfigurations(String tenantDomain)
            throws CredentialIssuerMetadataException {

        VCCredentialConfigManager configManager = CredentialIssuerMetadataDataHolder.getInstance()
                .getVCCredentialConfigManager();
        try {
            List<VCCredentialConfiguration> configurations = configManager.list(tenantDomain);

            Map<String, Object> configurationsMap = new LinkedHashMap<>();
            if (configurations == null || configurations.isEmpty()) {
                return configurationsMap;
            }

            for (VCCredentialConfiguration cfg : configurations) {
                VCCredentialConfiguration configuration = configManager.get(cfg.getId(), tenantDomain);

                // Use builder pattern for clean construction
                CredentialConfigurationMetadataBuilder builder = new CredentialConfigurationMetadataBuilder()
                        .id(configuration.getIdentifier())
                        .format(configuration.getFormat())
                        .scope(configuration.getIdentifier())
                        .signingAlgorithm(configuration.getSigningAlgorithm())
                        .type(Constants.W3CVCDataModel.VERIFIABLE_CREDENTIAL_TYPE)
                        .display(configuration.getDisplayName())
                        .type(configuration.getIdentifier())
                        .claims(configuration.getClaims());

                configurationsMap.put(configuration.getIdentifier(), builder.build());
            }

            return configurationsMap;
        } catch (VCConfigMgtException e) {
            throw new CredentialIssuerMetadataException("Error while retrieving VC credential configurations " +
                    "for tenant: " + tenantDomain, e);
        }
    }
}
