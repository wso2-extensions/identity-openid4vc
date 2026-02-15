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

package org.wso2.carbon.identity.openid4vc.presentation.listener;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.service.PresentationDefinitionService;
import org.wso2.carbon.idp.mgt.listener.AbstractIdentityProviderMgtListener;

import java.util.UUID;

/**
 * Identity Provider Management Listener for OpenIDoa4VP.
 * This listener manages the lifecycle of Presentation Definitions associated with Identity Providers.
 */
public class OpenID4VPIdentityProviderMgtListener extends AbstractIdentityProviderMgtListener {

    private static final Log log = LogFactory.getLog(OpenID4VPIdentityProviderMgtListener.class);
    private static final String PROP_PRESENTATION_DEFINITION = "presentationDefinition";
    private static final String DIGITAL_CREDENTIALS_TEMPLATE_ID = "digital-credentials"; 

    @Override
    public int getDefaultOrderId() {

        return 99;
    }

    @Override
    public boolean doPostAddIdP(IdentityProvider identityProvider, String tenantDomain) {

        handlePresentationDefinitionUpdate(identityProvider, tenantDomain);
        return true;
    }

    @Override
    public boolean doPostUpdateIdP(String oldIdPName, IdentityProvider identityProvider, String tenantDomain) {

        handlePresentationDefinitionUpdate(identityProvider, tenantDomain);
        return true;
    }

    @Override
    public boolean doPostDeleteIdP(String idPName, String tenantDomain) {

        // IDP delete logic doesn't provide the Resource ID easily in all versions, 
        // but we need to clean up definitions. 
        // Ideally we should delete by Resource ID, but if we don't have it, we might be stuck.
        // However, the IDP deletion usually doesn't cascade to external tables automatically unless we enforce it.
        // For now, let's try to lookup the IDP or assume we need to handle this.
        
        // Actually, since doPostDeleteIdP only gives the name, we might not be able to get the ResourceId 
        // if the IDP is already deleted from DB. 
        // But doPreDeleteIdP gives us a chance.
        return true;
    }

    @Override
    @SuppressFBWarnings("CRLF_INJECTION_LOGS")
    public boolean doPreDeleteIdP(String idPName, String tenantDomain) {

        try {
            IdentityProvider identityProvider = VPServiceDataHolder.getInstance()
                    .getApplicationManagementService().getIdentityProvider(idPName, tenantDomain);

            if (identityProvider != null && StringUtils.isNotBlank(identityProvider.getResourceId())) {
                PresentationDefinitionService pdService = VPServiceDataHolder.getInstance()
                        .getPresentationDefinitionService();
                if (pdService != null) {
                    PresentationDefinition existingPd = pdService.getPresentationDefinitionByResourceId(
                            identityProvider.getResourceId(), IdentityTenantUtil.getTenantId(tenantDomain));

                    if (existingPd != null) {
                        pdService.deletePresentationDefinition(existingPd.getDefinitionId(), 
                                IdentityTenantUtil.getTenantId(tenantDomain));
                    }
                }
            }
        } catch (IdentityApplicationManagementException | VPException e) {
            log.error("Error deleting presentation definition for IDP: " + sanitize(idPName), e);
        }
        return true;
    }

    @SuppressFBWarnings("CRLF_INJECTION_LOGS")
    private void handlePresentationDefinitionUpdate(IdentityProvider identityProvider, String tenantDomain) {

        if (identityProvider == null) {
            return;
        }

        // Check if there is a presentation definition property
        String presentationDefinitionJson = null;
        IdentityProviderProperty[] properties = identityProvider.getIdpProperties();
        if (properties != null) {
            for (IdentityProviderProperty prop : properties) {
                if (PROP_PRESENTATION_DEFINITION.equals(prop.getName())) {
                    presentationDefinitionJson = prop.getValue();
                    break;
                }
            }
        }

        if (StringUtils.isBlank(presentationDefinitionJson)) {
            // Nothing to do if no PD is provided
            return;
        }

        try {
            PresentationDefinitionService pdService =
                    VPServiceDataHolder.getInstance().getPresentationDefinitionService();
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            String resourceId = identityProvider.getResourceId();

            if (StringUtils.isBlank(resourceId)) {
                log.warn("Resource ID is null for Identity Provider: "
                        + sanitize(identityProvider.getIdentityProviderName()));
                return;
            }

            // Check if a definition already exists for this resource
            PresentationDefinition existingPd = pdService.getPresentationDefinitionByResourceId(resourceId, tenantId);

            if (existingPd != null) {
                // Update existing
                existingPd.setDefinitionJson(presentationDefinitionJson);
                existingPd.setName(identityProvider.getIdentityProviderName() + " Definition"); // Sync name
                pdService.updatePresentationDefinition(existingPd, tenantId);
            } else {
                // Create new
                PresentationDefinition newPd = new PresentationDefinition.Builder()
                        .definitionId(UUID.randomUUID().toString())
                        .resourceId(resourceId)
                        .name(identityProvider.getIdentityProviderName() + " Definition")
                        .description("Auto-generated definition for connection: " + 
                        identityProvider.getIdentityProviderName())
                        .definitionJson(presentationDefinitionJson)
                        .tenantId(tenantId)
                        .build();
                pdService.createPresentationDefinition(newPd, tenantId);
            }

        } catch (VPException e) {
            log.error("Error managing presentation definition for IDP: "
                    + sanitize(identityProvider.getIdentityProviderName()), e);
        }
    }

    /**
     * Sanitize a string to prevent CRLF injection in log messages.
     *
     * @param input The string to sanitize
     * @return Sanitized string with CR/LF characters removed
     */
    private String sanitize(String input) {
        if (input == null) {
            return null;
        }
        return input.replace("\r", "").replace("\n", "");
    }
}
