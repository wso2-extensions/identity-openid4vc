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
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
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

    @SuppressFBWarnings({"CRLF_INJECTION_LOGS", "REC_CATCH_EXCEPTION"})
    private void handlePresentationDefinitionUpdate(IdentityProvider identityProvider, String tenantDomain) {

        if (identityProvider == null) {
            return;
        }

        // Check if there is a presentation definition property
        String presentationDefinitionValue = null;
        IdentityProviderProperty[] properties = identityProvider.getIdpProperties();
        if (properties != null) {
            for (IdentityProviderProperty prop : properties) {
                if (PROP_PRESENTATION_DEFINITION.equals(prop.getName())) {
                    presentationDefinitionValue = prop.getValue();
                    break;
                }
            }
        }

        if (StringUtils.isBlank(presentationDefinitionValue)) {
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

            // Determine if the value is a definition ID (UUID) or a JSON string.
            // A UUID is a short alphanumeric string; JSON starts with '{'.
            boolean isJson = presentationDefinitionValue.trim().startsWith("{");

            if (isJson) {
                // Value is PD JSON — this is a new connection creation.
                // Create the PD in the database and update the IDP property to store the definition ID.
                PresentationDefinition existingPd = pdService.getPresentationDefinitionByResourceId(
                        resourceId, tenantId);

                String definitionId;
                if (existingPd != null) {
                    // Update existing definition with new JSON
                    existingPd.setDefinitionJson(presentationDefinitionValue);
                    existingPd.setName(identityProvider.getIdentityProviderName() + " Definition");
                    pdService.updatePresentationDefinition(existingPd, tenantId);
                    definitionId = existingPd.getDefinitionId();
                } else {
                    // Create new definition
                    definitionId = UUID.randomUUID().toString();
                    PresentationDefinition newPd = new PresentationDefinition.Builder()
                            .definitionId(definitionId)
                            .resourceId(resourceId)
                            .name(identityProvider.getIdentityProviderName() + " Definition")
                            .description("Auto-generated definition for connection: " +
                                    identityProvider.getIdentityProviderName())
                            .definitionJson(presentationDefinitionValue)
                            .tenantId(tenantId)
                            .build();
                    pdService.createPresentationDefinition(newPd, tenantId);
                }

                // Update the IDP property to store the definition ID instead of JSON
                updateIdPPropertyToDefinitionId(identityProvider, tenantDomain, definitionId);

            } else {
                // Value is already a definition ID — this is a connection update.
                // The definition JSON should be updated via the PUT endpoint, not here.
                // Just verify the definition still exists.
                String definitionId = presentationDefinitionValue.trim();
                PresentationDefinition existingPd = pdService.getPresentationDefinitionByResourceId(
                        resourceId, tenantId);
                if (existingPd == null) {
                    log.warn("Presentation definition not found for definition ID: "
                            + sanitize(definitionId) + " and resource ID: " + sanitize(resourceId));
                }
            }

        } catch (Exception e) {
            log.error("Error managing presentation definition for IDP: "
                    + sanitize(identityProvider.getIdentityProviderName()), e);
        }
    }

    /**
     * Update IDP property to store the definition ID instead of the full JSON.
     */
    @SuppressFBWarnings({"CRLF_INJECTION_LOGS", "REC_CATCH_EXCEPTION"})
    private void updateIdPPropertyToDefinitionId(IdentityProvider identityProvider,
            String tenantDomain, String definitionId) {

        try {
            IdentityProviderProperty[] properties = identityProvider.getIdpProperties();
            if (properties != null) {
                for (IdentityProviderProperty prop : properties) {
                    if (PROP_PRESENTATION_DEFINITION.equals(prop.getName())) {
                        prop.setValue(definitionId);
                        break;
                    }
                }
            }

            // Update the IDP to persist the property change.
            // This will trigger doPostUpdateIdP again, but since the value is now a UUID
            // (not JSON), the listener will take the non-JSON branch and skip the update loop.
            IdentityProviderManager.getInstance()
                    .updateIdP(identityProvider.getIdentityProviderName(),
                            identityProvider, tenantDomain);
        } catch (Exception e) {
            log.error("Error updating IDP property to definition ID for: "
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
