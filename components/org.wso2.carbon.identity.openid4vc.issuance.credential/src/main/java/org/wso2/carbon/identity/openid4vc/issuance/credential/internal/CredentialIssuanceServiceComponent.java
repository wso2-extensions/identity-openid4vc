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

package org.wso2.carbon.identity.openid4vc.issuance.credential.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenProvider;
import org.wso2.carbon.identity.openid4vc.issuance.credential.CredentialIssuanceService;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.handlers.CredentialFormatHandler;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.handlers.impl.JwtVcJsonFormatHandler;
import org.wso2.carbon.identity.openid4vc.template.management.VCTemplateManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Service component for credential issuance operations.
 */
@Component(
        name = "identity.openid4vc.issuance.credential.component",
        immediate = true
)
public class CredentialIssuanceServiceComponent {

    private static final Log LOG = LogFactory.getLog(CredentialIssuanceServiceComponent.class);


    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleContext = context.getBundleContext();
            bundleContext.registerService(CredentialIssuanceService.class, new CredentialIssuanceService(), null);
            bundleContext.registerService(CredentialFormatHandler.class, new JwtVcJsonFormatHandler(), null);
            if (LOG.isDebugEnabled()) {
                LOG.debug("OID4VCI credential issuance component activated");
            }
        } catch (Throwable throwable) {
            LOG.error("Error while activating CredentialIssuanceServiceComponent", throwable);
        }
    }

    @Reference(
            name = "vc.template.mgt.service.component",
            service = VCTemplateManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetVCTemplateManager"
    )
    protected void setVCTemplateManager(VCTemplateManager vcTemplateManager) {

        CredentialIssuanceDataHolder.getInstance().setVCTemplateManager(vcTemplateManager);
    }

    protected void unsetVCTemplateManager(VCTemplateManager vcTemplateManager) {

        CredentialIssuanceDataHolder.getInstance().setVCTemplateManager(null);
    }

    @Reference(
            name = "openid4vc.issuance.credential.handler.format",
            service = CredentialFormatHandler.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeScopeValidationHandler"
    )
    protected void addCredentialFormatHandler(CredentialFormatHandler credentialFormatHandler) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Adding the CredentialFormatHandler Service : " + credentialFormatHandler.getFormat());
        }
        CredentialIssuanceDataHolder.getInstance().addCredentialFormatHandler(credentialFormatHandler);
    }

    protected void removeScopeValidationHandler(CredentialFormatHandler credentialFormatHandler) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Removing the CredentialFormatHandler Service : " + credentialFormatHandler.getFormat());
        }
        CredentialIssuanceDataHolder.getInstance().removeCredentialFormatHandler(credentialFormatHandler);
    }

    @Reference(
            name = "token.provider",
            service = TokenProvider.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetTokenProvider"
    )
    protected void setTokenProvider(TokenProvider tokenProvider) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Setting token provider.");
        }
        CredentialIssuanceDataHolder.getInstance().setTokenProvider(tokenProvider);
    }

    protected void unsetTokenProvider(TokenProvider tokenProvider) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Unset token provider.");
        }
        CredentialIssuanceDataHolder.getInstance().setTokenProvider(null);
    }

    @Reference(
            name = "user.realmservice.default",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Adding the Realm Service");
        }
        CredentialIssuanceDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Removing the Realm Service");
        }
        CredentialIssuanceDataHolder.getInstance().setRealmService(null);
    }
}
