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

package org.wso2.carbon.identity.openid4vc.issuance.offer.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.openid4vc.config.management.VCCredentialConfigManager;
import org.wso2.carbon.identity.openid4vc.issuance.offer.CredentialOfferProcessor;
import org.wso2.carbon.identity.openid4vc.issuance.offer.DefaultCredentialOfferProcessor;

/**
 * Service component for OID4VCI Credential Offer.
 */
@Component(
        name = "identity.openid4vc.issuance.offer.component",
        immediate = true
)
public class CredentialOfferServiceComponent {

    private static final Log log = LogFactory.getLog(CredentialOfferServiceComponent.class);

    protected void activate(ComponentContext context) {
        try {
            BundleContext bundleContext = context.getBundleContext();
            // Exposing credential offer processor as a service
            bundleContext.registerService(CredentialOfferProcessor.class.getName(),
                    DefaultCredentialOfferProcessor.getInstance(), null);
            if (log.isDebugEnabled()) {
                log.debug("OID4VCI Credential Offer bundle is activated");
            }
        } catch (Throwable e) {
            log.error("Error while activating CredentialOfferServiceComponent", e);
        }
    }

    @Reference(
            name = "vc.config.mgt.service.component",
            service = VCCredentialConfigManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetVCCredentialConfigManager"
    )
    protected void setVCCredentialConfigManager(VCCredentialConfigManager vcCredentialConfigManager) {

        CredentialOfferDataHolder.getInstance().setVcCredentialConfigManager(vcCredentialConfigManager);
    }

    protected void unsetVCCredentialConfigManager(VCCredentialConfigManager vcCredentialConfigManager) {

        CredentialOfferDataHolder.getInstance().setVcCredentialConfigManager(null);
    }
}

