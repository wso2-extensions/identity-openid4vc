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

package org.wso2.carbon.identity.openid4vc.issuance.metadata.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.CredentialIssuerMetadataProcessor;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.DefaultCredentialIssuerMetadataProcessor;
import org.wso2.carbon.identity.openid4vc.template.management.VCTemplateManager;

/**
 * Service component for OID4VCI Credential Issuer Metadata.
 */
@Component(
        name = "identity.openid4vc.issuance.metadata.component",
        immediate = true
)
public class CredentialIssuerMetadataServiceComponent {
    private static final Log LOG = LogFactory.getLog(CredentialIssuerMetadataServiceComponent.class);
    private static BundleContext bundleContext = null;

    public static BundleContext getBundleContext() {
        return bundleContext;
    }

    protected void activate(ComponentContext context) {
        try {
            bundleContext = context.getBundleContext();
            // exposing server configuration as a service
            bundleContext.registerService(CredentialIssuerMetadataProcessor.class.getName(),
                    DefaultCredentialIssuerMetadataProcessor.getInstance(), null);
            if (LOG.isDebugEnabled()) {
                LOG.debug("OID4VCI Credential Issuer Metadata bundle is activated");
            }
        } catch (Throwable e) {
            LOG.error("Error while activating CredentialIssuerMetadataServiceComponent", e);
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

        CredentialIssuerMetadataDataHolder.getInstance().setVCTemplateManager(vcTemplateManager);
    }

    protected void unsetVCTemplateManager(VCTemplateManager vcTemplateManager) {

        CredentialIssuerMetadataDataHolder.getInstance().setVCTemplateManager(null);
    }

}
