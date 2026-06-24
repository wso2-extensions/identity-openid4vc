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

package org.wso2.carbon.identity.openid4vc.presentation.server.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.openid4vc.presentation.common.config.OpenID4VPConfigService;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.server.config.OpenID4VPConfigServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.server.service.StandaloneVerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.server.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.server.service.impl.VPRequestServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;

/**
 * OSGi DS component for the OpenID4VP presentation server.
 * Registers VPRequestService and OpenID4VPConfigService, and wires in
 * PresentationDefinitionService and VerificationService via mandatory references.
 */
@Component(name = "org.wso2.carbon.identity.openid4vc.presentation.server.component", immediate = true)
public class VPServerComponent {

    private static final Log LOG = LogFactory.getLog(VPServerComponent.class);
    private static final String OID4VP_ENABLED_CONFIG = "OpenID4VP.Enabled";

    @Activate
    protected void activate(ComponentContext context) {

        try {
            if (!Boolean.parseBoolean(IdentityUtil.getProperty(OID4VP_ENABLED_CONFIG))) {
                LOG.info("OpenID4VP feature is disabled in deployment.toml. Server services will not be registered.");
                return;
            }
            VPRequestServiceImpl vpRequestService = new VPRequestServiceImpl();
            VPServerDataHolder.setVPRequestService(vpRequestService);
            context.getBundleContext().registerService(
                    VPRequestService.class.getName(), vpRequestService, null);

            OpenID4VPConfigServiceImpl configService = new OpenID4VPConfigServiceImpl();
            VPServerDataHolder.setOpenID4VPConfigService(configService);
            context.getBundleContext().registerService(
                    OpenID4VPConfigService.class.getName(), configService, null);

            LOG.info("OpenID4VP presentation server component activated.");
        } catch (Throwable e) {
            LOG.error("Error activating OpenID4VP presentation server component.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        LOG.info("OpenID4VP presentation server component deactivated.");
    }

    @Reference(
        name = "openid4vc.presentation.definition.service",
        service = PresentationDefinitionService.class,
        cardinality = ReferenceCardinality.MANDATORY,
        policy = ReferencePolicy.DYNAMIC,
        unbind = "unsetPresentationDefinitionService"
    )
    protected void setPresentationDefinitionService(PresentationDefinitionService service) {

        VPServerDataHolder.setPresentationDefinitionService(service);
    }

    protected void unsetPresentationDefinitionService(PresentationDefinitionService service) {

        VPServerDataHolder.setPresentationDefinitionService(null);
    }

    @Reference(
        name = "openid4vc.verification.service",
        service = VerificationService.class,
        cardinality = ReferenceCardinality.MANDATORY,
        policy = ReferencePolicy.DYNAMIC,
        unbind = "unsetVerificationService"
    )
    protected void setVerificationService(VerificationService service) {

        VPServerDataHolder.setVerificationService(service);
    }

    protected void unsetVerificationService(VerificationService service) {

        VPServerDataHolder.setVerificationService(null);
    }

    @Reference(
        name = "openid4vc.standalone.verification.service",
        service = StandaloneVerificationService.class,
        cardinality = ReferenceCardinality.OPTIONAL,
        policy = ReferencePolicy.DYNAMIC,
        unbind = "unsetStandaloneVerificationService"
    )
    protected void setStandaloneVerificationService(StandaloneVerificationService service) {

        VPServerDataHolder.setStandaloneVerificationService(service);
    }

    protected void unsetStandaloneVerificationService(StandaloneVerificationService service) {

        VPServerDataHolder.setStandaloneVerificationService(null);
    }
}
