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

package org.wso2.carbon.identity.openid4vc.presentation.standalone.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.openid4vc.presentation.server.service.StandaloneVerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.server.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.standalone.service.impl.StandaloneVerificationServiceImpl;

/**
 * OSGi Declarative Services component for the OpenID4VP standalone verification module.
 * Registers StandaloneVerificationService so the server servlet can dispatch non-auth-flow
 * VP requests to it.
 */
@Component(
    name = "org.wso2.carbon.identity.openid4vc.presentation.standalone.component",
    immediate = true
)
public class StandaloneComponent {

    private static final Log LOG = LogFactory.getLog(StandaloneComponent.class);

    private VPRequestService vpRequestService;

    @Activate
    protected void activate(ComponentContext context) {

        try {
            StandaloneVerificationServiceImpl service = new StandaloneVerificationServiceImpl(vpRequestService);
            context.getBundleContext().registerService(
                    StandaloneVerificationService.class.getName(), service, null);
            LOG.info("OpenID4VP standalone verification component activated.");
        } catch (Exception e) {
            LOG.error("Failed to activate OpenID4VP standalone verification component.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        LOG.info("OpenID4VP standalone verification component deactivated.");
    }

    @Reference(
        name = "openid4vc.vp.request.service",
        service = VPRequestService.class,
        cardinality = ReferenceCardinality.MANDATORY,
        policy = ReferencePolicy.DYNAMIC,
        unbind = "unsetVPRequestService"
    )
    protected void setVPRequestService(VPRequestService service) {

        this.vpRequestService = service;
    }

    protected void unsetVPRequestService(VPRequestService service) {

        this.vpRequestService = null;
    }
}
