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

package org.wso2.carbon.identity.openid4vc.presentation.registration.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.openid4vc.presentation.registration.executor.OpenID4VPRegistrationExecutor;
import org.wso2.carbon.identity.openid4vc.presentation.server.service.StandaloneVerificationService;

/**
 * OSGi Declarative Services component for the OpenID4VP wallet self-registration module.
 * Registers {@link OpenID4VPRegistrationExecutor} as an {@link Executor} OSGi service
 * so the IS flow engine can discover and invoke it.
 */
@Component(
    name = "org.wso2.carbon.identity.openid4vc.presentation.registration.component",
    immediate = true
)
public class RegistrationComponent {

    private static final Log LOG = LogFactory.getLog(RegistrationComponent.class);

    private StandaloneVerificationService standaloneVerificationService;

    @Activate
    protected void activate(ComponentContext context) {

        try {
            context.getBundleContext().registerService(
                    Executor.class.getName(),
                    new OpenID4VPRegistrationExecutor(standaloneVerificationService),
                    null);
            LOG.info("OpenID4VP registration component activated.");
        } catch (Exception e) {
            LOG.error("Failed to activate OpenID4VP registration component.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        LOG.info("OpenID4VP registration component deactivated.");
    }

    @Reference(
        name = "openid4vc.standalone.verification.service",
        service = StandaloneVerificationService.class,
        cardinality = ReferenceCardinality.MANDATORY,
        policy = ReferencePolicy.DYNAMIC,
        unbind = "unsetStandaloneVerificationService"
    )
    protected void setStandaloneVerificationService(StandaloneVerificationService service) {

        this.standaloneVerificationService = service;
    }

    protected void unsetStandaloneVerificationService(StandaloneVerificationService service) {

        this.standaloneVerificationService = null;
    }
}
