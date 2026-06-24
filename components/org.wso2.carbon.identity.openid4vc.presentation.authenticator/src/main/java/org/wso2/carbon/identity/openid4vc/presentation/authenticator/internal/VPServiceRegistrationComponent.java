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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.OpenID4VPAuthenticator;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.idp.mgt.listener.IdentityProviderMgtListener;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Slimmed OSGi component for the OpenID4VP authenticator bundle.
 * Registers only the OpenID4VP authenticator and the IdP management listener.
 * All server services are now registered by presentation.server/VPServerComponent.
 */
@Component(name = "org.wso2.carbon.identity.openid4vc.presentation.service.component", immediate = true)
public class VPServiceRegistrationComponent {

    private static final Log LOG = LogFactory.getLog(VPServiceRegistrationComponent.class);

    private static final String OID4VP_ENABLED_CONFIG = "OpenID4VP.Enabled";

    @Activate
    protected void activate(ComponentContext context) {

        try {
            boolean isOid4vpEnabled = Boolean.parseBoolean(IdentityUtil.getProperty(OID4VP_ENABLED_CONFIG));
            if (!isOid4vpEnabled) {
                LOG.info("OpenID4VP feature is disabled in deployment.toml. Authenticator will not be registered.");
                return;
            }

            context.getBundleContext().registerService(
                    ApplicationAuthenticator.class.getName(),
                    new OpenID4VPAuthenticator(),
                    null);

            context.getBundleContext().registerService(
                    IdentityProviderMgtListener.class.getName(),
                    new OpenID4VPIdPManagementListener(),
                    null);

            LOG.info("OpenID4VP Authenticator bundle is activated.");
        } catch (Throwable e) {
            LOG.error("Error while activating OpenID4VP authenticator component.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        LOG.info("OpenID4VP Authenticator bundle is deactivated.");
    }

    @Reference(
        name = "user.realm.service",
        service = RealmService.class,
        cardinality = ReferenceCardinality.MANDATORY,
        policy = ReferencePolicy.DYNAMIC,
        unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        VPServiceDataHolder.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        VPServiceDataHolder.setRealmService(null);
    }

    @Reference(
        name = "org.wso2.carbon.identity.application.mgt.ApplicationManagementService",
        service = ApplicationManagementService.class,
        cardinality = ReferenceCardinality.MANDATORY,
        policy = ReferencePolicy.DYNAMIC,
        unbind = "unsetApplicationManagementService"
    )
    protected void setApplicationManagementService(ApplicationManagementService service) {

        VPServiceDataHolder.setApplicationManagementService(service);
    }

    protected void unsetApplicationManagementService(ApplicationManagementService service) {

        VPServiceDataHolder.setApplicationManagementService(null);
    }

    @Reference(
        name = "org.wso2.carbon.identity.organization.management.service.OrganizationManager",
        service = OrganizationManager.class,
        cardinality = ReferenceCardinality.OPTIONAL,
        policy = ReferencePolicy.DYNAMIC,
        unbind = "unsetOrganizationManager"
    )
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        VPServiceDataHolder.setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        VPServiceDataHolder.setOrganizationManager(null);
    }
}
