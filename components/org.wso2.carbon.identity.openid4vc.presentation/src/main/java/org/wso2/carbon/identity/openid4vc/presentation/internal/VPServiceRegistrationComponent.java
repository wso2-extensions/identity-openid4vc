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

package org.wso2.carbon.identity.openid4vc.presentation.internal;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.OpenID4VPAuthenticator;
import org.wso2.carbon.identity.openid4vc.presentation.service.ApplicationPresentationDefinitionMappingService;
import org.wso2.carbon.identity.openid4vc.presentation.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPSubmissionService;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.ApplicationPresentationDefinitionMappingServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.PresentationDefinitionServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.VPRequestServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.VPSubmissionServiceImpl;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Hashtable;

/**
 * OSGi component for OpenID4VP service registration.
 * 
 * This component:
 * 1. Creates and registers service implementations as OSGi services
 * 2. Registers the OpenID4VP authenticator with the authentication framework
 * 3. Initializes the VPServiceDataHolder with required services
 */
@Component(name = "org.wso2.carbon.identity.openid4vc.presentation.service.component", immediate = true)
public class VPServiceRegistrationComponent {

    private static volatile boolean authenticatorRegistered = false;

    @Activate
    protected void activate(ComponentContext context) {
        try {
            // Only register once to avoid duplicates
            if (authenticatorRegistered) {
                                return;
            }

            BundleContext bundleContext = context.getBundleContext();

            // Initialize database schema (creates tables if they don't exist)
                        DatabaseSchemaInitializer.initializeSchema();

            // Initialize services using default constructors (which create their own DAOs)
            VPRequestService vpRequestService = new VPRequestServiceImpl();
            VPSubmissionService vpSubmissionService = new VPSubmissionServiceImpl();
            PresentationDefinitionService presentationDefinitionService = new PresentationDefinitionServiceImpl();
            ApplicationPresentationDefinitionMappingService mappingService = 
            new ApplicationPresentationDefinitionMappingServiceImpl();

            // Register services with OSGi
            bundleContext.registerService(VPRequestService.class.getName(),
                    vpRequestService, new Hashtable<>());
            bundleContext.registerService(VPSubmissionService.class.getName(),
                    vpSubmissionService, new Hashtable<>());
            bundleContext.registerService(PresentationDefinitionService.class.getName(),
                    presentationDefinitionService, new Hashtable<>());
            bundleContext.registerService(
                    ApplicationPresentationDefinitionMappingService.class.getName(),
                    mappingService, new Hashtable<>());

            // Set services in data holder
            VPServiceDataHolder.getInstance().setVPRequestService(vpRequestService);
            VPServiceDataHolder.getInstance().setVPSubmissionService(vpSubmissionService);
            VPServiceDataHolder.getInstance().setPresentationDefinitionService(presentationDefinitionService);
            VPServiceDataHolder.getInstance().setApplicationPresentationDefinitionMappingService(mappingService);

            // Register OpenID4VP Authenticator
            OpenID4VPAuthenticator authenticator = new OpenID4VPAuthenticator();
            bundleContext.registerService(ApplicationAuthenticator.class.getName(),
                    authenticator, new Hashtable<>());

            authenticatorRegistered = true;

                        
        } catch (Exception e) {
                    }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        // Services are automatically unregistered by OSGi
        VPServiceDataHolder.getInstance().setVPRequestService(null);
        VPServiceDataHolder.getInstance().setVPSubmissionService(null);
        VPServiceDataHolder.getInstance().setPresentationDefinitionService(null);
        VPServiceDataHolder.getInstance().setApplicationPresentationDefinitionMappingService(null);

        authenticatorRegistered = false;

            }

    @Reference(name = "user.realm.service", service = RealmService.class, cardinality = 
    ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {
        VPServiceDataHolder.getInstance().setRealmService(realmService);
        if (log.isDebugEnabled()) {
                    }
    }

    protected void unsetRealmService(RealmService realmService) {
        VPServiceDataHolder.getInstance().setRealmService(null);
        if (log.isDebugEnabled()) {
                    }
    }

    @Reference(name = "application.mgt.service", service = ApplicationManagementService.class, cardinality = 
    ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetApplicationManagementService")
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {
        VPServiceDataHolder.getInstance().setApplicationManagementService(applicationManagementService);
        if (log.isDebugEnabled()) {
                    }
    }

    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {
        VPServiceDataHolder.getInstance().setApplicationManagementService(null);
        if (log.isDebugEnabled()) {
                    }
    }
}
