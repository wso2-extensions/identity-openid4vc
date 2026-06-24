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

import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Slimmed data holder for the authenticator module.
 * Only holds the services directly consumed by the authenticator and IdP listener.
 */
public final class VPServiceDataHolder {

    private static final AtomicReference<RealmService> REALM_SERVICE = new AtomicReference<>();
    private static final AtomicReference<ApplicationManagementService> APPLICATION_MANAGEMENT_SERVICE =
            new AtomicReference<>();
    private static final AtomicReference<OrganizationManager> ORGANIZATION_MANAGER = new AtomicReference<>();

    private VPServiceDataHolder() { }

    public static RealmService getRealmService() { return REALM_SERVICE.get(); }
    public static void setRealmService(RealmService realmService) { REALM_SERVICE.set(realmService); }

    public static ApplicationManagementService getApplicationManagementService() {
        return APPLICATION_MANAGEMENT_SERVICE.get();
    }
    public static void setApplicationManagementService(ApplicationManagementService service) {
        APPLICATION_MANAGEMENT_SERVICE.set(service);
    }

    public static OrganizationManager getOrganizationManager() { return ORGANIZATION_MANAGER.get(); }
    public static void setOrganizationManager(OrganizationManager organizationManager) {
        ORGANIZATION_MANAGER.set(organizationManager);
    }
}
