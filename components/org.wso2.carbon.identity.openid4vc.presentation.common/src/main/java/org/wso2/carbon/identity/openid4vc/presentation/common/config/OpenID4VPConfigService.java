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

package org.wso2.carbon.identity.openid4vc.presentation.common.config;

/**
 * OSGi service for per-tenant OpenID4VP configuration management.
 * Config is persisted in the governance registry under each tenant's namespace.
 */
public interface OpenID4VPConfigService {

    /**
     * Retrieve the OpenID4VP configuration for the given tenant.
     * Returns an object with null fields if no tenant-level config has been saved.
     *
     * @param tenantDomain Tenant domain.
     * @return Current tenant config (never null; fields may be null).
     * @throws OpenID4VPConfigMgtException on registry error.
     */
    OpenID4VPTenantConfig getConfig(String tenantDomain) throws OpenID4VPConfigMgtException;

    /**
     * Retrieve the OpenID4VP configuration by tenant ID.
     * Convenience overload for callers that only have a tenant ID.
     *
     * @param tenantId Tenant ID.
     * @return Current tenant config (never null; fields may be null).
     * @throws OpenID4VPConfigMgtException on registry or tenant-resolution error.
     */
    OpenID4VPTenantConfig getConfigByTenantId(int tenantId) throws OpenID4VPConfigMgtException;

    /**
     * Persist the OpenID4VP configuration for the given tenant.
     * Replaces any previously stored config.
     *
     * @param config       New config values.
     * @param tenantDomain Tenant domain.
     * @throws OpenID4VPConfigMgtException on registry error.
     */
    void setConfig(OpenID4VPTenantConfig config, String tenantDomain) throws OpenID4VPConfigMgtException;
}
