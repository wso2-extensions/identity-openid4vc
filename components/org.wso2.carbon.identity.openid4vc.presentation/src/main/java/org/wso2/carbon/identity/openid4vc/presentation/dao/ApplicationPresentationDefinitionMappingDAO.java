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

package org.wso2.carbon.identity.openid4vc.presentation.dao;

import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.ApplicationPresentationDefinitionMapping;

/**
 * DAO interface for Application Presentation Definition Mapping operations.
 */
public interface ApplicationPresentationDefinitionMappingDAO {

    /**
     * Create or update a mapping between application and presentation definition.
     *
     * @param mapping The mapping to create or update
     * @throws VPException If an error occurs
     */
    void createOrUpdateMapping(ApplicationPresentationDefinitionMapping mapping) throws VPException;

    /**
     * Get the presentation definition ID for a specific application.
     *
     * @param applicationId The application ID
     * @param tenantId      The tenant ID
     * @return The presentation definition ID or null if not found
     * @throws VPException If an error occurs
     */
    String getPresentationDefinitionIdByApplicationId(String applicationId, int tenantId) throws VPException;

    /**
     * Get the mapping for an application.
     *
     * @param applicationId The application ID
     * @param tenantId      The tenant ID
     * @return The mapping or null if not found
     * @throws VPException If an error occurs
     */
    ApplicationPresentationDefinitionMapping getMappingByApplicationId(String applicationId, int tenantId)
            throws VPException;

    /**
     * Delete the mapping for an application.
     *
     * @param applicationId The application ID
     * @param tenantId      The tenant ID
     * @throws VPException If an error occurs
     */
    void deleteMapping(String applicationId, int tenantId) throws VPException;

    /**
     * Check if a mapping exists for an application.
     *
     * @param applicationId The application ID
     * @param tenantId      The tenant ID
     * @return True if mapping exists, false otherwise
     * @throws VPException If an error occurs
     */
    boolean mappingExists(String applicationId, int tenantId) throws VPException;
}
