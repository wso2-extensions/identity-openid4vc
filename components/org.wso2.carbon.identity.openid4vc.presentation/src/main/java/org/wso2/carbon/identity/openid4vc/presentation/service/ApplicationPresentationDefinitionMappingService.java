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

package org.wso2.carbon.identity.openid4vc.presentation.service;

import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.ApplicationPresentationDefinitionMapping;

/**
 * Service interface for managing application-presentation definition mappings.
 */
public interface ApplicationPresentationDefinitionMappingService {

    /**
     * Map a presentation definition to an application.
     *
     * @param applicationId The application ID
     * @param presentationDefinitionId The presentation definition ID
     * @param tenantId The tenant ID
     * @throws VPException If an error occurs
     */
    void mapPresentationDefinitionToApplication(String applicationId, 
                                                 String presentationDefinitionId, 
                                                 int tenantId) throws VPException;

    /**
     * Get the presentation definition ID mapped to an application.
     *
     * @param applicationId The application ID
     * @param tenantId The tenant ID
     * @return The presentation definition ID or null if not found
     * @throws VPException If an error occurs
     */
    String getApplicationPresentationDefinitionId(String applicationId, int tenantId) throws VPException;

    /**
     * Get the mapping for an application.
     *
     * @param applicationId The application ID
     * @param tenantId The tenant ID
     * @return The mapping or null if not found
     * @throws VPException If an error occurs
     */
    ApplicationPresentationDefinitionMapping getApplicationMapping(String applicationId, 
                                                                   int tenantId) throws VPException;

    /**
     * Remove the presentation definition mapping for an application.
     *
     * @param applicationId The application ID
     * @param tenantId The tenant ID
     * @throws VPException If an error occurs
     */
    void removePresentationDefinitionMapping(String applicationId, int tenantId) throws VPException;

    /**
     * Check if a presentation definition is mapped to an application.
     *
     * @param applicationId The application ID
     * @param tenantId The tenant ID
     * @return True if mapped, false otherwise
     * @throws VPException If an error occurs
     */
    boolean isApplicationMappingExists(String applicationId, int tenantId) throws VPException;
}
