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

package org.wso2.carbon.identity.openid4vc.presentation.service.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.dao.ApplicationPresentationDefinitionMappingDAO;
import org.wso2.carbon.identity.openid4vc.presentation.dao.impl.ApplicationPresentationDefinitionMappingDAOImpl;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.ApplicationPresentationDefinitionMapping;
import org.wso2.carbon.identity.openid4vc.presentation.service.ApplicationPresentationDefinitionMappingService;

/**
 * Implementation of ApplicationPresentationDefinitionMappingService.
 */
public class ApplicationPresentationDefinitionMappingServiceImpl 
        implements ApplicationPresentationDefinitionMappingService {

    private static final Log log = LogFactory.getLog(ApplicationPresentationDefinitionMappingServiceImpl.class);

    private final ApplicationPresentationDefinitionMappingDAO mappingDAO;

    /**
     * Default constructor.
     */
    public ApplicationPresentationDefinitionMappingServiceImpl() {
        this.mappingDAO = new ApplicationPresentationDefinitionMappingDAOImpl();
    }

    /**
     * Constructor with dependency injection.
     *
     * @param mappingDAO The DAO for mappings
     */
    public ApplicationPresentationDefinitionMappingServiceImpl(
            ApplicationPresentationDefinitionMappingDAO mappingDAO) {
        this.mappingDAO = mappingDAO;
    }

    @Override
    public void mapPresentationDefinitionToApplication(String applicationId, 
                                                        String presentationDefinitionId, 
                                                        int tenantId) throws VPException {
        
        if (log.isDebugEnabled()) {
            log.debug("Mapping presentation definition '" + presentationDefinitionId + 
                    "' to application '" + applicationId + "' for tenant: " + tenantId);
        }

        ApplicationPresentationDefinitionMapping mapping = new ApplicationPresentationDefinitionMapping.Builder()
                .applicationId(applicationId)
                .presentationDefinitionId(presentationDefinitionId)
                .tenantId(tenantId)
                .createdAt(System.currentTimeMillis())
                .updatedAt(System.currentTimeMillis())
                .build();

        mappingDAO.createOrUpdateMapping(mapping);

        if (log.isInfoEnabled()) {
            log.info("Successfully mapped presentation definition '" + presentationDefinitionId + 
                    "' to application '" + applicationId + "'");
        }
    }

    @Override
    public String getApplicationPresentationDefinitionId(String applicationId, int tenantId) 
            throws VPException {
        
        if (log.isDebugEnabled()) {
            log.debug("Retrieving presentation definition ID for application '" + applicationId + 
                    "' in tenant: " + tenantId);
        }

        String presentationDefinitionId = mappingDAO.getPresentationDefinitionIdByApplicationId(
                applicationId, tenantId);

        if (log.isDebugEnabled()) {
            log.debug("Retrieved presentation definition ID: " + 
                    (presentationDefinitionId != null ? presentationDefinitionId : "NOT FOUND"));
        }

        return presentationDefinitionId;
    }

    @Override
    public ApplicationPresentationDefinitionMapping getApplicationMapping(String applicationId, 
                                                                          int tenantId) throws VPException {
        
        if (log.isDebugEnabled()) {
            log.debug("Retrieving mapping for application '" + applicationId + 
                    "' in tenant: " + tenantId);
        }

        ApplicationPresentationDefinitionMapping mapping = mappingDAO.getMappingByApplicationId(
                applicationId, tenantId);

        if (log.isDebugEnabled()) {
            log.debug("Retrieved mapping: " + (mapping != null ? "FOUND" : "NOT FOUND"));
        }

        return mapping;
    }

    @Override
    public void removePresentationDefinitionMapping(String applicationId, int tenantId) 
            throws VPException {
        
        if (log.isDebugEnabled()) {
            log.debug("Removing presentation definition mapping for application '" + applicationId + 
                    "' in tenant: " + tenantId);
        }

        mappingDAO.deleteMapping(applicationId, tenantId);

        if (log.isInfoEnabled()) {
            log.info("Successfully removed presentation definition mapping for application '" + 
                    applicationId + "'");
        }
    }

    @Override
    public boolean isApplicationMappingExists(String applicationId, int tenantId) throws VPException {
        
        if (log.isDebugEnabled()) {
            log.debug("Checking if mapping exists for application '" + applicationId + 
                    "' in tenant: " + tenantId);
        }

        return mappingDAO.mappingExists(applicationId, tenantId);
    }
}
