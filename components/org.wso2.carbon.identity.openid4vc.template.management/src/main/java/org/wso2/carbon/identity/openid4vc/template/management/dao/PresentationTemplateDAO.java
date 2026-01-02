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

package org.wso2.carbon.identity.openid4vc.template.management.dao;

import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtException;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationTemplate;

import java.util.List;

/**
 * Data Access Object for Presentation Template operations.
 */
public interface PresentationTemplateDAO {

    /**
     * Create a new presentation template.
     *
     * @param template Presentation template to create
     * @param tenantId Tenant ID
     * @return Created template with generated ID
     * @throws VCTemplateMgtException if creation fails
     */
    PresentationTemplate createTemplate(PresentationTemplate template, int tenantId) throws VCTemplateMgtException;

    /**
     * Retrieve a presentation template by client ID.
     *
     * @param clientId Client ID
     * @param version  Template version (optional, defaults to "current")
     * @param tenantId Tenant ID
     * @return Presentation template or null if not found
     * @throws VCTemplateMgtException if retrieval fails
     */
    PresentationTemplate getTemplateByClientId(String clientId, String version, int tenantId)
            throws VCTemplateMgtException;

    /**
     * Update an existing presentation template.
     *
     * @param template Updated template
     * @param tenantId Tenant ID
     * @return Updated template
     * @throws VCTemplateMgtException if update fails
     */
    PresentationTemplate updateTemplate(PresentationTemplate template, int tenantId) throws VCTemplateMgtException;

    /**
     * Delete a presentation template.
     *
     * @param clientId Client ID
     * @param version  Template version
     * @param tenantId Tenant ID
     * @throws VCTemplateMgtException if deletion fails
     */
    void deleteTemplate(String clientId, String version, int tenantId) throws VCTemplateMgtException;

    /**
     * List all templates for a tenant.
     *
     * @param tenantId Tenant ID
     * @return List of templates
     * @throws VCTemplateMgtException if listing fails
     */
    List<PresentationTemplate> listTemplates(int tenantId) throws VCTemplateMgtException;

    /**
     * Check if a template exists.
     *
     * @param clientId Client ID
     * @param version  Template version
     * @param tenantId Tenant ID
     * @return true if exists
     * @throws VCTemplateMgtException if check fails
     */
    boolean templateExists(String clientId, String version, int tenantId) throws VCTemplateMgtException;
}

