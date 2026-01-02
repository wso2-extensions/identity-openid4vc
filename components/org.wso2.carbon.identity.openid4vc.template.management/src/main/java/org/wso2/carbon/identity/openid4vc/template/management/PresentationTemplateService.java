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

package org.wso2.carbon.identity.openid4vc.template.management;

import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtException;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationTemplate;

import java.util.List;

/**
 * Service interface for Presentation Template management.
 */
public interface PresentationTemplateService {

    /**
     * Create a new presentation template.
     *
     * @param template      Presentation template to create
     * @param tenantDomain  Tenant domain
     * @return Created template
     * @throws VCTemplateMgtException if creation fails
     */
    PresentationTemplate createTemplate(PresentationTemplate template, String tenantDomain)
            throws VCTemplateMgtException;

    /**
     * Get a presentation template by client ID.
     *
     * @param clientId      Client ID
     * @param version       Template version (optional)
     * @param tenantDomain  Tenant domain
     * @return Template or null if not found
     * @throws VCTemplateMgtException if retrieval fails
     */
    PresentationTemplate getTemplateByClientId(String clientId, String version, String tenantDomain)
            throws VCTemplateMgtException;

    /**
     * Update a presentation template.
     *
     * @param template      Template to update
     * @param tenantDomain  Tenant domain
     * @return Updated template
     * @throws VCTemplateMgtException if update fails
     */
    PresentationTemplate updateTemplate(PresentationTemplate template, String tenantDomain)
            throws VCTemplateMgtException;

    /**
     * Delete a presentation template.
     *
     * @param clientId      Client ID
     * @param version       Template version
     * @param tenantDomain  Tenant domain
     * @throws VCTemplateMgtException if deletion fails
     */
    void deleteTemplate(String clientId, String version, String tenantDomain) throws VCTemplateMgtException;

    /**
     * List all templates for a tenant.
     *
     * @param tenantDomain  Tenant domain
     * @return List of templates
     * @throws VCTemplateMgtException if listing fails
     */
    List<PresentationTemplate> listTemplates(String tenantDomain) throws VCTemplateMgtException;

    /**
     * Get or create default template for a client.
     *
     * @param clientId      Client ID
     * @param tenantDomain  Tenant domain
     * @return Template (existing or newly created default)
     * @throws VCTemplateMgtException if operation fails
     */
    PresentationTemplate getOrCreateDefaultTemplate(String clientId, String tenantDomain)
            throws VCTemplateMgtException;
}

