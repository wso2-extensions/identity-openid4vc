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
import org.wso2.carbon.identity.openid4vc.template.management.model.VCTemplate;
import org.wso2.carbon.identity.openid4vc.template.management.model.VCTemplateSearchResult;

import java.util.List;

/**
 * Manager interface for Verifiable Credential templates.
 */
public interface VCTemplateManager {

    /**
     * List all VC templates for a tenant.
     *
     * @param tenantDomain Tenant domain.
     * @return List of templates.
     * @throws VCTemplateMgtException on retrieval errors.
     */
    List<VCTemplate> list(String tenantDomain) throws VCTemplateMgtException;

    /**
     * List VC templates with pagination support.
     *
     * @param after        Get templates after this cursor value.
     * @param before       Get templates before this cursor value.
     * @param limit        Maximum number of templates to retrieve.
     * @param filter       Filter expression.
     * @param sortOrder    Sort order (ASC or DESC).
     * @param tenantDomain Tenant domain.
     * @return VC template search result with pagination.
     * @throws VCTemplateMgtException If an error occurs while retrieving templates.
     */
    VCTemplateSearchResult listWithPagination(String after, String before, Integer limit, String filter,
                                              String sortOrder, String tenantDomain)
            throws VCTemplateMgtException;

    /**
     * Get a template by ID.
     *
     * @param id     Unique template id.
     * @param tenantDomain Tenant domain.
     * @return Template or null if not found.
     * @throws VCTemplateMgtException on retrieval errors.
     */
    VCTemplate get(String id, String tenantDomain) throws VCTemplateMgtException;

    /**
     * Get a template by identifier.
     *
     * @param identifier Identifier of the template.
     * @param tenantDomain Tenant domain.
     * @return Template or null if not found.
     * @throws VCTemplateMgtException on retrieval errors.
     */
    VCTemplate getByIdentifier(String identifier, String tenantDomain) throws VCTemplateMgtException;

    /**
     * Get a template by offer ID.
     *
     * @param offerId Offer ID of the template.
     * @param tenantDomain Tenant domain.
     * @return Template or null if not found.
     * @throws VCTemplateMgtException on retrieval errors.
     */
    VCTemplate getByOfferId(String offerId, String tenantDomain) throws VCTemplateMgtException;

    /**
     * Add a new template.
     *
     * @param template Template payload.
     * @param tenantDomain  Tenant domain.
     * @return Added template.
     * @throws VCTemplateMgtException on creation errors.
     */
    VCTemplate add(VCTemplate template, String tenantDomain)
            throws VCTemplateMgtException;

    /**
     * Update an existing template by id.
     *
     * @param id      Template id to update.
     * @param template Updated payload.
     * @param tenantDomain  Tenant domain.
     * @return Updated template.
     * @throws VCTemplateMgtException on update errors.
     */
    VCTemplate update(String id, VCTemplate template, String tenantDomain)
            throws VCTemplateMgtException;

    /**
     * Delete a template by id.
     *
     * @param id     Template id.
     * @param tenantDomain Tenant domain.
     * @throws VCTemplateMgtException on deletion errors.
     */
    void delete(String id, String tenantDomain) throws VCTemplateMgtException;

    /**
     * Generate or regenerate a credential offer for a template.
     * Creates a new random UUID for offerId.
     * If an offer already exists, it will be regenerated with a new UUID.
     *
     * @param templateId The template ID.
     * @param tenantDomain Tenant domain.
     * @return Updated template with offerId.
     * @throws VCTemplateMgtException if template not found.
     */
    VCTemplate generateOffer(String templateId, String tenantDomain) throws VCTemplateMgtException;

    /**
     * Revoke/delete the credential offer for a template.
     * Sets offerId to null.
     * Returns 404 if no offer exists.
     *
     * @param templateId The template ID.
     * @param tenantDomain Tenant domain.
     * @return Updated template with offerId = null.
     * @throws VCTemplateMgtException if template or offer not found.
     */
    VCTemplate revokeOffer(String templateId, String tenantDomain) throws VCTemplateMgtException;
}

