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

import org.wso2.carbon.identity.core.model.ExpressionNode;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtException;
import org.wso2.carbon.identity.openid4vc.template.management.model.VCTemplate;

import java.util.List;

/**
 * DAO for VC Template persistence.
 */
public interface VCTemplateMgtDAO {

    /**
     * List all VC templates for a tenant.
     *
     * @param tenantId Tenant ID.
     * @return List of templates.
     * @throws VCTemplateMgtException on retrieval errors.
     */
    List<VCTemplate> list(int tenantId) throws VCTemplateMgtException;

    /**
     * List VC templates with pagination support.
     *
     * @param limit            Maximum number of templates to retrieve.
     * @param tenantId         Tenant ID.
     * @param sortOrder        Sort order (ASC or DESC).
     * @param expressionNodes  Filter expression nodes including after/before cursors.
     * @return List of templates.
     * @throws VCTemplateMgtException on retrieval errors.
     */
    List<VCTemplate> list(Integer limit, Integer tenantId, String sortOrder,
                          List<ExpressionNode> expressionNodes) throws VCTemplateMgtException;

    /**
     * Get the count of VC templates matching the filter.
     *
     * @param tenantId         Tenant ID.
     * @param expressionNodes  Filter expression nodes (excluding after/before cursors).
     * @return Total count of templates.
     * @throws VCTemplateMgtException on retrieval errors.
     */
    Integer getTemplatesCount(Integer tenantId, List<ExpressionNode> expressionNodes)
            throws VCTemplateMgtException;

    /**
     * Get a template by ID.
     *
     * @param id Unique template id.
     * @param tenantId Tenant ID.
     * @return Template or null if not found.
     * @throws VCTemplateMgtException on retrieval errors.
     */
    VCTemplate get(String id, int tenantId) throws VCTemplateMgtException;

    /**
     * Get a template by Identifier.
     *
     * @param identifier Identifier of the template.
     * @param tenantId Tenant ID.
     * @return Template or null if not found.
     * @throws VCTemplateMgtException on retrieval errors.
     */
    VCTemplate getByIdentifier(String identifier, int tenantId) throws VCTemplateMgtException;

    /**
     * Get a template by offer ID.
     *
     * @param offerId Offer ID of the template.
     * @param tenantId Tenant ID.
     * @return Template or null if not found.
     * @throws VCTemplateMgtException on retrieval errors.
     */
    VCTemplate getByOfferId(String offerId, int tenantId) throws VCTemplateMgtException;

    /**
     * Check existence by identifier.
     *
     * @param identifier Identifier.
     * @param tenantId   Tenant ID.
     * @return true if exists, false otherwise.
     * @throws VCTemplateMgtException on retrieval errors.
     */
    boolean existsByIdentifier(String identifier, int tenantId) throws VCTemplateMgtException;


    /**
     * Add a new template.
     *
     * @param template Template payload.
     * @param tenantId      Tenant ID.
     * @return Added template.
     * @throws VCTemplateMgtException on creation errors.
     */
    VCTemplate add(VCTemplate template, int tenantId) throws VCTemplateMgtException;

    /**
     * Update an existing template by id.
     * @param id     Template id to update.
     * @param template Updated payload.
     * @param tenantId     Tenant ID.
     * @return Updated template.
     * @throws VCTemplateMgtException on update errors.
     */
    VCTemplate update(String id, VCTemplate template, int tenantId) throws VCTemplateMgtException;

    /**
     * Delete a template by id.
     * @param id     Template id.
     * @param tenantId     Tenant ID.
     * @throws VCTemplateMgtException on deletion errors.
     */
    void delete(String id, int tenantId) throws VCTemplateMgtException;

    /**
     * Update only the offerId field of a template.
     * Used for offer generation, regeneration, and revocation.
     *
     * @param configId Template ID.
     * @param offerId New offer ID (null to revoke).
     * @param tenantId Tenant ID.
     * @throws VCTemplateMgtException on database errors.
     */
    void updateOfferId(String configId, String offerId, int tenantId) throws VCTemplateMgtException;
}
