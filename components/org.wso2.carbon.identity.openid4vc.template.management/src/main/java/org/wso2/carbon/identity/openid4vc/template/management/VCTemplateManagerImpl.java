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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.api.resource.mgt.APIResourceMgtException;
import org.wso2.carbon.identity.application.common.model.APIResource;
import org.wso2.carbon.identity.application.common.model.Scope;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.core.model.ExpressionNode;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants;
import org.wso2.carbon.identity.openid4vc.template.management.dao.VCTemplateMgtDAO;
import org.wso2.carbon.identity.openid4vc.template.management.dao.impl.VCTemplateMgtDAOImpl;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtClientException;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtException;
import org.wso2.carbon.identity.openid4vc.template.management.internal.VCTemplateManagementServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.template.management.model.VCTemplate;
import org.wso2.carbon.identity.openid4vc.template.management.model.VCTemplateSearchResult;
import org.wso2.carbon.identity.openid4vc.template.management.util.VCTemplateFilterUtil;
import org.wso2.carbon.identity.openid4vc.template.management.util.VCTemplateMgtExceptionHandler;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.wso2.carbon.identity.api.resource.mgt.constant.APIResourceManagementConstants.APIResourceTypes.VC;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.DEFAULT_SIGNING_ALGORITHM;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_CLAIM_VALIDATION_ERROR;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_EMPTY_FIELD;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_IDENTIFIER_ALREADY_EXISTS;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_INVALID_CLAIM;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_INVALID_EXPIRY;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_INVALID_FIELD;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_OFFER_NOT_FOUND;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_TEMPLATE_ID_MISMATCH;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_TEMPLATE_NOT_FOUND;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_UNSUPPORTED_VC_FORMAT;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.VCTemplateManagementConstants.VC_DIALECT;

/**
 * Implementation of {@link VCTemplateManager}.
 */
public class VCTemplateManagerImpl implements VCTemplateManager {

    private static final Log LOG = LogFactory.getLog(VCTemplateManagerImpl.class);
    private static final VCTemplateManager INSTANCE = new VCTemplateManagerImpl();
    private final VCTemplateMgtDAO dao = new VCTemplateMgtDAOImpl();

    private VCTemplateManagerImpl() {

    }

    public static VCTemplateManager getInstance() {

        return INSTANCE;
    }

    @Override
    public List<VCTemplate> list(String tenantDomain) throws VCTemplateMgtException {

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Retrieving VC templates for tenant: %s", tenantDomain));
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        return dao.list(tenantId);
    }

    @Override
    public VCTemplateSearchResult listWithPagination(String after, String before, Integer limit,
                                                     String filter, String sortOrder, String tenantDomain)
            throws VCTemplateMgtException {

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Retrieving VC templates with pagination for tenant: %s",
                    tenantDomain));
        }
        VCTemplateSearchResult result = new VCTemplateSearchResult();
        List<ExpressionNode> expressionNodes = VCTemplateFilterUtil.getExpressionNodes(filter, after, before);
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        result.setTotalCount(dao.getTemplatesCount(tenantId, expressionNodes));
        result.setTemplates(dao.list(limit, tenantId, sortOrder, expressionNodes));
        return result;
    }

    @Override
    public VCTemplate get(String id, String tenantDomain) throws VCTemplateMgtException {

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Retrieving VC template with id: %s for tenant: %s", id,
                    tenantDomain));
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        return dao.get(id, tenantId);
    }

    @Override
    public VCTemplate getByIdentifier(String identifier, String tenantDomain)
            throws VCTemplateMgtException {

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Retrieving VC template with identifier: %s for tenant: %s",
                    identifier, tenantDomain));
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        return dao.getByIdentifier(identifier, tenantId);
    }

    @Override
    public VCTemplate getByOfferId(String offerId, String tenantDomain)
            throws VCTemplateMgtException {

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Retrieving VC template with offer ID: %s for tenant: %s",
                    offerId, tenantDomain));
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        return dao.getByOfferId(offerId, tenantId);
    }

    @Override
    public VCTemplate add(VCTemplate template, String tenantDomain)
            throws VCTemplateMgtException {

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Adding new VC template for tenant: %s", tenantDomain));
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        checkIdentifierExists(template, tenantId);
        validateDisplayName(template, tenantId);
        validateFormat(template);
        template.setSigningAlgorithm(DEFAULT_SIGNING_ALGORITHM);
        validateExpiry(template.getExpiresIn());
        validateClaims(template.getClaims(), tenantDomain);
        addVCResource(template, tenantDomain);
        try {
            return dao.add(template, tenantId);
        } catch (VCTemplateMgtException e) {
            if (VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_TRANSACTION_ERROR.getCode()
                    .equals(e.getErrorCode())) {
                // Rollback VC resource addition if DAO operation fails.
                deleteVCResource(template, tenantDomain);
            }
            throw e;
        }
    }

    @Override
    public VCTemplate update(String id, VCTemplate template,
                             String tenantDomain) throws VCTemplateMgtException {

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Updating VC template with id: %s for tenant: %s", id,
                    tenantDomain));
        }
        if (template.getId() != null && !StringUtils.equals(id, template.getId())) {
            throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_TEMPLATE_ID_MISMATCH);
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        // Validate identifier uniqueness if changed.
        VCTemplate existing = dao.get(id, tenantId);
        if (existing == null) {
            throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_TEMPLATE_NOT_FOUND);
        }

        if (!StringUtils.isBlank(template.getIdentifier())) {
            throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_INVALID_FIELD,
                    "Identifier cannot be updated");
        }

        // Preserve identifier from existing template.
        template.setIdentifier(existing.getIdentifier());
        template.setSigningAlgorithm(DEFAULT_SIGNING_ALGORITHM);
        validateDisplayName(template, tenantId);
        validateFormat(template);
        validateExpiry(template.getExpiresIn());
        validateClaims(template.getClaims(), tenantDomain);
        return dao.update(id, template, tenantId);
    }

    @Override
    public void delete(String id, String tenantDomain) throws VCTemplateMgtException {

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Deleting VC template with id: %s for tenant: %s", id,
                    tenantDomain));
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        VCTemplate template = dao.get(id, tenantId);
        deleteVCResource(template, tenantDomain);
        try {
            dao.delete(id, tenantId);
        } catch (VCTemplateMgtException e) {
            if (VCTemplateManagementConstants.ErrorMessages.ERROR_CODE_TRANSACTION_ERROR.getCode()
                    .equals(e.getErrorCode())) {
                // Rollback VC resource deletion if DAO operation fails.
                addVCResource(template, tenantDomain);
            }
            throw e;
        }
    }

    /**
     * Check if a template with the given identifier already exists.
     *
     * @param template VC template.
     * @param tenantId      Tenant ID.
     * @throws VCTemplateMgtException on validation errors.
     */
    private void checkIdentifierExists(VCTemplate template, int tenantId)
            throws VCTemplateMgtException {

        if (StringUtils.isBlank(template.getIdentifier())) {
            throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_EMPTY_FIELD, "Identifier");
        }
        if (dao.existsByIdentifier(template.getIdentifier(), tenantId)) {
            throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_IDENTIFIER_ALREADY_EXISTS);
        }
    }

    /**
     * Validate display name.
     *
     * @param template VC template.
     * @param tenantId      Tenant ID.
     * @throws VCTemplateMgtException on validation errors.
     */
    private void validateDisplayName(VCTemplate template, int tenantId)
            throws VCTemplateMgtException {

        if (StringUtils.isBlank(template.getDisplayName())) {
            throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_EMPTY_FIELD, "Display name");
        }
    }

    /**
     * Validate format.
     *
     * @param template VC template.
     * @throws VCTemplateMgtClientException on validation errors.
     */
    private void validateFormat(VCTemplate template) throws VCTemplateMgtClientException {

        if (StringUtils.isBlank(template.getFormat())) {
            template.setFormat(VCTemplateManagementConstants.DEFAULT_VC_FORMAT);
        } else {
            // Currently only default format is supported.
            if (!StringUtils.equals(template.getFormat(),
                    VCTemplateManagementConstants.DEFAULT_VC_FORMAT)) {
                throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_UNSUPPORTED_VC_FORMAT);
            }
        }
    }

    /**
     * Validate expiry.
     *
     * @param expiryInSeconds Expiry in seconds.
     * @throws VCTemplateMgtClientException on validation errors.
     */
    private void validateExpiry(Integer expiryInSeconds) throws VCTemplateMgtClientException {

        if (expiryInSeconds == null || expiryInSeconds < VCTemplateManagementConstants.MIN_EXPIRES_IN_SECONDS) {
            throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_INVALID_EXPIRY,
                    VCTemplateManagementConstants.MIN_EXPIRES_IN_SECONDS);
        }
    }

    /**
     * Add VC API resource for the given VC template.
     *
     * @param template VC template.
     * @param tenantDomain  Tenant domain.
     */
    private void addVCResource(VCTemplate template, String tenantDomain) {
        try {

            List<Scope> scopes = new ArrayList<>();
            Scope.ScopeBuilder scopeBuilder = new Scope.ScopeBuilder()
                    .name(template.getIdentifier())
                    .displayName(template.getIdentifier())
                    .description(template.getIdentifier());
            scopes.add(scopeBuilder.build());

            APIResource.APIResourceBuilder apiResourceBuilder = new APIResource.APIResourceBuilder()
                    .name(template.getIdentifier())
                    .identifier(template.getIdentifier())
                    .description(template.getIdentifier())
                    .scopes(scopes)
                    .requiresAuthorization(false)
                    .type(VC)
                    .authorizationDetailsTypes(new ArrayList<>());

            VCTemplateManagementServiceDataHolder.getInstance().getAPIResourceManager()
                    .addAPIResource(apiResourceBuilder.build(), tenantDomain);
        } catch (APIResourceMgtException e) {
            LOG.error("Error while adding VC API resource for VC template: " + template.getIdentifier() +
                    " in tenant: " + tenantDomain, e);
        }
    }

    /**
     * Delete VC API resource for the given VC template.
     *
     * @param template VC template.
     * @param tenantDomain  Tenant domain.
     */
    private void deleteVCResource(VCTemplate template, String tenantDomain) {
        try {

            APIResource apiResource = VCTemplateManagementServiceDataHolder.getInstance().getAPIResourceManager()
                    .getAPIResourceByIdentifier(template.getIdentifier(), tenantDomain);
            if (apiResource == null) {
                LOG.error("VC API resource for VC template: " + template.getIdentifier() +
                        " not found in tenant: " + tenantDomain);
                return;
            }
            VCTemplateManagementServiceDataHolder.getInstance().getAPIResourceManager()
                    .deleteAPIResourceById(apiResource.getId(), tenantDomain);
        } catch (APIResourceMgtException e) {
            LOG.error("Error while adding VC API resource for VC template: " + template.getIdentifier() +
                    " in tenant: " + tenantDomain, e);
        }
    }

    /**
     * Validate claims.
     *
     * @param claims       List of claim URIs.
     * @param tenantDomain Tenant domain.
     * @throws VCTemplateMgtException on validation errors.
     */
    private void validateClaims(List<String> claims, String tenantDomain) throws VCTemplateMgtException {

        if (claims != null && !claims.isEmpty()) {
            Set<ExternalClaim> vcClaims;
            try {
                vcClaims = ClaimMetadataHandler.getInstance()
                        .getMappingsFromOtherDialectToCarbon(VC_DIALECT, null, tenantDomain);
            } catch (ClaimMetadataException e) {
                throw VCTemplateMgtExceptionHandler.handleServerException(ERROR_CODE_CLAIM_VALIDATION_ERROR, e);
            }

            // Build a map for efficient claim lookup.
            List<String> vcClaimURIs = new ArrayList<>();
            for (ExternalClaim externalClaim : vcClaims) {
                vcClaimURIs.add(externalClaim.getClaimURI());
            }

            for (String claim : claims) {
                if (StringUtils.isBlank(claim) || !vcClaimURIs.contains(claim)) {
                    throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_INVALID_CLAIM, claim);
                }
            }
        }
    }

    @Override
    public VCTemplate generateOffer(String templateId, String tenantDomain)
            throws VCTemplateMgtException {

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Generating or regenerating credential offer for template: %s for tenant: %s",
                    templateId, tenantDomain));
        }

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        // Check if template exists.
        VCTemplate existing = dao.get(templateId, tenantId);
        if (existing == null) {
            throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_TEMPLATE_NOT_FOUND);
        }

        // Generate new offer ID (regardless of whether one exists - handles both generation and regeneration).
        String offerId = java.util.UUID.randomUUID().toString();
        dao.updateOfferId(templateId, offerId, tenantId);

        return dao.get(templateId, tenantId);
    }

    @Override
    public VCTemplate revokeOffer(String templateId, String tenantDomain)
            throws VCTemplateMgtException {

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Revoking credential offer for template: %s for tenant: %s",
                    templateId, tenantDomain));
        }

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        // Check if template exists.
        VCTemplate existing = dao.get(templateId, tenantId);
        if (existing == null) {
            throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_TEMPLATE_NOT_FOUND);
        }

        // Check if offer exists.
        if (existing.getOfferId() == null) {
            throw VCTemplateMgtExceptionHandler.handleClientException(ERROR_CODE_OFFER_NOT_FOUND);
        }

        // Revoke offer by setting offerId to null.
        dao.updateOfferId(templateId, null, tenantId);

        return dao.get(templateId, tenantId);
    }
}
