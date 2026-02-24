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

package org.wso2.carbon.identity.openid4vc.template.management.dao.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.model.ExpressionNode;
import org.wso2.carbon.identity.openid4vc.template.management.cache.VCTemplateCacheById;
import org.wso2.carbon.identity.openid4vc.template.management.cache.VCTemplateCacheByIdentifier;
import org.wso2.carbon.identity.openid4vc.template.management.cache.VCTemplateCacheByOfferId;
import org.wso2.carbon.identity.openid4vc.template.management.cache.VCTemplateCacheEntry;
import org.wso2.carbon.identity.openid4vc.template.management.cache.VCTemplateIdCacheKey;
import org.wso2.carbon.identity.openid4vc.template.management.cache.VCTemplateIdentifierCacheKey;
import org.wso2.carbon.identity.openid4vc.template.management.cache.VCTemplateOfferIdCacheKey;
import org.wso2.carbon.identity.openid4vc.template.management.dao.VCTemplateMgtDAO;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtException;
import org.wso2.carbon.identity.openid4vc.template.management.model.VCTemplate;

import java.util.List;

/**
 * Cache-backed implementation of {@link VCTemplateMgtDAO}.
 * Wraps an underlying DAO and adds caching for single-template lookups.
 */
public class CacheBackedVCTemplateMgtDAO implements VCTemplateMgtDAO {

    private static final Log LOG = LogFactory.getLog(CacheBackedVCTemplateMgtDAO.class);
    private final VCTemplateMgtDAO vcTemplateMgtDAO;
    private final VCTemplateCacheById vcTemplateCacheById;
    private final VCTemplateCacheByIdentifier vcTemplateCacheByIdentifier;
    private final VCTemplateCacheByOfferId vcTemplateCacheByOfferId;

    public CacheBackedVCTemplateMgtDAO(VCTemplateMgtDAO vcTemplateMgtDAO) {

        this.vcTemplateMgtDAO = vcTemplateMgtDAO;
        vcTemplateCacheById = VCTemplateCacheById.getInstance();
        vcTemplateCacheByIdentifier = VCTemplateCacheByIdentifier.getInstance();
        vcTemplateCacheByOfferId = VCTemplateCacheByOfferId.getInstance();
    }

    @Override
    public List<VCTemplate> list(int tenantId) throws VCTemplateMgtException {

        return vcTemplateMgtDAO.list(tenantId);
    }

    @Override
    public List<VCTemplate> list(Integer limit, Integer tenantId, String sortOrder,
                                 List<ExpressionNode> expressionNodes) throws VCTemplateMgtException {

        return vcTemplateMgtDAO.list(limit, tenantId, sortOrder, expressionNodes);
    }

    @Override
    public Integer getTemplatesCount(Integer tenantId, List<ExpressionNode> expressionNodes)
            throws VCTemplateMgtException {

        return vcTemplateMgtDAO.getTemplatesCount(tenantId, expressionNodes);
    }

    @Override
    public VCTemplate get(String id, int tenantId) throws VCTemplateMgtException {

        VCTemplateIdCacheKey cacheKey = new VCTemplateIdCacheKey(id);
        VCTemplateCacheEntry entry = vcTemplateCacheById.getValueFromCache(cacheKey, tenantId);

        if (entry != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Cache entry found for VC template " + id);
            }
            return entry.getVCTemplate();
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Cache entry not found for VC template " + id + ". Fetching entry from DB");
        }

        VCTemplate vcTemplate = vcTemplateMgtDAO.get(id, tenantId);

        if (vcTemplate != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Entry fetched from DB for VC template " + id + ". Updating cache");
            }
            addToAllCaches(vcTemplate, tenantId);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Entry for VC template " + id + " not found in cache or DB");
            }
        }

        return vcTemplate;
    }

    @Override
    public VCTemplate getByIdentifier(String identifier, int tenantId) throws VCTemplateMgtException {

        VCTemplateIdentifierCacheKey cacheKey = new VCTemplateIdentifierCacheKey(identifier);
        VCTemplateCacheEntry entry = vcTemplateCacheByIdentifier.getValueFromCache(cacheKey, tenantId);

        if (entry != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Cache entry found for VC template identifier " + identifier);
            }
            return entry.getVCTemplate();
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Cache entry not found for VC template identifier " + identifier +
                    ". Fetching entry from DB");
        }

        VCTemplate vcTemplate = vcTemplateMgtDAO.getByIdentifier(identifier, tenantId);

        if (vcTemplate != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Entry fetched from DB for VC template identifier " + identifier + ". Updating cache");
            }
            addToAllCaches(vcTemplate, tenantId);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Entry for VC template identifier " + identifier + " not found in cache or DB");
            }
        }

        return vcTemplate;
    }

    @Override
    public VCTemplate getByOfferId(String offerId, int tenantId) throws VCTemplateMgtException {

        VCTemplateOfferIdCacheKey cacheKey = new VCTemplateOfferIdCacheKey(offerId);
        VCTemplateCacheEntry entry = vcTemplateCacheByOfferId.getValueFromCache(cacheKey, tenantId);

        if (entry != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Cache entry found for VC template offer ID " + offerId);
            }
            return entry.getVCTemplate();
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Cache entry not found for VC template offer ID " + offerId +
                    ". Fetching entry from DB");
        }

        VCTemplate vcTemplate = vcTemplateMgtDAO.getByOfferId(offerId, tenantId);

        if (vcTemplate != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Entry fetched from DB for VC template offer ID " + offerId + ". Updating cache");
            }
            addToAllCaches(vcTemplate, tenantId);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Entry for VC template offer ID " + offerId + " not found in cache or DB");
            }
        }

        return vcTemplate;
    }

    @Override
    public boolean existsByIdentifier(String identifier, int tenantId) throws VCTemplateMgtException {

        VCTemplateIdentifierCacheKey cacheKey = new VCTemplateIdentifierCacheKey(identifier);
        VCTemplateCacheEntry entry = vcTemplateCacheByIdentifier.getValueFromCache(cacheKey, tenantId);
        if (entry != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Cache entry found for VC template identifier " + identifier);
            }
            return true;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Cache entry not found for VC template identifier " + identifier +
                    ". Fetching entry from DB");
        }
        return vcTemplateMgtDAO.existsByIdentifier(identifier, tenantId);
    }

    @Override
    public VCTemplate add(VCTemplate template, int tenantId) throws VCTemplateMgtException {

        return vcTemplateMgtDAO.add(template, tenantId);
    }

    @Override
    public VCTemplate update(String id, VCTemplate template, int tenantId) throws VCTemplateMgtException {

        clearVCTemplateCache(id, null, null, tenantId);
        return vcTemplateMgtDAO.update(id, template, tenantId);
    }

    @Override
    public void delete(String id, int tenantId) throws VCTemplateMgtException {

        clearVCTemplateCache(id, null, null, tenantId);
        vcTemplateMgtDAO.delete(id, tenantId);
    }

    @Override
    public void updateOfferId(String configId, String offerId, int tenantId) throws VCTemplateMgtException {

        clearVCTemplateCache(configId, null, null, tenantId);
        vcTemplateMgtDAO.updateOfferId(configId, offerId, tenantId);
    }

    /**
     * Add a VC template to all caches.
     *
     * @param vcTemplate VC template.
     * @param tenantId   Tenant ID.
     */
    private void addToAllCaches(VCTemplate vcTemplate, int tenantId) {

        VCTemplateCacheEntry cacheEntry = new VCTemplateCacheEntry(vcTemplate);

        if (vcTemplate.getId() != null) {
            vcTemplateCacheById.addToCache(new VCTemplateIdCacheKey(vcTemplate.getId()), cacheEntry, tenantId);
        }
        if (vcTemplate.getIdentifier() != null) {
            vcTemplateCacheByIdentifier.addToCache(new VCTemplateIdentifierCacheKey(vcTemplate.getIdentifier()),
                    cacheEntry, tenantId);
        }
        if (vcTemplate.getOfferId() != null) {
            vcTemplateCacheByOfferId.addToCache(new VCTemplateOfferIdCacheKey(vcTemplate.getOfferId()),
                    cacheEntry, tenantId);
        }
    }

    /**
     * Clear all cache entries related to a VC template.
     *
     * @param id         Template ID (may be null).
     * @param identifier Template identifier (may be null).
     * @param offerId    Offer ID (may be null).
     * @param tenantId   Tenant ID.
     * @throws VCTemplateMgtException on errors.
     */
    private void clearVCTemplateCache(String id, String identifier, String offerId, int tenantId)
            throws VCTemplateMgtException {

        VCTemplate vcTemplate = null;
        if (StringUtils.isNotBlank(id)) {
            vcTemplate = this.get(id, tenantId);
        }
        if (vcTemplate == null && StringUtils.isNotBlank(identifier)) {
            vcTemplate = this.getByIdentifier(identifier, tenantId);
        }
        if (vcTemplate == null && StringUtils.isNotBlank(offerId)) {
            vcTemplate = this.getByOfferId(offerId, tenantId);
        }

        if (vcTemplate != null) {
            id = id != null ? id : vcTemplate.getId();
            identifier = identifier != null ? identifier : vcTemplate.getIdentifier();
            offerId = offerId != null ? offerId : vcTemplate.getOfferId();

            if (LOG.isDebugEnabled()) {
                LOG.debug("Removing cache entries for VC template " + id + " of tenantId:" + tenantId);
            }

            if (id != null) {
                vcTemplateCacheById.clearCacheEntry(new VCTemplateIdCacheKey(id), tenantId);
            }
            if (identifier != null) {
                vcTemplateCacheByIdentifier.clearCacheEntry(
                        new VCTemplateIdentifierCacheKey(identifier), tenantId);
            }
            if (offerId != null) {
                vcTemplateCacheByOfferId.clearCacheEntry(new VCTemplateOfferIdCacheKey(offerId), tenantId);
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Entry for VC template not found in cache or DB for cache invalidation");
            }
        }
    }
}
