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

package org.wso2.carbon.identity.openid4vc.template.management.cache;

import org.wso2.carbon.identity.core.cache.BaseCache;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * Cache for VC template by offer ID.
 */
public class VCTemplateCacheByOfferId extends BaseCache<VCTemplateOfferIdCacheKey, VCTemplateCacheEntry> {

    private static final String CACHE_NAME = "VCTemplateCacheByOfferId";

    private static final VCTemplateCacheByOfferId INSTANCE = new VCTemplateCacheByOfferId();

    private VCTemplateCacheByOfferId() {

        super(CACHE_NAME);
    }

    /**
     * Get VCTemplateCacheByOfferId instance.
     *
     * @return VCTemplateCacheByOfferId instance.
     */
    public static VCTemplateCacheByOfferId getInstance() {

        CarbonUtils.checkSecurity();
        return INSTANCE;
    }
}
