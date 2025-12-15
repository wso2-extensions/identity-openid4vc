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

package org.wso2.carbon.identity.openid4vc.template.management.model;

import java.util.List;

/**
 * VC template search result with pagination support.
 */
public class VCTemplateSearchResult {

    private int totalCount;
    private List<VCTemplate> templates;

    /**
     * Get the total count of configurations.
     *
     * @return Total count.
     */
    public int getTotalCount() {

        return totalCount;
    }

    /**
     * Set the total count of configurations.
     *
     * @param totalCount Total count.
     */
    public void setTotalCount(int totalCount) {

        this.totalCount = totalCount;
    }

    /**
     * Get the list of VC templates.
     *
     * @return List of VC templates.
     */
    public List<VCTemplate> getTemplates() {
        return templates;
    }

    /**
     * Set the list of VC templates.
     *
     * @param templates List of VC templates.
     */
    public void setTemplates(List<VCTemplate> templates) {
        this.templates = templates;
    }
}
