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

package org.wso2.carbon.identity.openid4vc.presentation.model;

/**
 * Model class for Application Presentation Definition Mapping.
 */
public class ApplicationPresentationDefinitionMapping {

    private String applicationId;
    private String presentationDefinitionId;
    private int tenantId;
    private long createdAt;
    private Long updatedAt;

    /**
     * Default constructor.
     */
    public ApplicationPresentationDefinitionMapping() {
    }

    /**
     * Constructor with all fields.
     *
     * @param applicationId Application ID
     * @param presentationDefinitionId Presentation Definition ID
     * @param tenantId Tenant ID
     * @param createdAt Creation timestamp
     * @param updatedAt Last update timestamp
     */
    public ApplicationPresentationDefinitionMapping(String applicationId,
                                                     String presentationDefinitionId,
                                                     int tenantId,
                                                     long createdAt,
                                                     Long updatedAt) {
        this.applicationId = applicationId;
        this.presentationDefinitionId = presentationDefinitionId;
        this.tenantId = tenantId;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public String getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }

    public String getPresentationDefinitionId() {
        return presentationDefinitionId;
    }

    public void setPresentationDefinitionId(String presentationDefinitionId) {
        this.presentationDefinitionId = presentationDefinitionId;
    }

    public int getTenantId() {
        return tenantId;
    }

    public void setTenantId(int tenantId) {
        this.tenantId = tenantId;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    public Long getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Long updatedAt) {
        this.updatedAt = updatedAt;
    }

    /**
     * Builder class for ApplicationPresentationDefinitionMapping.
     */
    public static class Builder {

        private String applicationId;
        private String presentationDefinitionId;
        private int tenantId;
        private long createdAt;
        private Long updatedAt;

        public Builder applicationId(String applicationId) {
            this.applicationId = applicationId;
            return this;
        }

        public Builder presentationDefinitionId(String presentationDefinitionId) {
            this.presentationDefinitionId = presentationDefinitionId;
            return this;
        }

        public Builder tenantId(int tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public Builder createdAt(long createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        public Builder updatedAt(Long updatedAt) {
            this.updatedAt = updatedAt;
            return this;
        }

        public ApplicationPresentationDefinitionMapping build() {
            return new ApplicationPresentationDefinitionMapping(
                    applicationId,
                    presentationDefinitionId,
                    tenantId,
                    createdAt,
                    updatedAt
            );
        }
    }
}
