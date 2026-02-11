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
     */
    public ApplicationPresentationDefinitionMapping(String applicationId,
                                                     String presentationDefinitionId,
                                                     int tenantId) {
        this.applicationId = applicationId;
        this.presentationDefinitionId = presentationDefinitionId;
        this.tenantId = tenantId;
    }

    private ApplicationPresentationDefinitionMapping(Builder builder) {
        this.applicationId = builder.applicationId;
        this.presentationDefinitionId = builder.presentationDefinitionId;
        this.tenantId = builder.tenantId;
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

    /**
     * Builder class for ApplicationPresentationDefinitionMapping.
     */
    public static class Builder {

        private String applicationId;
        private String presentationDefinitionId;
        private int tenantId;


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

        public ApplicationPresentationDefinitionMapping build() {
            return new ApplicationPresentationDefinitionMapping(this);
        }
    }
}
