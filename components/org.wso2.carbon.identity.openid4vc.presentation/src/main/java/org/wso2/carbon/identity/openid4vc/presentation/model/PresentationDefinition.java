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

import java.io.Serializable;

/**
 * Model class representing a Presentation Definition.
 * This defines the credential requirements for a Verifiable Presentation request.
 */
public class PresentationDefinition implements Serializable {

    private static final long serialVersionUID = 1L;

    private String definitionId;
    private String resourceId;
    private String name;
    private String description;
    private String definitionJson;
    private int tenantId;

    /**
     * Default constructor.
     */
    public PresentationDefinition() {
    }

    /**
     * Builder pattern constructor.
     */
    private PresentationDefinition(Builder builder) {
        this.definitionId = builder.definitionId;
        this.resourceId = builder.resourceId;
        this.name = builder.name;
        this.description = builder.description;
        this.definitionJson = builder.definitionJson;
        this.tenantId = builder.tenantId;
    }

    // Getters and Setters

    public String getDefinitionId() {
        return definitionId;
    }

    public void setDefinitionId(String definitionId) {
        this.definitionId = definitionId;
    }

    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDefinitionJson() {
        return definitionJson;
    }

    public void setDefinitionJson(String definitionJson) {
        this.definitionJson = definitionJson;
    }

    public int getTenantId() {
        return tenantId;
    }

    public void setTenantId(int tenantId) {
        this.tenantId = tenantId;
    }

    /**
     * Builder class for PresentationDefinition.
     */
    public static class Builder {
        private String definitionId;
        private String resourceId;
        private String name;
        private String description;
        private String definitionJson;
        private int tenantId;

        public Builder definitionId(String definitionId) {
            this.definitionId = definitionId;
            return this;
        }

        public Builder resourceId(String resourceId) {
            this.resourceId = resourceId;
            return this;
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder definitionJson(String definitionJson) {
            this.definitionJson = definitionJson;
            return this;
        }

        public Builder tenantId(int tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public PresentationDefinition build() {
            return new PresentationDefinition(this);
        }
    }

    @Override
    public String toString() {
        return "PresentationDefinition{" +
                "definitionId='" + definitionId + '\'' +
                ", resourceId='" + resourceId + '\'' +
                ", name='" + name + '\'' +
                ", tenantId=" + tenantId +
                '}';
    }
}
