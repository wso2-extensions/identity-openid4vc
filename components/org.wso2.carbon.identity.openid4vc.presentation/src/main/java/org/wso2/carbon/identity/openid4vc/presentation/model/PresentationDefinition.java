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

    private int id;
    private String definitionId;
    private String name;
    private String description;
    private String definitionJson;
    private boolean isDefault;
    private long createdAt;
    private Long updatedAt;
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
        this.id = builder.id;
        this.definitionId = builder.definitionId;
        this.name = builder.name;
        this.description = builder.description;
        this.definitionJson = builder.definitionJson;
        this.isDefault = builder.isDefault;
        this.createdAt = builder.createdAt;
        this.updatedAt = builder.updatedAt;
        this.tenantId = builder.tenantId;
    }

    // Getters and Setters

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getDefinitionId() {
        return definitionId;
    }

    public void setDefinitionId(String definitionId) {
        this.definitionId = definitionId;
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

    public boolean isDefault() {
        return isDefault;
    }

    public void setDefault(boolean isDefault) {
        this.isDefault = isDefault;
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
        private int id;
        private String definitionId;
        private String name;
        private String description;
        private String definitionJson;
        private boolean isDefault;
        private long createdAt;
        private Long updatedAt;
        private int tenantId;

        public Builder id(int id) {
            this.id = id;
            return this;
        }

        public Builder definitionId(String definitionId) {
            this.definitionId = definitionId;
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

        public Builder isDefault(boolean isDefault) {
            this.isDefault = isDefault;
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
                "id=" + id +
                ", definitionId='" + definitionId + '\'' +
                ", name='" + name + '\'' +
                ", isDefault=" + isDefault +
                ", tenantId=" + tenantId +
                '}';
    }
}
