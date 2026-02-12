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
 * Model class representing a Verifiable Presentation Request.
 * This corresponds to an OpenID4VP authorization request.
 */
public class VPRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private String requestId;
    private String transactionId;
    private String clientId;
    private String nonce;
    private String presentationDefinitionId;
    private String presentationDefinition;
    private String responseUri;
    private String responseMode;
    private String requestJwt;
    private VPRequestStatus status;
    private long expiresAt;
    private int tenantId;
    private String didMethod;
    private String signingAlgorithm;

    private VPRequest(Builder builder) {
        this.requestId = builder.requestId;
        this.transactionId = builder.transactionId;
        this.clientId = builder.clientId;
        this.nonce = builder.nonce;
        this.presentationDefinitionId = builder.presentationDefinitionId;
        this.presentationDefinition = builder.presentationDefinition;
        this.responseUri = builder.responseUri;
        this.responseMode = builder.responseMode;
        this.requestJwt = builder.requestJwt;
        this.status = builder.status;
        this.expiresAt = builder.expiresAt;
        this.tenantId = builder.tenantId;
        this.didMethod = builder.didMethod;
        this.signingAlgorithm = builder.signingAlgorithm;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getPresentationDefinitionId() {
        return presentationDefinitionId;
    }

    public void setPresentationDefinitionId(String presentationDefinitionId) {
        this.presentationDefinitionId = presentationDefinitionId;
    }

    public String getPresentationDefinition() {
        return presentationDefinition;
    }

    public void setPresentationDefinition(String presentationDefinition) {
        this.presentationDefinition = presentationDefinition;
    }

    public String getResponseUri() {
        return responseUri;
    }

    public void setResponseUri(String responseUri) {
        this.responseUri = responseUri;
    }

    public String getResponseMode() {
        return responseMode;
    }

    public void setResponseMode(String responseMode) {
        this.responseMode = responseMode;
    }

    public String getRequestJwt() {
        return requestJwt;
    }

    public void setRequestJwt(String requestJwt) {
        this.requestJwt = requestJwt;
    }

    public VPRequestStatus getStatus() {
        return status;
    }

    public void setStatus(VPRequestStatus status) {
        this.status = status;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(long expiresAt) {
        this.expiresAt = expiresAt;
    }

    public int getTenantId() {
        return tenantId;
    }

    public void setTenantId(int tenantId) {
        this.tenantId = tenantId;
    }

    public String getDidMethod() {
        return didMethod;
    }

    public void setDidMethod(String didMethod) {
        this.didMethod = didMethod;
    }

    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    public void setSigningAlgorithm(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }

    @Override
    public String toString() {
        return "VPRequest{" +
                "requestId='" + requestId + '\'' +
                ", transactionId='" + transactionId + '\'' +
                ", clientId='" + clientId + '\'' +
                ", status=" + status +
                ", expiresAt=" + expiresAt +
                ", tenantId=" + tenantId +
                ", didMethod='" + didMethod + '\'' +
                ", signingAlgorithm='" + signingAlgorithm + '\'' +
                '}';
    }

    /**
     * Builder class for VPRequest.
     */
    public static class Builder {
        private String requestId;
        private String transactionId;
        private String clientId;
        private String nonce;
        private String presentationDefinitionId;
        private String presentationDefinition;
        private String responseUri;
        private String responseMode;
        private String requestJwt;
        private VPRequestStatus status;
        private long expiresAt;
        private int tenantId;
        private String didMethod;
        private String signingAlgorithm;

        public Builder requestId(String requestId) {
            this.requestId = requestId;
            return this;
        }

        public Builder transactionId(String transactionId) {
            this.transactionId = transactionId;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public Builder presentationDefinitionId(String presentationDefinitionId) {
            this.presentationDefinitionId = presentationDefinitionId;
            return this;
        }

        public Builder presentationDefinition(String presentationDefinition) {
            this.presentationDefinition = presentationDefinition;
            return this;
        }

        public Builder responseUri(String responseUri) {
            this.responseUri = responseUri;
            return this;
        }

        public Builder responseMode(String responseMode) {
            this.responseMode = responseMode;
            return this;
        }

        public Builder requestJwt(String requestJwt) {
            this.requestJwt = requestJwt;
            return this;
        }

        public Builder status(VPRequestStatus status) {
            this.status = status;
            return this;
        }

        public Builder expiresAt(long expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        public Builder tenantId(int tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public Builder didMethod(String didMethod) {
            this.didMethod = didMethod;
            return this;
        }

        public Builder signingAlgorithm(String signingAlgorithm) {
            this.signingAlgorithm = signingAlgorithm;
            return this;
        }

        public VPRequest build() {
            return new VPRequest(this);
        }
    }
}
