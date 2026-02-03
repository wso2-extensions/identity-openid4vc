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
 * Model class for DID Keys.
 */
public class DIDKey {

    private String keyId;
    private int tenantId;
    private String algorithm;
    private byte[] publicKey;
    private byte[] privateKey;
    private long createdAt;

    public DIDKey() {
    }

    public DIDKey(String keyId, int tenantId, String algorithm, byte[] publicKey, byte[] privateKey) {
        this.keyId = keyId;
        this.tenantId = tenantId;
        this.algorithm = algorithm;
        this.publicKey = publicKey != null ? publicKey.clone() : null;
        this.privateKey = privateKey != null ? privateKey.clone() : null;
        this.createdAt = System.currentTimeMillis();
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public int getTenantId() {
        return tenantId;
    }

    public void setTenantId(int tenantId) {
        this.tenantId = tenantId;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public byte[] getPublicKey() {
        return publicKey != null ? publicKey.clone() : null;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey != null ? publicKey.clone() : null;
    }

    public byte[] getPrivateKey() {
        return privateKey != null ? privateKey.clone() : null;
    }

    public void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey != null ? privateKey.clone() : null;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public String toString() {
        return "DIDKey{" +
                "keyId='" + keyId + '\'' +
                ", tenantId=" + tenantId +
                ", algorithm='" + algorithm + '\'' +
                ", createdAt=" + createdAt +
                '}';
    }
}
