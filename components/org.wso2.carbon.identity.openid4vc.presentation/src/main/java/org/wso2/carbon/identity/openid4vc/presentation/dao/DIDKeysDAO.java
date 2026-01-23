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

package org.wso2.carbon.identity.openid4vc.presentation.dao;

import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.DIDKey;

/**
 * Data Access Object interface for DID Keys operations.
 */
public interface DIDKeysDAO {

    /**
     * Add a new DID key.
     *
     * @param didKey DID key to add
     * @throws VPException if addition fails
     */
    void addDIDKey(DIDKey didKey) throws VPException;

    /**
     * Get a DID key by its ID.
     *
     * @param keyId    Key ID (e.g., the specific part of the DID or alias)
     * @param tenantId Tenant ID
     * @return DIDKey object or null if not found
     * @throws VPException if retrieval fails
     */
    DIDKey getDIDKey(String keyId, int tenantId) throws VPException;

    /**
     * Delete a DID key.
     *
     * @param keyId    Key ID
     * @param tenantId Tenant ID
     * @throws VPException if deletion fails
     */
    void deleteDIDKey(String keyId, int tenantId) throws VPException;

    /**
     * Get the latest DID key for a tenant.
     *
     * @param tenantId Tenant ID
     * @return DIDKey object or null if not found
     * @throws VPException if retrieval fails
     */
    DIDKey getDIDKeyByTenant(int tenantId) throws VPException;

    /**
     * Check if a DID key exists.
     *
     * @param keyId    Key ID
     * @param tenantId Tenant ID
     * @return true if exists, false otherwise
     * @throws VPException if check fails
     */
    boolean isDIDKeyExists(String keyId, int tenantId) throws VPException;
}
