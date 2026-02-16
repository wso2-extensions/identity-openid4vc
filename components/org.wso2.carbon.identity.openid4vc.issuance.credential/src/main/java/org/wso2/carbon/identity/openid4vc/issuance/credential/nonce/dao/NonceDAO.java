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

package org.wso2.carbon.identity.openid4vc.issuance.credential.nonce.dao;

import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;

import java.sql.Timestamp;

/**
 * Data access interface for nonce lifecycle management.
 */
public interface NonceDAO {

    /**
     * Persist a newly generated nonce.
     *
     * @param nonceValue The nonce value presented to the client.
     * @param tenantId   Tenant identifier.
     * @param expiryTime Absolute expiry timestamp.
     * @throws CredentialIssuanceException on persistence failure.
     */
    void storeNonce(String nonceValue, int tenantId, Timestamp expiryTime)
            throws CredentialIssuanceException;

    /**
     * Atomically validate and consume (single-use DELETE) a nonce.
     *
     * @param nonceValue The nonce value to validate.
     * @param tenantId   Tenant identifier.
     * @return {@code true} if the nonce existed, was not expired, and has been deleted; {@code false} otherwise.
     * @throws CredentialIssuanceException on database failure.
     */
    boolean validateAndConsumeNonce(String nonceValue, int tenantId)
            throws CredentialIssuanceException;

    /**
     * Delete all expired nonces. Intended for periodic cleanup jobs.
     *
     * @throws CredentialIssuanceException on database failure.
     */
    void deleteExpiredNonces() throws CredentialIssuanceException;
}
