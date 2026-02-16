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

package org.wso2.carbon.identity.openid4vc.issuance.credential.nonce;

import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.nonce.dao.NonceDAO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.nonce.dao.impl.NonceDAOImpl;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.Base64;

import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.DEFAULT_NONCE_TTL_SECONDS;

/**
 * Service for c_nonce lifecycle management.
 *
 * <p>Nonces are 32-byte cryptographically random values, Base64url-encoded without padding.
 * They are stored in the shared identity database so all cluster nodes can validate them.</p>
 */
public class NonceService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final NonceDAO nonceDAO;

    public NonceService() {

        this.nonceDAO = new NonceDAOImpl();
    }

    public String generateNonce(String tenantDomain) throws CredentialIssuanceException {

        byte[] nonceBytes = new byte[32];
        SECURE_RANDOM.nextBytes(nonceBytes);
        String nonceValue = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        long expiryMillis = System.currentTimeMillis() + (DEFAULT_NONCE_TTL_SECONDS * 1000L);
        nonceDAO.storeNonce(nonceValue, tenantId, new Timestamp(expiryMillis));
        return nonceValue;
    }

    public boolean validateAndConsumeNonce(String nonce, String tenantDomain) throws CredentialIssuanceException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        return nonceDAO.validateAndConsumeNonce(nonce, tenantId);
    }
}
