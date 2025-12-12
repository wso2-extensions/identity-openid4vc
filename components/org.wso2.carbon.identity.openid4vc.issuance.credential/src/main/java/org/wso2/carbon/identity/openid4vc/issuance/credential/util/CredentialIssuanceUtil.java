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

package org.wso2.carbon.identity.openid4vc.issuance.credential.util;

import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;

import java.security.Key;

/**
 * Utility class for credential issuance related operations.
 */
public class CredentialIssuanceUtil {

    /**
     * Method to obtain the tenant's private key for OAuth2 protocol.
     * This could be the primary keystore private key, tenant keystore private key,
     * or a custom keystore private key.
     *
     * @param tenantDomain Tenant Domain as a String.
     * @return Private key for OAuth2 protocol in the tenant domain.
     * @throws CredentialIssuanceException When failed to obtain the private key for the requested tenant.
     */
    public static Key getPrivateKey(String tenantDomain) throws CredentialIssuanceException {
        try {
            return IdentityKeyStoreResolver.getInstance().getPrivateKey(
                    tenantDomain, IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH);
        } catch (IdentityKeyStoreResolverException e) {
            throw new CredentialIssuanceException("Error while obtaining private key", e);
        }
    }
}
