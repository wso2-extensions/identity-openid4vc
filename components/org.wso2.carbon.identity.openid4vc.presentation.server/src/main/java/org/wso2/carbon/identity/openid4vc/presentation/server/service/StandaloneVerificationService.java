/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.server.service;

import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.StandaloneVerificationInitiation;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.StandaloneVerificationSession;

/**
 * OSGi service for standalone (API-initiated) VP verification sessions.
 * Allows external applications to trigger VP verification without a WSO2 login flow.
 */
public interface StandaloneVerificationService {

    /**
     * Initiate a new standalone verification session.
     *
     * @param presentationDefinitionId ID of the presentation definition to request.
     * @param tenantDomain             Tenant domain for the request.
     * @return Initiation result containing txnId, walletUrl, requestUri, and expiresAt.
     * @throws VPAuthenticatorException on configuration or definition lookup failure.
     */
    StandaloneVerificationInitiation initiate(String presentationDefinitionId, String tenantDomain)
            throws VPAuthenticatorException;

    /**
     * Generate the request JWT for a standalone session (served via request_uri).
     *
     * @param txnId Transaction ID of the standalone session.
     * @return Signed request JWT string.
     * @throws VPAuthenticatorException if the session is not found or JWT building fails.
     */
    String generateRequestJwt(String txnId) throws VPAuthenticatorException;

    /**
     * Look up a standalone session by transaction ID.
     * Returns null if not found or expired.
     *
     * @param txnId Transaction ID.
     * @return Session, or null.
     */
    StandaloneVerificationSession getSession(String txnId);
}
