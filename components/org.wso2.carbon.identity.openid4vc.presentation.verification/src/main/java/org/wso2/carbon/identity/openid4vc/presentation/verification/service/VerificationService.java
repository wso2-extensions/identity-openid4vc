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

package org.wso2.carbon.identity.openid4vc.presentation.verification.service;

import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

/**
 * Service interface for Verifiable Credential verification.
 */
public interface VerificationService {

    /**
     * Verify a SD-JWT or JWT VC presentation with KB-JWT holder-binding validation.
     *
     * @param submission     The presentation_submission object
     * @param tenantId       The tenant identifier
     * @param vpToken        The VP token string
     * @param expectedNonce  The nonce sent in the VP request; used to verify the KB-JWT nonce claim.
     *                       Pass {@code null} to skip nonce validation (not recommended for production).
     * @return VerificationResult containing the verification outcome
     * @throws VerificationException If verification fails critically
     */
    VerificationResult verify(PresentationSubmission submission, int tenantId, String vpToken,
                              String expectedNonce)
            throws VerificationException;

    /**
     * Verify without a known nonce. Prefer the 4-arg overload whenever a nonce is available.
     */
    default VerificationResult verify(PresentationSubmission submission, int tenantId, String vpToken)
            throws VerificationException {

        return verify(submission, tenantId, vpToken, null);
    }
}
