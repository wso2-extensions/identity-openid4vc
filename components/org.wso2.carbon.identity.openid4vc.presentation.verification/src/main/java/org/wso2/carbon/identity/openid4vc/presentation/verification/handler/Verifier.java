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

package org.wso2.carbon.identity.openid4vc.presentation.verification.handler;

import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

import java.security.PublicKey;
import java.util.Map;

/**
 * Interface for format-specific token verifiers.
 */
public interface Verifier {

    /**
         * Determines whether this verifier supports the given presentation format.
         *
         * @param format The format value from {@code descriptor_map[*].format}
         * @return {@code true} if this verifier can process the format; otherwise {@code false}
     */
    boolean canHandle(String format);

    /**
         * Verifies the supplied VP token using a format-specific strategy.
         *
         * @param submission The {@link PresentationSubmission} metadata for the token
         * @param tenantId The tenant identifier used for tenant-scoped resolution
         * @param vpToken The raw verifiable presentation token
         * @return A map of verified claims extracted from the presentation
         * @throws VerificationException If verification fails due to client or server conditions
     */
    Map<String, Object> handle(PresentationSubmission submission, int tenantId, String vpToken)
            throws VerificationException;

    /**
     * Verifies the VP token using a statically configured trusted issuer public key
     * extracted from a PEM certificate, bypassing live DID/JWKS discovery.
     * Implementations that do not override this method fall back to the standard
     * {@link #handle(PresentationSubmission, int, String)} path.
     *
     * @param submission      The {@link PresentationSubmission} metadata for the token
     * @param tenantId        The tenant identifier used for tenant-scoped resolution
     * @param vpToken         The raw verifiable presentation token
     * @param trustedIssuerKey The public key extracted from the configured issuer certificate,
     *                         or {@code null} to use DID/JWKS discovery
     * @return A map of verified claims extracted from the presentation
     * @throws VerificationException If verification fails due to client or server conditions
     */
    default Map<String, Object> handle(PresentationSubmission submission, int tenantId,
                                       String vpToken, PublicKey trustedIssuerKey)
            throws VerificationException {

        return handle(submission, tenantId, vpToken);
    }

    /**
     * Verifies the VP token with full holder-binding validation (KB-JWT nonce check).
     * Implementations that do not override this method fall back to
     * {@link #handle(PresentationSubmission, int, String, PublicKey)}.
     *
     * @param submission       The {@link PresentationSubmission} metadata for the token
     * @param tenantId         The tenant identifier used for tenant-scoped resolution
     * @param vpToken          The raw verifiable presentation token
     * @param trustedIssuerKey The issuer public key (cert-pinned), or {@code null} for JWKS discovery
     * @param expectedNonce    The nonce sent in the VP request, used to verify the KB-JWT; may be {@code null}
     * @return A map of verified claims extracted from the presentation
     * @throws VerificationException If verification fails due to client or server conditions
     */
    default Map<String, Object> handle(PresentationSubmission submission, int tenantId,
                                       String vpToken, PublicKey trustedIssuerKey,
                                       String expectedNonce)
            throws VerificationException {

        return handle(submission, tenantId, vpToken, trustedIssuerKey);
    }
}
