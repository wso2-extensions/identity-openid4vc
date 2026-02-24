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

package org.wso2.carbon.identity.openid4vc.oid4vp.verification.service;

import org.wso2.carbon.identity.openid4vc.presentation.common.dto.VCVerificationResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.CredentialVerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.common.model.VerifiableCredential;
import org.wso2.carbon.identity.openid4vc.presentation.common.model.VerifiablePresentation;

import java.util.List;

/**
 * Service interface for Verifiable Credential (VC) verification.
 * Provides methods to verify individual credentials and verifiable presentations.
 * 
 * Supports multiple credential formats:
 * - JSON-LD Verifiable Credentials (ldp_vc)
 * - JWT Verifiable Credentials (jwt_vc, jwt_vc_json)
 * - SD-JWT Verifiable Credentials (vc+sd-jwt)
 */
public interface VCVerificationService {

    /**
     * Verify a single Verifiable Credential.
     * Performs all applicable verification checks including:
     * - Cryptographic signature verification
     * - Expiration checking
     * - Revocation status checking (if credential has credentialStatus)
     *
     * @param vcString    The VC as a string (JSON-LD object or JWT string)
     * @param contentType Content type indicating the format:
     *                    - application/vc+ld+json for JSON-LD
     *                    - application/jwt or application/vc+jwt for JWT
     *                    - application/vc+sd-jwt for SD-JWT
     * @return VCVerificationResultDTO with verification result
     * @throws CredentialVerificationException If verification fails critically
     */
    VCVerificationResultDTO verify(String vcString, String contentType) 
            throws CredentialVerificationException;

    /**
     * Verify a Verifiable Credential with a specific index.
     *
     * @param vcString    The VC string
     * @param contentType The content type
     * @param vcIndex     Index of the credential in a presentation
     * @return VCVerificationResultDTO with verification result
     * @throws CredentialVerificationException If verification fails critically
     */
    VCVerificationResultDTO verify(String vcString, String contentType, int vcIndex)
            throws CredentialVerificationException;

    /**
     * Verify a parsed Verifiable Credential object.
     *
     * @param credential The parsed VerifiableCredential
     * @return VCVerificationResultDTO with verification result
     * @throws CredentialVerificationException If verification fails critically
     */
    VCVerificationResultDTO verifyCredential(VerifiableCredential credential)
            throws CredentialVerificationException;

    /**
     * Verify a VP token and all contained credentials.
     * Parses the VP token, extracts all verifiable credentials,
     * and verifies each one.
     *
     * @param vpToken The VP token (JWT or JSON-LD string)
     * @return List of VCVerificationResultDTO for each credential
     * @throws CredentialVerificationException If VP parsing fails
     */
    List<VCVerificationResultDTO> verifyVPToken(String vpToken)
            throws CredentialVerificationException;

    /**
     * Verify a parsed Verifiable Presentation.
     *
     * @param presentation The parsed VerifiablePresentation
     * @return List of VCVerificationResultDTO for each credential
     * @throws CredentialVerificationException If verification fails critically
     */
    List<VCVerificationResultDTO> verifyPresentation(VerifiablePresentation presentation)
            throws CredentialVerificationException;

    /**
     * Verify only the cryptographic signature of a credential.
     *
     * @param credential The credential to verify
     * @return true if signature is valid
     * @throws CredentialVerificationException If verification fails
     */
    boolean verifySignature(VerifiableCredential credential)
            throws CredentialVerificationException;

    /**
     * Check if a credential has expired.
     *
     * @param credential The credential to check
     * @return true if credential has expired
     */
    boolean isExpired(VerifiableCredential credential);

    /**
     * Check if a credential has been revoked.
     * Requires the credential to have a credentialStatus field.
     *
     * @param credential The credential to check
     * @return true if credential is revoked
     * @throws CredentialVerificationException If revocation check fails
     */
    boolean isRevoked(VerifiableCredential credential)
            throws CredentialVerificationException;

    /**
     * Parse a VC string into a VerifiableCredential object.
     *
     * @param vcString    The VC string
     * @param contentType The content type
     * @return Parsed VerifiableCredential
     * @throws CredentialVerificationException If parsing fails
     */
    VerifiableCredential parseCredential(String vcString, String contentType)
            throws CredentialVerificationException;

    /**
     * Parse a VP token into a VerifiablePresentation object.
     *
     * @param vpToken The VP token string
     * @return Parsed VerifiablePresentation
     * @throws CredentialVerificationException If parsing fails
     */
    VerifiablePresentation parsePresentation(String vpToken)
            throws CredentialVerificationException;

    /**
     * Verify nonce in the VP token matches expected nonce.
     *
     * @param vpToken       The VP token
     * @param expectedNonce The expected nonce value
     * @return true if nonce matches
     * @throws CredentialVerificationException If nonce verification fails
     */
    boolean verifyNonce(String vpToken, String expectedNonce)
            throws CredentialVerificationException;

    /**
     * Check if a content type is supported for verification.
     *
     * @param contentType The content type to check
     * @return true if supported
     */
    boolean isContentTypeSupported(String contentType);

    /**
     * Get the list of supported content types.
     *
     * @return Array of supported content types
     */
    String[] getSupportedContentTypes();

    /**
     * Verify JWT VC issuer against trusted allowlist.
     * Performs DID resolution and signature verification.
     * 
     * @param vcJwt The JWT VC token
     * @param tenantDomain The tenant domain
     * @return true if issuer is trusted and signature is valid
     * @throws CredentialVerificationException if verification fails
     */
    boolean verifyJWTVCIssuer(String vcJwt, String tenantDomain) 
            throws CredentialVerificationException;

    /**
     * Verify JSON-LD VC issuer against trusted allowlist.
     * Performs DID resolution and signature verification.
     * 
     * @param vcJsonObject The JSON-LD VC as JsonObject
     * @param tenantDomain The tenant domain
     * @return true if issuer is trusted and signature is valid
     * @throws CredentialVerificationException if verification fails
     */
    boolean verifyJSONLDVCIssuer(com.google.gson.JsonObject vcJsonObject, String tenantDomain) 
            throws CredentialVerificationException;
    /**
     * Verify SD-JWT Token with Key Binding and Disclosure verification.
     *
     * @param vpToken                   The VP token string (SD-JWT format)
     * @param expectedNonce             The nonce value expected in the KB-JWT
     * @param expectedAudience          The audience value expected in the KB-JWT
     * @param presentationDefinitionJson The JSON string of the Presentation Definition for constraint checking
     * @return A Map of verified user attributes/claims
     * @throws CredentialVerificationException If verification fails
     */
    java.util.Map<String, Object> verifySdJwtToken(String vpToken, 
                                                String expectedNonce, 
                                                String expectedAudience, 
                                                String presentationDefinitionJson) 
            throws CredentialVerificationException;

    /**
     * Verify claims against a Presentation Definition's input descriptors.
     *
     * @param claims                    The map of verified claims
     * @param presentationDefinitionJson The JSON string of the Presentation Definition
     * @throws CredentialVerificationException If constraints are not satisfied
     */
    void verifyClaimsAgainstDefinition(java.util.Map<String, Object> claims, String presentationDefinitionJson)
            throws CredentialVerificationException;
}
