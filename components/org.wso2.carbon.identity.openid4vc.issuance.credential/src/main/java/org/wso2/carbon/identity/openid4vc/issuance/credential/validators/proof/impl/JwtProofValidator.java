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

package org.wso2.carbon.identity.openid4vc.issuance.credential.validators.proof.impl;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.issuance.common.util.CommonUtil;
import org.wso2.carbon.identity.openid4vc.issuance.credential.dto.ProofDTO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceClientException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.nonce.NonceService;
import org.wso2.carbon.identity.openid4vc.issuance.credential.validators.proof.ProofValidator;

import java.util.List;

import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.JWT_PROOF;
import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.JWT_PROOF_TYPE;
import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.MAX_CLOCK_SKEW_SECONDS;
import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.SUPPORTED_JWT_PROOF_SIGNING_ALGORITHMS;
import static org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceErrorCode.INVALID_NONCE;
import static org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceErrorCode.INVALID_PROOF;

/**
 * Proof validator for JWT-based proofs.
 */
public class JwtProofValidator implements ProofValidator {

    private static final Log LOG = LogFactory.getLog(JwtProofValidator.class);
    private static final int MAX_AUDIENCE_SIZE = 10;
    private final NonceService nonceService = new NonceService();

    @Override
    public String getType() {

        return JWT_PROOF;
    }

    @Override
    public void validateProof(ProofDTO proofDTO, String tenantDomain) throws CredentialIssuanceException {

        List<String> proofs = proofDTO.getProofs();
        if (proofs == null || proofs.isEmpty()) {
            throw new CredentialIssuanceException("JWT proof is required");
        }

        // Enforce single proof for single credential issuance
        if (proofs.size() > 1) {
            throw new CredentialIssuanceException("Multiple proofs not supported");
        }

        validateJwtProof(proofDTO, tenantDomain);
    }

    private void validateJwtProof(ProofDTO proofDTO, String tenantDomain)
            throws CredentialIssuanceException {

        String jwtString = proofDTO.getProofs().get(0);
        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(jwtString);
        } catch (Exception e) {
            throw new CredentialIssuanceException("Invalid JWT proof format", e);
        }

        // Validate header
        validateHeader(signedJWT);

        // Extract public key from header
        JWK publicKey = extractPublicKey(signedJWT);

        // Verify signature
        verifySignature(signedJWT, publicKey);

        // Validate claims
        validateClaims(signedJWT, tenantDomain, proofDTO);

        proofDTO.setPublicKey(publicKey.toPublicJWK().toJSONObject());

        try {
            if (signedJWT.getJWTClaimsSet().getIssueTime() != null) {
                proofDTO.setIssuedAt(
                        signedJWT.getJWTClaimsSet().getIssueTime().getTime());
            }
            Object nonce = signedJWT.getJWTClaimsSet().getClaim("nonce");
            if (nonce != null) {
                proofDTO.setNonce(nonce.toString());
            }
        } catch (Exception e) {
            LOG.warn("Error extracting claims from proof JWT", e);
        }
    }

    private void validateHeader(SignedJWT signedJWT)
            throws CredentialIssuanceException {

        // Check typ header
        if (signedJWT.getHeader().getType() == null) {
            throw new CredentialIssuanceClientException(INVALID_PROOF, "Missing typ header in proof JWT");
        }

        String typ = signedJWT.getHeader().getType().toString();
        if (!JWT_PROOF_TYPE.equals(typ)) {
            throw new CredentialIssuanceClientException(INVALID_PROOF,
                    "Invalid typ header. Expected: " + JWT_PROOF_TYPE + ", got: " + typ);
        }

        // Check algorithm is in the allowed asymmetric algorithm set
        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (!SUPPORTED_JWT_PROOF_SIGNING_ALGORITHMS.contains(alg)) {
            throw new CredentialIssuanceClientException(INVALID_PROOF,
                    "Unsupported proof signing algorithm: " + alg +
                    ". Allowed: " + SUPPORTED_JWT_PROOF_SIGNING_ALGORITHMS);
        }
    }

    private JWK extractPublicKey(SignedJWT signedJWT)
            throws CredentialIssuanceException {

        try {
            JWK jwk = signedJWT.getHeader().getJWK();
            if (jwk == null) {
                throw new CredentialIssuanceClientException(INVALID_PROOF,
                        "Public key (jwk) must be present in proof header");
            }
            // Security: Ensure JWK does not contain private key material
            if (jwk.isPrivate()) {
                throw new CredentialIssuanceClientException(INVALID_PROOF,
                        "JWK must not contain private key material");
            }
            return jwk;
        } catch (CredentialIssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialIssuanceClientException(INVALID_PROOF,
                    "Failed to extract public key");
        }
    }

    private void verifySignature(SignedJWT signedJWT, JWK publicKey)
            throws CredentialIssuanceException {

        try {
            JWSVerifier verifier;
            String keyType = publicKey.getKeyType().getValue();
            String algorithm = signedJWT.getHeader().getAlgorithm().getName();

            if ("EC".equals(keyType)) {
                // Verify EC key is used with ES* algorithms only
                if (!algorithm.startsWith("ES")) {
                    throw new CredentialIssuanceClientException(INVALID_PROOF,
                            "Algorithm mismatch: EC key cannot be used with " + algorithm + " algorithm");
                }
                ECKey ecKey = ECKey.parse(publicKey.toJSONObject());
                verifier = new ECDSAVerifier(ecKey);
            } else if ("RSA".equals(keyType)) {
                // Verify RSA key is used with RS* or PS* algorithms only
                if (!algorithm.startsWith("RS") && !algorithm.startsWith("PS")) {
                    throw new CredentialIssuanceClientException(INVALID_PROOF,
                            "Algorithm mismatch: RSA key cannot be used with " + algorithm + " algorithm");
                }
                RSAKey rsaKey = RSAKey.parse(publicKey.toJSONObject());
                verifier = new RSASSAVerifier(rsaKey);
            } else {
                throw new CredentialIssuanceClientException(INVALID_PROOF,
                        "Unsupported key type: " + keyType);
            }

            if (!signedJWT.verify(verifier)) {
                throw new CredentialIssuanceClientException(INVALID_PROOF,
                        "Proof signature verification failed");
            }
        } catch (CredentialIssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialIssuanceException("Signature verification failed", e);
        }
    }

    private void validateClaims(SignedJWT signedJWT, String tenantDomain, ProofDTO proofDTO)
            throws CredentialIssuanceException {

        try {
            // Validate iss - MUST be present and match client_id per OID4VCI spec
            String issuer = signedJWT.getJWTClaimsSet().getIssuer();
            String expectedClientId = proofDTO.getClientId();
            if (expectedClientId != null) {
                if (issuer == null) {
                    throw new CredentialIssuanceClientException(INVALID_PROOF,
                            "Missing iss claim. Required when client_id is present.");
                }
                if (!issuer.equals(expectedClientId)) {
                    throw new CredentialIssuanceClientException(INVALID_PROOF,
                            "Invalid iss claim. Must match client_id.");
                }
            }

            // Validate aud
            List<String> audience = signedJWT.getJWTClaimsSet().getAudience();
            if (audience == null || audience.isEmpty()) {
                throw new CredentialIssuanceClientException(INVALID_PROOF, "Missing aud claim in proof");
            }
            if (audience.size() > MAX_AUDIENCE_SIZE) {
                throw new CredentialIssuanceClientException(INVALID_PROOF,
                        "Audience list exceeds maximum allowed size");
            }

            String credentialIssuerUrl = CommonUtil.buildCredentialIssuerUrl(tenantDomain);
            if (!audience.contains(credentialIssuerUrl)) {
                throw new CredentialIssuanceClientException(INVALID_PROOF,
                        "Invalid aud claim in proof. Expected to contain: " + credentialIssuerUrl);
            }

            // Validate iat
            if (signedJWT.getJWTClaimsSet().getIssueTime() == null) {
                throw new CredentialIssuanceClientException(INVALID_PROOF, "Missing iat claim in proof");
            }

            long iat = signedJWT.getJWTClaimsSet().getIssueTime().getTime() / 1000;
            long now = System.currentTimeMillis() / 1000;
            if (Math.abs(now - iat) > MAX_CLOCK_SKEW_SECONDS) {
                throw new CredentialIssuanceClientException(INVALID_PROOF,
                        "Proof is too old or from the future");
            }

            // Validate nonce — MUST be present and valid when the issuer operates a Nonce Endpoint (draft 16).
            Object nonceObj = signedJWT.getJWTClaimsSet().getClaim("nonce");
            if (nonceObj == null) {
                throw new CredentialIssuanceClientException(INVALID_PROOF,
                        "Missing nonce claim in proof JWT. A nonce from the Nonce Endpoint is required.");
            }
            if (!nonceService.validateAndConsumeNonce(nonceObj.toString(), tenantDomain)) {
                throw new CredentialIssuanceClientException(INVALID_NONCE,
                        "Invalid or expired nonce");
            }

        } catch (CredentialIssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialIssuanceException("Claim validation failed", e);
        }
    }

}
