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
    private final NonceService nonceService = new NonceService();

    @Override
    public String getType() {

        return JWT_PROOF;
    }

    @Override
    public void validateProof(ProofDTO proofDTO, String tenantDomain) throws CredentialIssuanceException {

        List<String> proofs = proofDTO.getProofs();
        if (proofs.isEmpty()) {
            throw new CredentialIssuanceException("JWT proof is required");
        }

        // Enforce single proof for single credential issuance
        if (proofs.size() > 1) {
            throw new CredentialIssuanceException(
                    "Multiple proofs not supported");
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
        validateClaims(signedJWT, tenantDomain);

        proofDTO.setPublicKey(publicKey.toJSONObject());

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
            throw new CredentialIssuanceException("Missing typ header in proof JWT");
        }

        String typ = signedJWT.getHeader().getType().toString();
        if (!JWT_PROOF_TYPE.equals(typ)) {
            throw new CredentialIssuanceException(
                    "Invalid typ header. Expected: " + JWT_PROOF_TYPE + ", got: " + typ);
        }

        // Check algorithm is in the allowed asymmetric algorithm set
        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (!SUPPORTED_JWT_PROOF_SIGNING_ALGORITHMS.contains(alg)) {
            throw new CredentialIssuanceException(
                    "Unsupported proof signing algorithm: " + alg +
                    ". Allowed: " + SUPPORTED_JWT_PROOF_SIGNING_ALGORITHMS);
        }
    }

    private JWK extractPublicKey(SignedJWT signedJWT)
            throws CredentialIssuanceException {

        try {
            JWK jwk = signedJWT.getHeader().getJWK();
            if (jwk == null) {
                throw new CredentialIssuanceException(
                        "Public key (jwk) must be present in proof header");
            }
            return jwk;
        } catch (CredentialIssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialIssuanceException("Failed to extract public key", e);
        }
    }

    private void verifySignature(SignedJWT signedJWT, JWK publicKey)
            throws CredentialIssuanceException {

        try {
            JWSVerifier verifier;
            String keyType = publicKey.getKeyType().getValue();

            if ("EC".equals(keyType)) {
                ECKey ecKey = ECKey.parse(publicKey.toJSONObject());
                verifier = new ECDSAVerifier(ecKey);
            } else if ("RSA".equals(keyType)) {
                RSAKey rsaKey = RSAKey.parse(publicKey.toJSONObject());
                verifier = new RSASSAVerifier(rsaKey);
            } else {
                throw new CredentialIssuanceException(
                        "Unsupported key type: " + keyType);
            }

            if (!signedJWT.verify(verifier)) {
                throw new CredentialIssuanceException(
                        "Proof signature verification failed");
            }
        } catch (CredentialIssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialIssuanceException("Signature verification failed", e);
        }
    }

    private void validateClaims(SignedJWT signedJWT, String tenantDomain) throws CredentialIssuanceException {

        try {
            // Validate aud
            List<String> audience = signedJWT.getJWTClaimsSet().getAudience();
            if (audience == null || audience.isEmpty()) {
                throw new CredentialIssuanceException("Missing aud claim in proof");
            }

            String aud = audience.get(0);
            String issuer = CommonUtil.buildCredentialIssuerUrl(tenantDomain);
            if (!issuer.equals(aud)) {
                throw new CredentialIssuanceException(
                        "Invalid aud claim. Expected: " + issuer + ", got: " + aud);
            }

            // TODO : validate the aud to issuer

            // Validate iat
            if (signedJWT.getJWTClaimsSet().getIssueTime() == null) {
                throw new CredentialIssuanceException("Missing iat claim in proof");
            }

            long iat = signedJWT.getJWTClaimsSet().getIssueTime().getTime() / 1000;
            long now = System.currentTimeMillis() / 1000;
            if (Math.abs(now - iat) > MAX_CLOCK_SKEW_SECONDS) {
                throw new CredentialIssuanceException(
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
