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

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.SignatureVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.vcmodel.SdJwt;
import org.wso2.carbon.identity.sdjwt.Disclosure;
import org.wso2.carbon.identity.sdjwt.SDJWT;
import org.wso2.carbon.identity.sdjwt.constant.SDJWTConstants;
import org.wso2.carbon.identity.sdjwt.exception.SDJWTException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Verifier for SD-JWT tokens.
 *
 * <p>In addition to verifying the issuer signature and selective disclosures, this verifier
 * enforces RFC 9901 §4.3 Key Binding JWT (KB-JWT) validation when a KB-JWT is present:
 * <ul>
 *   <li>Cryptographic signature verified against the holder key in the {@code cnf} claim.</li>
 *   <li>{@code nonce} verified against the expected nonce from the VP request.</li>
 *   <li>{@code iat} freshness verified (within 5-minute window).</li>
 *   <li>{@code sd_hash} verified against a fresh hash of the presentation string.</li>
 *   <li>{@code typ} header verified to be {@code kb+jwt}.</li>
 * </ul>
 */
public final class SdJwtVerifier implements Verifier {

    private static final Log LOG = LogFactory.getLog(SdJwtVerifier.class);

    private static final String KB_JWT_TYPE = "kb+jwt";
    private static final String CNF_JWK_CLAIM = "jwk";
    private static final String KB_JWT_SD_HASH_CLAIM = "sd_hash";
    private static final String KB_JWT_NONCE_CLAIM = "nonce";
    private static final long KB_JWT_IAT_TOLERANCE_MS = 5 * 60 * 1000L; // 5 minutes

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean canHandle(final String format) {

        return Constants.VC_SD_JWT_FORMAT.equals(format);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Processing steps:</p>
     * <ul>
     *   <li>Parse the SD-JWT container token.</li>
     *   <li>Parse and verify the issuer-signed JWT signature.</li>
     *   <li>Map token claims into an {@link SdJwt} model.</li>
     *   <li>Verify disclosures against {@code _sd} hashes and merge verified claims.</li>
     * </ul>
     */
    @Override
    public Map<String, Object> handle(final PresentationSubmission submission,
                                      final int tenantId, final String vpToken)
            throws VerificationException {

        return handle(submission, tenantId, vpToken, null, null);
    }

    /**
     * {@inheritDoc}
     *
     * <p>When {@code trustedIssuerKey} is non-null, the issuer-signed JWT signature is verified
     * directly against that key (cert-based trust), skipping DID/JWKS discovery.</p>
     */
    @Override
    public Map<String, Object> handle(final PresentationSubmission submission,
                                      final int tenantId, final String vpToken,
                                      final PublicKey trustedIssuerKey)
            throws VerificationException {

        return handle(submission, tenantId, vpToken, trustedIssuerKey, null);
    }

    /**
     * {@inheritDoc}
     *
     * <p>When {@code expectedNonce} is non-null, the KB-JWT is required and its {@code nonce}
     * claim is verified against {@code expectedNonce}. The KB-JWT signature, {@code iat},
     * and {@code sd_hash} are always verified when a KB-JWT is present, regardless of nonce.</p>
     */
    @Override
    public Map<String, Object> handle(final PresentationSubmission submission,
                                      final int tenantId, final String vpToken,
                                      final PublicKey trustedIssuerKey,
                                      final String expectedNonce)
            throws VerificationException {

        try {
            SDJWT sdJwt;
            try {
                sdJwt = SDJWT.parse(vpToken);
            } catch (SDJWTException e) {
                throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                        "Failed to parse SD-JWT VP: " + e.getMessage(), e);
            }

            SignedJWT parsedVp;
            try {
                parsedVp = SignedJWT.parse(sdJwt.getIssuerSignedJwt());
            } catch (ParseException e) {
                throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                        "Failed to parse issuer-signed JWT: " + e.getMessage(), e);
            }

            // Verify the issuer signature (cert-pinned or JWKS/x5c discovery).
            if (trustedIssuerKey != null) {
                String alg = parsedVp.getHeader().getAlgorithm().getName();
                boolean signatureValid = SignatureVerifier.verifyJwtSignature(
                        sdJwt.getIssuerSignedJwt(), trustedIssuerKey, alg);
                if (!signatureValid) {
                    throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                            "Signature verification failed for SD-JWT VP against trusted issuer certificate.");
                }
                SdJwt payload = mapToSdJwt(parsedVp);
                SignatureVerifier.verifyExpiration(payload);
                Map<String, Object> claims = getClaims(payload);
                if (sdJwt.getDisclosureCount() > 0) {
                    verifyDisclosures(payload, sdJwt.getDisclosures(), claims);
                }
                verifyKeyBinding(sdJwt, payload, vpToken, expectedNonce);
                return claims;
            }

            boolean signatureValid = SignatureVerifier.verifySignature(parsedVp);
            if (!signatureValid) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                        "Signature verification failed for SD-JWT VP");
            }

            SdJwt payload = mapToSdJwt(parsedVp);
            Map<String, Object> claims = getClaims(payload);
            if (sdJwt.getDisclosureCount() > 0) {
                verifyDisclosures(payload, sdJwt.getDisclosures(), claims);
            }
            verifyKeyBinding(sdJwt, payload, vpToken, expectedNonce);
            return claims;

        } catch (ParseException e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to extract claims from SD-JWT VP: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies the KB-JWT (RFC 9901 §4.3) when present in the SD-JWT.
     *
     * <p>Checks performed:
     * <ol>
     *   <li>{@code typ} header must be {@code kb+jwt}.</li>
     *   <li>Signature verified against the holder public key from {@code cnf.jwk} in the issuer JWT.</li>
     *   <li>{@code iat} must be within a 5-minute window of the current time.</li>
     *   <li>{@code sd_hash} must match the hash of the presentation string.</li>
     *   <li>{@code nonce} must match {@code expectedNonce} when {@code expectedNonce} is non-null.</li>
     * </ol>
     *
     * <p>If the credential contains a {@code cnf} claim but no KB-JWT was presented, a warning is
     * logged. The presentation is not rejected so that wallets without KB-JWT support can still
     * interoperate; however, this means holder binding is not verified.
     *
     * @param sdJwt          The parsed SD-JWT container
     * @param payload        The mapped issuer-signed JWT payload (provides {@code cnf})
     * @param vpToken        The raw VP token string (needed to compute {@code sd_hash})
     * @param expectedNonce  The nonce from the VP request; {@code null} to skip nonce check
     */
    private void verifyKeyBinding(SDJWT sdJwt, SdJwt payload, String vpToken, String expectedNonce)
            throws VerificationException {

        if (!sdJwt.hasKeyBinding()) {
            if (payload.getCnf() != null) {
                LOG.warn("Credential has cnf claim but no KB-JWT was presented; " +
                        "holder binding cannot be verified.");
            }
            return;
        }

        String kbJwtStr = sdJwt.getKeyBindingJwt();

        SignedJWT kbJwt;
        try {
            kbJwt = SignedJWT.parse(kbJwtStr);
        } catch (ParseException e) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                    "Failed to parse KB-JWT: " + e.getMessage(), e);
        }

        // 1. typ must be kb+jwt.
        if (kbJwt.getHeader().getType() == null
                || !KB_JWT_TYPE.equals(kbJwt.getHeader().getType().getType())) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT typ header must be '" + KB_JWT_TYPE + "'.");
        }

        // 2. Resolve holder public key from cnf.jwk in the issuer-signed JWT.
        if (payload.getCnf() == null) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "KB-JWT is present but issuer-signed JWT has no cnf claim.");
        }
        PublicKey holderPublicKey = resolveHolderPublicKey(payload.getCnf());

        // 3. Verify KB-JWT signature.
        String kbAlg = kbJwt.getHeader().getAlgorithm().getName();
        boolean kbSigValid;
        try {
            kbSigValid = SignatureVerifier.verifyJwtSignature(kbJwtStr, holderPublicKey, kbAlg);
        } catch (VerificationException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT signature verification failed: " + e.getMessage(), e);
        }
        if (!kbSigValid) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT signature is invalid.");
        }

        JWTClaimsSet kbClaims;
        try {
            kbClaims = kbJwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                    "Failed to parse KB-JWT claims: " + e.getMessage(), e);
        }

        // 4. Verify iat freshness.
        Date iat = kbClaims.getIssueTime();
        if (iat == null) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT is missing iat claim.");
        }
        if (Math.abs(System.currentTimeMillis() - iat.getTime()) > KB_JWT_IAT_TOLERANCE_MS) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT iat is outside the accepted 5-minute window.");
        }

        // 5. Verify sd_hash.
        verifyKbSdHash(sdJwt, payload, vpToken, kbClaims);

        // 6. Verify nonce.
        if (StringUtils.isNotBlank(expectedNonce)) {
            String kbNonce;
            try {
                kbNonce = kbClaims.getStringClaim(KB_JWT_NONCE_CLAIM);
            } catch (ParseException e) {
                throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                        "Failed to read nonce from KB-JWT: " + e.getMessage(), e);
            }
            if (StringUtils.isBlank(kbNonce)) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                        "KB-JWT is missing nonce claim.");
            }
            if (!expectedNonce.equals(kbNonce)) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                        "KB-JWT nonce does not match the expected nonce from the VP request.");
            }
        }
    }

    /**
     * Verifies the {@code sd_hash} claim in the KB-JWT against a fresh hash of the
     * presentation string (RFC 9901 §5.4).
     *
     * <p>The presentation string is the serialized SD-JWT without the KB-JWT:
     * {@code <issuer-jwt>~<disc1>~...~<discN>~}
     */
    private void verifyKbSdHash(SDJWT sdJwt, SdJwt payload, String vpToken,
                                 JWTClaimsSet kbClaims) throws VerificationException {

        String claimedSdHash;
        try {
            claimedSdHash = kbClaims.getStringClaim(KB_JWT_SD_HASH_CLAIM);
        } catch (ParseException e) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                    "Failed to read sd_hash from KB-JWT: " + e.getMessage(), e);
        }
        if (StringUtils.isBlank(claimedSdHash)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT is missing sd_hash claim.");
        }

        // Build the presentation string: issuer-jwt~disc1~...~discN~
        SDJWT presentationWithoutKb = new SDJWT(sdJwt.getIssuerSignedJwt(), sdJwt.getDisclosures());
        String presentationString = presentationWithoutKb.serialize();

        String jcaAlg = mapSdAlgToJca(payload.getSdAlg());
        byte[] hashBytes;
        try {
            hashBytes = MessageDigest.getInstance(jcaAlg)
                    .digest(presentationString.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Hash algorithm not available: " + jcaAlg, e);
        }

        String computedSdHash = Base64URL.encode(hashBytes).toString();
        if (!computedSdHash.equals(claimedSdHash)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT sd_hash does not match the hash of the presented SD-JWT.");
        }
    }

    /**
     * Resolves the holder {@link PublicKey} from the {@code cnf} claim of the issuer-signed JWT.
     * Only {@code cnf.jwk} (JWK object) is supported; other binding methods ({@code x5t#S256},
     * {@code kid}) are not yet implemented.
     */
    @SuppressWarnings("unchecked")
    private PublicKey resolveHolderPublicKey(Map<String, Object> cnf) throws VerificationException {

        Object jwkObj = cnf.get(CNF_JWK_CLAIM);
        if (!(jwkObj instanceof Map)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "Unsupported cnf format: only cnf.jwk is currently supported.");
        }
        JWK holderJwk;
        try {
            holderJwk = JWK.parse((Map<String, Object>) jwkObj);
        } catch (Exception e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "Failed to parse holder JWK from cnf claim: " + e.getMessage(), e);
        }
        if (holderJwk.isPrivate()) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "cnf.jwk must not contain private key material.");
        }
        try {
            String keyType = holderJwk.getKeyType().getValue();
            switch (keyType) {
                case "EC":
                    return ((ECKey) holderJwk).toECPublicKey();
                case "RSA":
                    return ((RSAKey) holderJwk).toRSAPublicKey();
                default:
                    throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                            "Unsupported holder key type in cnf.jwk: " + keyType);
            }
        } catch (VerificationClientException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "Failed to extract holder public key from cnf.jwk: " + e.getMessage(), e);
        }
    }

    /**
     * Maps a hash algorithm identifier from the SD-JWT {@code _sd_alg} claim to a JCA algorithm name.
     */
    private static String mapSdAlgToJca(String sdAlg) {

        if (sdAlg == null) {
            return "SHA-256";
        }
        switch (sdAlg.toLowerCase()) {
            case "sha-256": return "SHA-256";
            case "sha-384": return "SHA-384";
            case "sha-512": return "SHA-512";
            default:        return "SHA-256";
        }
    }

    /**
     * Extracts normalized claims from a mapped {@link SdJwt} payload.
     */
    private Map<String, Object> getClaims(final SdJwt payload) {

        Map<String, Object> claims = new HashMap<>(payload.getAdditionalClaims());
        claims.put(Constants.CLAIM_ISS, payload.getIss());
        claims.put(Constants.CLAIM_SUB, payload.getSub());
        claims.put(Constants.CLAIM_IAT, payload.getIat());
        claims.put(Constants.CLAIM_EXP, payload.getExp());
        if (payload.getCnf() != null) {
            claims.put(SDJWTConstants.CLAIM_CNF, payload.getCnf());
        }
        return claims;
    }

    /**
     * Verifies disclosures against the {@code _sd} hash list and merges matching
     * claim values into the provided claim map.
     */
    private void verifyDisclosures(final SdJwt payload,
                                   final List<Disclosure> disclosures,
                                   final Map<String, Object> claims)
            throws VerificationException {

        List<String> sdHashes = payload.getSd();
        if (sdHashes == null || sdHashes.isEmpty()) {
            return;
        }
        String sdAlg = payload.getSdAlg();
        try {
            for (Disclosure disclosure : disclosures) {
                String calculatedHash = disclosure.digest(sdAlg);
                if (sdHashes.contains(calculatedHash)) {
                    if (!disclosure.isArrayElement()) {
                        claims.put(disclosure.getClaimName(), disclosure.getClaimValue());
                    }
                }
            }
        } catch (SDJWTException e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Error verifying SD-JWT disclosures: " + e.getMessage(), e);
        }
    }

    /**
     * Maps a parsed issuer-signed {@link SignedJWT} to an {@link SdJwt} model.
     */
    private SdJwt mapToSdJwt(final SignedJWT jwt) throws ParseException {

        SdJwt payload = new SdJwt();
        JwtVerifier.populateJwtModel(payload, jwt);

        Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();

        if (claims.containsKey(SDJWTConstants.CLAIM_SD_ALG)) {
            payload.setSdAlg(claims.get(SDJWTConstants.CLAIM_SD_ALG).toString());
        }
        if (claims.containsKey(SDJWTConstants.CLAIM_SD)
                && claims.get(SDJWTConstants.CLAIM_SD) instanceof List) {
            payload.setSd((List<String>) claims.get(SDJWTConstants.CLAIM_SD));
        }

        Map<String, Object> additional = payload.getAdditionalClaims();
        additional.remove(SDJWTConstants.CLAIM_SD);
        additional.remove(SDJWTConstants.CLAIM_SD_ALG);

        return payload;
    }
}
