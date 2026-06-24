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

package org.wso2.carbon.identity.openid4vc.presentation.verification.service.impl;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.common.config.OpenID4VPConfigMgtException;
import org.wso2.carbon.identity.openid4vc.presentation.common.config.OpenID4VPConfigService;
import org.wso2.carbon.identity.openid4vc.presentation.common.config.OpenID4VPTenantConfig;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition.ClaimConstraint;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition.RequestedCredential;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationMetadata;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.handler.JwtVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.handler.SdJwtVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.handler.Verifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.SignatureVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.StatusListChecker;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.StatusListChecker.RevocationStatus;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationConstants;
import org.wso2.carbon.identity.sdjwt.SDJWT;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.PublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Implementation of the {@link VerificationService} for OpenID4VC presentations.
 */
@Component(
        name = "openid4vc.presentation.verification.service",
        immediate = true,
        service = VerificationService.class
)
public class VerificationServiceImpl implements VerificationService {

    private static final Log LOG = LogFactory.getLog(VerificationServiceImpl.class);

    private PresentationDefinitionService presentationDefinitionService;
    private OpenID4VPConfigService openID4VPConfigService;
    private final List<Verifier> verifiers;

    public VerificationServiceImpl() {

        this.verifiers = initVerifiers();
    }

    private List<Verifier> initVerifiers() {

        List<Verifier> verifierList = new java.util.ArrayList<>();
        verifierList.add(new JwtVerifier());
        verifierList.add(new SdJwtVerifier());
        return verifierList;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Verification flow:</p>
     * <ol>
     *   <li>Validate request shape and supported format.</li>
     *   <li>Load the Presentation Definition for the tenant.</li>
     *   <li><strong>Policy gate (before crypto):</strong> if {@code enforceTrustedIssuers} is
     *       enabled, parse the raw {@code iss} claim from the unverified token and reject
     *       immediately if it is not in the trusted-issuers list.  This avoids performing
     *       expensive cryptographic work for untrusted issuers.</li>
     *   <li>Resolve the signing key: use the per-credential {@code issuerCertPem} if configured,
     *       otherwise fall back to live JWKS/x5c discovery.</li>
     *   <li>Verify the VP token cryptographically (signature, disclosures, KB-JWT).</li>
     *   <li>Enforce required-claim constraints against the verified claim set.</li>
     * </ol>
     */
    @Override
    public VerificationResult verify(PresentationSubmission submission, int tenantId, String vpToken,
                                     String expectedNonce)
            throws VerificationException {

        VerificationResult.Builder resultBuilder = new VerificationResult.Builder();

        try {
            validateRequest(submission, vpToken);

            if (tenantId == MultitenantConstants.INVALID_TENANT_ID) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_VP_SUBMISSION,
                        "Invalid tenant ID provided.");
            }

            String format = submission.getDescriptorMap().get(0).getFormat();
            Verifier verifier = verifiers.stream()
                    .filter(v -> v.canHandle(format))
                    .findFirst()
                    .orElseThrow(() -> new VerificationClientException(VerificationErrorCode.INVALID_VP_FORMAT,
                            "No verifier found for format: " + format));

            if (presentationDefinitionService == null) {
                throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                        "Presentation definition service is not available");
            }

            PresentationDefinition definition;
            try {
                definition = presentationDefinitionService.getPresentationDefinitionById(
                        submission.getDefinitionId(), tenantId);
                if (definition == null) {
                    throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                            "Presentation definition not found for ID: " + submission.getDefinitionId());
                }
            } catch (VerificationException e) {
                throw e;
            } catch (Exception e) {
                throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                        "Error fetching presentation definition: " + e.getMessage(), e);
            }

            // Get the credential entry that governs this verification.
            // (Single-VC support only; multi-VC will be added later.)
            RequestedCredential req = getMatchingCredential(definition);

            // ── STEP 1: Policy gate – check iss BEFORE crypto ────────────────────
            // Parse the iss claim from the raw (unverified) token and reject early
            // if the issuer is not in the trusted list.  An attacker cannot bypass
            // the subsequent signature check by spoofing iss, so this early rejection
            // is safe and avoids unnecessary cryptographic work.
            if (req != null && req.isEnforceTrustedIssuers()) {
                String rawIss = parseIssFromRawToken(vpToken, format);
                enforceTrustedIssuer(rawIss, req.getTrustedIssuers());
            }

            // ── STEP 2: Resolve signing key ──────────────────────────────────────
            // Use the issuer cert that is pinned to this specific credential entry.
            // If no cert is configured the verifier falls back to live JWKS/x5c discovery.
            PublicKey trustedIssuerKey = resolveKeyFromCredential(req);

            // ── STEP 3: Cryptographic verification ──────────────────────────────
            Map<String, Object> verifiedClaims = verifier.handle(
                    submission, tenantId, vpToken, trustedIssuerKey, expectedNonce);

            // ── STEP 3.5: Revocation check via OAuth Status List ────────────────
            checkRevocationStatus(verifiedClaims, tenantId);

            // ── STEP 4: Enforce required claims ─────────────────────────────────
            Map<String, Object> finalClaims = verifyRequiredClaims(verifiedClaims, definition);

            PresentationMetadata metadata = extractMetadata(vpToken, format, finalClaims);

            resultBuilder.isVerified(true)
                         .verifiedClaims(finalClaims)
                         .metadata(metadata)
                         .statusMessage("Verification successful");
            return resultBuilder.build();

        } catch (VerificationClientException e) {
            return resultBuilder.isVerified(false)
                                .addError(e.getMessage())
                                .statusMessage("Verification failed")
                                .build();
        }
    }

    /**
     * Returns the first {@link RequestedCredential} from the definition, or {@code null}
     * when none are configured.  Single-VC support only; multi-VC matching will be added later.
     */
    private RequestedCredential getMatchingCredential(PresentationDefinition definition) {

        if (definition == null
                || definition.getRequestedCredentials() == null
                || definition.getRequestedCredentials().isEmpty()) {
            return null;
        }
        return definition.getRequestedCredentials().get(0);
    }

    /**
     * Reads the {@code iss} claim from the raw (unverified) VP token without performing
     * any signature check.  For SD-JWT tokens the issuer-signed JWT part is extracted first.
     *
     * <p>This is intentionally unverified: it is used only as a fast-fail policy gate.
     * Authenticity of the {@code iss} value is proven later by the cryptographic
     * signature check in {@link Verifier#handle}.</p>
     *
     * @param vpToken Raw VP token string
     * @param format  Token format (used to detect SD-JWT encoding)
     * @return The {@code iss} claim value, or {@code null} if it cannot be read
     */
    private String parseIssFromRawToken(String vpToken, String format) {

        try {
            String jwtPart = vpToken;
            if (Constants.VC_SD_JWT_FORMAT.equals(format) && vpToken.contains("~")) {
                jwtPart = vpToken.substring(0, vpToken.indexOf('~'));
            }
            SignedJWT jwt = SignedJWT.parse(jwtPart);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            return claims.getStringClaim(Constants.CLAIM_ISS);
        } catch (ParseException e) {
            LOG.debug("Could not parse iss from raw token for pre-check: " + e.getMessage());
            return null;
        }
    }

    /**
     * Enforces the trusted-issuers policy: rejects the presentation if {@code iss} is
     * absent or not contained in the configured list.
     *
     * @param iss            The {@code iss} value read from the unverified token
     * @param trustedIssuers The list of accepted issuer identifiers
     * @throws VerificationClientException If {@code iss} is missing or untrusted
     */
    private void enforceTrustedIssuer(String iss, List<String> trustedIssuers)
            throws VerificationClientException {

        if (CollectionUtils.isEmpty(trustedIssuers)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "Issuer enforcement is enabled but no trusted issuers are configured.");
        }
        if (StringUtils.isBlank(iss)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "Issuer enforcement failed: 'iss' claim is missing from the VP token.");
        }
        if (!trustedIssuers.contains(iss)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "Issuer '" + iss + "' is not in the trusted issuers list.");
        }
    }

    /**
     * Extracts the pinned issuer {@link PublicKey} from the {@code issuerCertPem} field of
     * the given {@link RequestedCredential}.  Returns {@code null} when no cert is configured,
     * which causes the verifier to fall back to live JWKS/x5c discovery.
     *
     * <p>The cert is scoped to the specific credential entry, so each requested credential
     * type can pin a different issuer key.</p>
     */
    private PublicKey resolveKeyFromCredential(RequestedCredential req) {

        if (req == null || StringUtils.isBlank(req.getIssuerCertPem())) {
            return null;
        }
        try {
            return SignatureVerifier.extractPublicKeyFromPem(req.getIssuerCertPem());
        } catch (VerificationException e) {
            LOG.warn("Failed to extract public key from issuer cert PEM; "
                    + "falling back to JWKS/x5c discovery.", e);
            return null;
        }
    }

    /**
     * Verifies that every claim declared in the Presentation Definition's
     * {@code RequestedCredential} is present in the already-verified claim set.
     *
     * <p>The {@code iss} policy check is intentionally absent here — it is enforced
     * before the cryptographic step in {@link #verify} so that untrusted issuers are
     * rejected before any signature work is performed.</p>
     *
     * @param verifiedClaims Claims extracted and verified by the format-specific verifier
     * @param definition     The Presentation Definition to enforce
     * @return The verified claim map when all constraints are satisfied
     * @throws VerificationException If a required claim is absent
     */
    private Map<String, Object> verifyRequiredClaims(Map<String, Object> verifiedClaims,
                                                      PresentationDefinition definition)
            throws VerificationException {

        if (definition.getRequestedCredentials() == null
                || definition.getRequestedCredentials().isEmpty()) {
            return verifiedClaims;
        }

        // Single-VC support only.
        RequestedCredential req = definition.getRequestedCredentials().get(0);

        if (CollectionUtils.isNotEmpty(req.getClaims())) {
            for (ClaimConstraint constraint : req.getClaims()) {
                String claimName = constraint.getName();
                if (StringUtils.isBlank(claimName)) {
                    continue;
                }
                boolean claimPresent = verifiedClaims.containsKey(claimName);

                if (constraint.isMandatory() && !claimPresent) {
                    throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                            "Required claim '" + claimName + "' is missing from the presentation.");
                }

                if (claimPresent && CollectionUtils.isNotEmpty(constraint.getAllowedValues())) {
                    Object actualValue = verifiedClaims.get(claimName);
                    String actualStr = actualValue != null ? actualValue.toString() : null;
                    if (!constraint.getAllowedValues().contains(actualStr)) {
                        LOG.warn("Claim '" + claimName + "' value does not match allowed values.");
                        throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                                "Credential does not meet the required constraints.");
                    }
                }
            }
        }

        return verifiedClaims;
    }

    // JWT/SD-JWT technical claims that belong in structured metadata fields, not in holder.claims.
    private static final Set<String> TECHNICAL_CLAIMS = new HashSet<>(Arrays.asList(
            "iss", "sub", "iat", "exp", "jti", "nbf", "aud",
            "cnf", "_sd", "_sd_alg", "vct"
    ));

    /**
     * Extracts all available metadata from the VP token and the verified claims map.
     */
    @SuppressWarnings("unchecked")
    private PresentationMetadata extractMetadata(String vpToken, String format, Map<String, Object> claims) {

        PresentationMetadata.Builder builder = new PresentationMetadata.Builder()
                .vpFormat(format)
                .presentationTime(System.currentTimeMillis());

        String issuerJwt = vpToken;
        if (Constants.VC_SD_JWT_FORMAT.equals(format) && vpToken.contains("~")) {
            issuerJwt = vpToken.substring(0, vpToken.indexOf('~'));
        }
        try {
            SignedJWT parsedVp = SignedJWT.parse(issuerJwt);
            if (parsedVp.getHeader() != null && parsedVp.getHeader().getAlgorithm() != null) {
                builder.algorithm(parsedVp.getHeader().getAlgorithm().getName());
            }
        } catch (java.text.ParseException e) {
            // already verified above — ignore
        }

        if (claims.get(Constants.CLAIM_ISS) != null) {
            builder.issuerDid(claims.get(Constants.CLAIM_ISS).toString());
        }
        if (claims.get(Constants.CLAIM_SUB) != null) {
            builder.holderDid(claims.get(Constants.CLAIM_SUB).toString());
        }
        if (claims.get(Constants.CLAIM_IAT) instanceof Long) {
            builder.issuedAt((Long) claims.get(Constants.CLAIM_IAT));
        }
        if (claims.get(Constants.CLAIM_EXP) instanceof Long) {
            builder.expiresAt((Long) claims.get(Constants.CLAIM_EXP));
        }
        if (claims.get("vct") != null) {
            builder.credentialType(claims.get("vct").toString());
        }

        Object cnfObj = claims.get("cnf");
        if (cnfObj instanceof Map) {
            Map<String, Object> cnf = (Map<String, Object>) cnfObj;
            Object jwkObj = cnf.get("jwk");
            if (jwkObj instanceof Map) {
                try {
                    JWK jwk = JWK.parse((Map<String, Object>) jwkObj);
                    builder.holderBindingMethod("cnf.jwk");
                    String keyType = jwk.getKeyType().getValue();
                    builder.holderKeyType(keyType);
                    if ("EC".equals(keyType)) {
                        builder.holderKeyCurve(((ECKey) jwk).getCurve().getName());
                    } else if ("OKP".equals(keyType)) {
                        builder.holderKeyCurve(((OctetKeyPair) jwk).getCurve().getName());
                    }
                } catch (Exception e) {
                    LOG.debug("Could not parse cnf.jwk for metadata: " + e.getMessage());
                }
            }
        }

        if (Constants.VC_SD_JWT_FORMAT.equals(format)) {
            try {
                SDJWT sdJwt = SDJWT.parse(vpToken);
                if (sdJwt.hasKeyBinding()) {
                    builder.kbJwtVerified(true);
                    SignedJWT kbJwt = SignedJWT.parse(sdJwt.getKeyBindingJwt());
                    JWTClaimsSet kbClaims = kbJwt.getJWTClaimsSet();
                    if (kbClaims.getIssueTime() != null) {
                        builder.kbJwtPresentedAt(kbClaims.getIssueTime().getTime());
                    }
                    if (kbClaims.getAudience() != null && !kbClaims.getAudience().isEmpty()) {
                        builder.kbJwtAudience(kbClaims.getAudience().get(0));
                    }
                    String kbNonce = kbClaims.getStringClaim("nonce");
                    if (StringUtils.isNotBlank(kbNonce)) {
                        builder.nonce(kbNonce);
                    }
                }
            } catch (Exception e) {
                LOG.debug("Could not extract KB-JWT metadata: " + e.getMessage());
            }
        }

        Map<String, Object> credentialClaims = new HashMap<>();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            if (!TECHNICAL_CLAIMS.contains(entry.getKey())) {
                credentialClaims.put(entry.getKey(), entry.getValue());
            }
        }
        builder.credentialClaims(credentialClaims);

        return builder.build();
    }

    /**
     * Validates the VP token and presentation submission before processing.
     */
    private void validateRequest(PresentationSubmission submission, String vpToken)
            throws VerificationException {

        if (StringUtils.isBlank(vpToken)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_VP_SUBMISSION,
                    VerificationConstants.ERROR_INVALID_VP_TOKEN);
        }

        if (submission == null) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_VP_SUBMISSION,
                    "Presentation submission is null.");
        }

        if (StringUtils.isBlank(submission.getDefinitionId())) {
            throw new VerificationServerException(VerificationErrorCode.INVALID_VP_SUBMISSION,
                    "Presentation submission is missing a definition_id.");
        }

        List<PresentationSubmission.DescriptorMap> descriptorMap = submission.getDescriptorMap();
        if (descriptorMap == null || descriptorMap.isEmpty()) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_VP_SUBMISSION,
                    "Presentation submission descriptor_map is missing or empty.");
        }

        String format = descriptorMap.get(0).getFormat();
        if (StringUtils.isBlank(format)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_VP_FORMAT,
                    "Presentation submission descriptor_map entry is missing a format.");
        }
        boolean isSupportedFormat = Constants.JWT_VC_FORMAT.equals(format)
                || Constants.VC_SD_JWT_FORMAT.equals(format);
        if (!isSupportedFormat) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_VP_FORMAT,
                    "Unsupported VP format: " + format + ". Supported formats: "
                            + Constants.JWT_VC_FORMAT + ", " + Constants.VC_SD_JWT_FORMAT);
        }
    }

    /**
     * Checks the credential's revocation status via the OAuth Status List.
     * If the credential is revoked a {@link VerificationClientException} is thrown.
     * If the credential has no {@code status} claim, the outcome depends on the
     * tenant-level {@code rejectVcWithoutStatusClaim} policy.
     */
    private void checkRevocationStatus(Map<String, Object> verifiedClaims, int tenantId)
            throws VerificationException {

        RevocationStatus status = StatusListChecker.check(verifiedClaims);

        if (status == RevocationStatus.REVOKED) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "The presented credential has been revoked by the issuer.");
        }

        if (status == RevocationStatus.NO_STATUS_CLAIM && openID4VPConfigService != null) {
            try {
                OpenID4VPTenantConfig cfg = openID4VPConfigService.getConfigByTenantId(tenantId);
                if (Boolean.TRUE.equals(cfg.getRejectVcWithoutStatusClaim())) {
                    throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                            "The presented credential does not contain a status claim, "
                                    + "which is required by this tenant's verification policy.");
                }
            } catch (VerificationException e) {
                throw e;
            } catch (OpenID4VPConfigMgtException e) {
                LOG.warn("[OID4VP] Could not load tenant config for revocation policy check (tenantId="
                        + tenantId + "). Allowing VC without status claim.", e);
            }
        }
    }

    @Reference(
            name = "presentation.definition.service",
            service = PresentationDefinitionService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetPresentationDefinitionService"
    )
    protected void setPresentationDefinitionService(PresentationDefinitionService service) {

        this.presentationDefinitionService = service;
    }

    protected void unsetPresentationDefinitionService(PresentationDefinitionService service) {

        this.presentationDefinitionService = null;
    }

    @Reference(
            name = "openid4vp.config.service",
            service = OpenID4VPConfigService.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOpenID4VPConfigService"
    )
    protected void setOpenID4VPConfigService(OpenID4VPConfigService service) {

        this.openID4VPConfigService = service;
    }

    protected void unsetOpenID4VPConfigService(OpenID4VPConfigService service) {

        this.openID4VPConfigService = null;
    }
}
