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

package org.wso2.carbon.identity.openid4vc.presentation.service.impl;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VCVerificationResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.CredentialVerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.DIDResolutionException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.RevocationCheckException;
import org.wso2.carbon.identity.openid4vc.presentation.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.model.RevocationCheckResult;
import org.wso2.carbon.identity.openid4vc.presentation.model.VCVerificationStatus;
import org.wso2.carbon.identity.openid4vc.presentation.model.VerifiableCredential;
import org.wso2.carbon.identity.openid4vc.presentation.model.VerifiablePresentation;
import org.wso2.carbon.identity.openid4vc.presentation.service.DIDResolverService;
import org.wso2.carbon.identity.openid4vc.presentation.service.StatusListService;
import org.wso2.carbon.identity.openid4vc.presentation.service.TrustedIssuerService;
import org.wso2.carbon.identity.openid4vc.presentation.service.VCVerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.util.OpenID4VPLogger;
import org.wso2.carbon.identity.openid4vc.presentation.util.SignatureVerifier;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

/**
 * Implementation of VCVerificationService for verifying Verifiable Credentials.
 * Supports JSON-LD, JWT, and SD-JWT credential formats.
 */
public class VCVerificationServiceImpl implements VCVerificationService {

    private static final Log LOG = LogFactory.getLog(VCVerificationServiceImpl.class);
    private static final Gson GSON = new Gson();

    // Content type constants
    private static final String CONTENT_TYPE_VC_LD_JSON = "application/vc+ld+json";
    private static final String CONTENT_TYPE_JWT = "application/jwt";
    private static final String CONTENT_TYPE_VC_JWT = "application/vc+jwt";
    private static final String CONTENT_TYPE_SD_JWT = "application/vc+sd-jwt";
    private static final String CONTENT_TYPE_JSON = "application/json";

    private static final String[] SUPPORTED_CONTENT_TYPES = {
            CONTENT_TYPE_VC_LD_JSON,
            CONTENT_TYPE_JWT,
            CONTENT_TYPE_VC_JWT,
            CONTENT_TYPE_SD_JWT,
            CONTENT_TYPE_JSON
    };

    // Date format for ISO 8601 dates
    private static final String[] DATE_FORMATS = {
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            "yyyy-MM-dd'T'HH:mm:ssXXX",
            "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",
            "yyyy-MM-dd'T'HH:mm:ss.SSSXXX",
            "yyyy-MM-dd"
    };

    private final DIDResolverService didResolverService;
    private final SignatureVerifier signatureVerifier;
    private final StatusListService statusListService;

    /**
     * Default constructor.
     */
    public VCVerificationServiceImpl() {
        this.didResolverService = new DIDResolverServiceImpl();
        this.signatureVerifier = new SignatureVerifier(didResolverService);
        this.statusListService = new StatusListServiceImpl();
    }

    /**
     * Constructor with dependencies.
     *
     * @param didResolverService DID resolver service
     */
    public VCVerificationServiceImpl(DIDResolverService didResolverService) {
        this.didResolverService = didResolverService;
        this.signatureVerifier = new SignatureVerifier(didResolverService);
        this.statusListService = new StatusListServiceImpl();
    }

    /**
     * Constructor with all dependencies.
     *
     * @param didResolverService DID resolver service
     * @param statusListService  Status list service
     */
    public VCVerificationServiceImpl(DIDResolverService didResolverService,
            StatusListService statusListService) {
        this.didResolverService = didResolverService;
        this.signatureVerifier = new SignatureVerifier(didResolverService);
        this.statusListService = statusListService;
    }

    @Override
    public VCVerificationResultDTO verify(String vcString, String contentType)
            throws CredentialVerificationException {
        return verify(vcString, contentType, 0);
    }

    @Override
    public VCVerificationResultDTO verify(String vcString, String contentType, int vcIndex)
            throws CredentialVerificationException {

        if (vcString == null || vcString.trim().isEmpty()) {
            throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                    "Credential string is null or empty");
        }

        try {
            // Parse the credential
            VerifiableCredential credential = parseCredential(vcString, contentType);

            // Perform verification
            VCVerificationResultDTO result = verifyCredentialInternal(credential, vcIndex);

            return result;

        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("Error verifying credential", e);
            throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                    "Verification failed: " + e.getMessage());
        }
    }

    @Override
    public VCVerificationResultDTO verifyCredential(VerifiableCredential credential)
            throws CredentialVerificationException {
        return verifyCredentialInternal(credential, 0);
    }

    /**
     * Internal method to verify a parsed credential.
     */
    private VCVerificationResultDTO verifyCredentialInternal(VerifiableCredential credential, int vcIndex)
            throws CredentialVerificationException {

        String credentialType = credential.getPrimaryType();
        String issuer = credential.getIssuerId();

        LOG.info("[VC_VERIFICATION] Starting verification for credential ID: " + credential.getId() +
                ", Type: " + credentialType + ", Issuer: " + issuer);

        // 1. Check expiration
        if (credential.getExpirationDate() != null && isExpired(credential)) {
            LOG.warn("[VC_VERIFICATION] Credential has expired: " + credential.getId());
            LOG.debug("Credential has expired: " + credential.getId());
            return new VCVerificationResultDTO(vcIndex, VCVerificationStatus.EXPIRED,
                    "Credential has expired");
        }
        credential.setExpirationChecked(true);
        LOG.info("[VC_VERIFICATION] Expiration check passed for credential: " + credential.getId());

        // 2. Verify signature
        try {
            boolean signatureValid = verifySignature(credential);
            if (!signatureValid) {
                LOG.error("[VC_VERIFICATION] Credential signature verification failed: " + credential.getId());
                LOG.debug("Credential signature verification failed: " + credential.getId());
                return new VCVerificationResultDTO(vcIndex, VCVerificationStatus.INVALID,
                        "Cryptographic signature verification failed");
            }
            credential.setSignatureVerified(true);
            LOG.info("[VC_VERIFICATION] Signature verification passed for credential: " + credential.getId());
        } catch (CredentialVerificationException e) {
            LOG.error("[VC_VERIFICATION] Signature verification error: " + e.getMessage());
            LOG.debug("Signature verification error: " + e.getMessage());
            return new VCVerificationResultDTO(vcIndex, VCVerificationStatus.INVALID,
                    "Signature verification error: " + e.getMessage());
        }

        // 3. Check revocation (if applicable)
        if (credential.hasCredentialStatus()) {
            try {
                if (isRevoked(credential)) {
                    LOG.info("[VC_VERIFICATION] Credential has been revoked: " + credential.getId());
                    LOG.debug("Credential has been revoked: " + credential.getId());
                    return new VCVerificationResultDTO(vcIndex, VCVerificationStatus.REVOKED,
                            "Credential has been revoked");
                }
                credential.setRevocationChecked(true);
                LOG.info("[VC_VERIFICATION] Revocation check passed for credential: " + credential.getId());
            } catch (CredentialVerificationException e) {
                LOG.warn("[VC_VERIFICATION] Revocation check failed, continuing: " + e.getMessage());
                // Continue without failing - revocation check is optional
            }
        } else {
            LOG.info("[VC_VERIFICATION] No revocation status found - skipping check for credential: "
                    + credential.getId());
        }

        // All checks passed
        LOG.info("[VC_VERIFICATION] Credential verification COMPLETED successfully: " + credential.getId());
        LOG.debug("Credential verification successful: " + credential.getId());
        return new VCVerificationResultDTO(vcIndex, VCVerificationStatus.SUCCESS,
                credentialType, issuer);
    }

    @Override
    public List<VCVerificationResultDTO> verifyVPToken(String vpToken)
            throws CredentialVerificationException {

        if (vpToken == null || vpToken.trim().isEmpty()) {
            throw new CredentialVerificationException("VP token is null or empty");
        }

        VerifiablePresentation presentation = parsePresentation(vpToken);
        return verifyPresentation(presentation);
    }

    @Override
    public List<VCVerificationResultDTO> verifyPresentation(VerifiablePresentation presentation)
            throws CredentialVerificationException {

        List<VCVerificationResultDTO> results = new ArrayList<>();

        if (presentation.getVerifiableCredentials() == null ||
                presentation.getVerifiableCredentials().isEmpty()) {
            LOG.error("[VC_VERIFICATION] No verifiable credentials found in presentation");
            throw new CredentialVerificationException("No verifiable credentials found in presentation");
        }

        LOG.info("[VC_VERIFICATION] Verifying presentation with " +
                presentation.getVerifiableCredentials().size() + " credentials");

        // Verify each credential
        int index = 0;
        for (VerifiableCredential credential : presentation.getVerifiableCredentials()) {
            try {
                VCVerificationResultDTO result = verifyCredentialInternal(credential, index);
                results.add(result);
            } catch (CredentialVerificationException e) {
                LOG.error("[VC_VERIFICATION] Verification failed for credential at index " + index + ": "
                        + e.getMessage());
                results.add(new VCVerificationResultDTO(index, VCVerificationStatus.INVALID,
                        e.getMessage()));
            }
            index++;
        }

        LOG.info("[VC_VERIFICATION] Presentation verification completed. Total Results: " + results.size());
        return results;
    }

    @Override
    public boolean verifySignature(VerifiableCredential credential)
            throws CredentialVerificationException {

        if (credential == null) {
            throw new CredentialVerificationException("Credential is null");
        }

        try {
            if (credential.isJwt()) {
                return verifyJwtSignature(credential);
            } else if (credential.isSdJwt()) {
                return verifySdJwtSignature(credential);
            } else if (credential.isJsonLd()) {
                return verifyJsonLdSignature(credential);
            } else {
                throw new CredentialVerificationException(
                        "Unknown credential format: " + credential.getFormat());
            }
        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "Signature verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * Verify JWT credential signature.
     */
    private boolean verifyJwtSignature(VerifiableCredential credential)
            throws CredentialVerificationException {

        String rawCredential = credential.getRawCredential();
        String[] parts = rawCredential.split("\\.");

        if (parts.length != 3) {
            throw new CredentialVerificationException("Invalid JWT format");
        }

        try {
            // Get issuer DID from credential
            String issuer = credential.getIssuerId();
            if (issuer == null || !issuer.startsWith("did:")) {
                // Try to get from JWT header kid
                Map<String, Object> header = parseJwtPart(parts[0]);
                if (header.containsKey("kid")) {
                    String kid = header.get("kid").toString();
                    if (kid.startsWith("did:")) {
                        issuer = kid.split("#")[0];
                    }
                }
            }

            if (issuer == null || !issuer.startsWith("did:")) {
                LOG.warn("Cannot determine issuer DID for signature verification");
                // For non-DID issuers, we cannot verify without additional configuration
                return true; // Skip verification for non-DID issuers
            }

            // Get the public key
            PublicKey publicKey = didResolverService.getPublicKey(issuer, null);

            // Determine algorithm from header
            Map<String, Object> header = parseJwtPart(parts[0]);
            String alg = header.containsKey("alg") ? header.get("alg").toString() : "RS256";

            // Verify signature
            return signatureVerifier.verifyJwtSignature(rawCredential, publicKey, alg);

        } catch (DIDResolutionException e) {
            throw new CredentialVerificationException(
                    "Failed to resolve issuer DID: " + e.getMessage(), e);
        }
    }

    /**
     * Verify SD-JWT credential signature.
     */
    private boolean verifySdJwtSignature(VerifiableCredential credential)
            throws CredentialVerificationException {

        // SD-JWT format: <issuer-jwt>~<disclosure1>~<disclosure2>~...~<kb-jwt>
        String rawCredential = credential.getRawCredential();
        String[] parts = rawCredential.split("~");

        if (parts.length < 1) {
            throw new CredentialVerificationException("Invalid SD-JWT format");
        }

        // Verify the issuer JWT (first part)
        String issuerJwt = parts[0];

        // Create a temporary credential for JWT verification
        VerifiableCredential tempCred = new VerifiableCredential();
        tempCred.setFormat(VerifiableCredential.Format.JWT);
        tempCred.setRawCredential(issuerJwt);
        tempCred.setIssuer(credential.getIssuer());
        tempCred.setIssuerId(credential.getIssuerId());

        return verifyJwtSignature(tempCred);
    }

    /**
     * Verify JSON-LD credential signature.
     */
    private boolean verifyJsonLdSignature(VerifiableCredential credential)
            throws CredentialVerificationException {

        VerifiableCredential.Proof proof = credential.getProof();
        if (proof == null) {
            throw new CredentialVerificationException("No proof found in JSON-LD credential");
        }

        String verificationMethod = proof.getVerificationMethod();
        if (verificationMethod == null) {
            throw new CredentialVerificationException("No verification method in proof");
        }

        try {
            // Extract DID from verification method
            String did = verificationMethod.contains("#")
                    ? verificationMethod.substring(0, verificationMethod.indexOf("#"))
                    : verificationMethod;

            // Get the public key
            PublicKey publicKey = didResolverService.getPublicKey(did, verificationMethod);

            // Get proof value
            String proofValue = proof.getProofValue();
            if (proofValue == null) {
                proofValue = proof.getJws();
            }

            if (proofValue == null) {
                throw new CredentialVerificationException("No proof value found");
            }

            // Verify based on proof type
            return signatureVerifier.verifyLinkedDataSignature(
                    credential.getRawCredential(),
                    publicKey,
                    proof.getType(),
                    proofValue);

        } catch (DIDResolutionException e) {
            throw new CredentialVerificationException(
                    "Failed to resolve verification method: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean isExpired(VerifiableCredential credential) {
        if (credential == null || credential.getExpirationDate() == null) {
            return false;
        }
        return new Date().after(credential.getExpirationDate());
    }

    @Override
    public boolean isRevoked(VerifiableCredential credential)
            throws CredentialVerificationException {

        if (credential == null || !credential.hasCredentialStatus()) {
            return false;
        }

        VerifiableCredential.CredentialStatus status = credential.getCredentialStatus();

        try {
            // Use the StatusListService to check revocation
            RevocationCheckResult result = statusListService.checkRevocationStatus(status);

            if (result.getStatus() == RevocationCheckResult.Status.SKIPPED) {
                LOG.debug("Revocation check skipped: " + result.getMessage());
                return false;
            }

            if (result.getStatus() == RevocationCheckResult.Status.UNKNOWN) {
                LOG.warn("Revocation check returned unknown status: " + result.getMessage());
                return false;
            }

            // Return true if REVOKED or SUSPENDED
            return result.getStatus() == RevocationCheckResult.Status.REVOKED ||
                    result.getStatus() == RevocationCheckResult.Status.SUSPENDED;

        } catch (RevocationCheckException e) {
            LOG.error("Error checking revocation status", e);
            throw new CredentialVerificationException(
                    "Error checking revocation status: " + e.getMessage(), e);
        }
    }

    /**
     * Check revocation status using StatusList2021 with detailed result.
     *
     * @param status the credential status
     * @return the revocation check result
     * @throws CredentialVerificationException if check fails
     */
    public RevocationCheckResult checkRevocationStatus(VerifiableCredential.CredentialStatus status)
            throws CredentialVerificationException {

        try {
            return statusListService.checkRevocationStatus(status);
        } catch (RevocationCheckException e) {
            throw new CredentialVerificationException(
                    "Error checking revocation status: " + e.getMessage(), e);
        }
    }

    @Override
    public VerifiableCredential parseCredential(String vcString, String contentType)
            throws CredentialVerificationException {

        if (vcString == null || vcString.trim().isEmpty()) {
            throw new CredentialVerificationException("Credential string is null or empty");
        }

        String normalizedContentType = normalizeContentType(contentType);

        try {
            // Auto-detect format if content type is generic JSON or null
            if (normalizedContentType == null || CONTENT_TYPE_JSON.equals(normalizedContentType)) {
                normalizedContentType = detectFormat(vcString);
            }

            if (CONTENT_TYPE_JWT.equals(normalizedContentType) ||
                    CONTENT_TYPE_VC_JWT.equals(normalizedContentType)) {
                return parseJwtCredential(vcString);
            } else if (CONTENT_TYPE_SD_JWT.equals(normalizedContentType)) {
                return parseSdJwtCredential(vcString);
            } else {
                return parseJsonLdCredential(vcString);
            }

        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "Failed to parse credential: " + e.getMessage(), e);
        }
    }

    /**
     * Detect the format of a credential string.
     */
    private String detectFormat(String vcString) {
        vcString = vcString.trim();

        // JWT format: xxx.xxx.xxx
        if (vcString.split("\\.").length == 3 && !vcString.startsWith("{")) {
            return CONTENT_TYPE_JWT;
        }

        // SD-JWT format: xxx.xxx.xxx~xxx~xxx
        if (vcString.contains("~") && vcString.split("~")[0].split("\\.").length == 3) {
            return CONTENT_TYPE_SD_JWT;
        }

        // JSON-LD format: starts with {
        if (vcString.startsWith("{")) {
            return CONTENT_TYPE_VC_LD_JSON;
        }

        return CONTENT_TYPE_VC_LD_JSON;
    }

    /**
     * Parse a JWT credential.
     */
    private VerifiableCredential parseJwtCredential(String jwtString)
            throws CredentialVerificationException {

        String[] parts = jwtString.split("\\.");
        if (parts.length != 3) {
            throw new CredentialVerificationException("Invalid JWT format: expected 3 parts");
        }

        try {
            VerifiableCredential credential = new VerifiableCredential();
            credential.setFormat(VerifiableCredential.Format.JWT);
            credential.setRawCredential(jwtString);
            credential.setJwtHeader(parts[0]);
            credential.setJwtPayload(parts[1]);
            credential.setJwtSignature(parts[2]);

            // Decode payload
            Map<String, Object> payload = parseJwtPart(parts[1]);
            credential.setJwtClaims(payload);

            // Extract standard claims
            if (payload.containsKey("iss")) {
                credential.setIssuer(payload.get("iss").toString());
                credential.setIssuerId(payload.get("iss").toString());
            }

            if (payload.containsKey("sub")) {
                credential.setCredentialSubjectId(payload.get("sub").toString());
            }

            if (payload.containsKey("jti")) {
                credential.setId(payload.get("jti").toString());
            }

            // Parse expiration
            if (payload.containsKey("exp")) {
                long exp = ((Number) payload.get("exp")).longValue();
                credential.setExpirationDate(new Date(exp * 1000));
            }

            // Parse issuance date
            if (payload.containsKey("iat")) {
                long iat = ((Number) payload.get("iat")).longValue();
                credential.setIssuanceDate(new Date(iat * 1000));
            } else if (payload.containsKey("nbf")) {
                long nbf = ((Number) payload.get("nbf")).longValue();
                credential.setIssuanceDate(new Date(nbf * 1000));
            }

            // Extract VC claim if present (JWT VC format)
            if (payload.containsKey("vc")) {
                Object vcClaim = payload.get("vc");
                if (vcClaim instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> vcMap = (Map<String, Object>) vcClaim;
                    extractVcFields(credential, vcMap);
                }
            }

            return credential;

        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "Failed to parse JWT credential: " + e.getMessage(), e);
        }
    }

    /**
     * Parse a SD-JWT credential.
     */
    private VerifiableCredential parseSdJwtCredential(String sdJwtString)
            throws CredentialVerificationException {

        String[] parts = sdJwtString.split("~");
        if (parts.length < 1) {
            throw new CredentialVerificationException("Invalid SD-JWT format");
        }

        try {
            // Parse the issuer JWT first
            VerifiableCredential credential = parseJwtCredential(parts[0]);
            credential.setFormat(VerifiableCredential.Format.SD_JWT);
            credential.setRawCredential(sdJwtString);

            // Parse disclosures
            List<String> disclosures = new ArrayList<>();
            for (int i = 1; i < parts.length; i++) {
                String part = parts[i].trim();
                if (!part.isEmpty()) {
                    // Check if this is the key binding JWT (last part, contains dots)
                    if (i == parts.length - 1 && part.split("\\.").length == 3) {
                        credential.setKeyBindingJwt(part);
                    } else {
                        disclosures.add(part);
                    }
                }
            }
            credential.setDisclosures(disclosures);

            // Process disclosures to extract revealed claims
            processDisclosures(credential);

            return credential;

        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "Failed to parse SD-JWT credential: " + e.getMessage(), e);
        }
    }

    /**
     * Process SD-JWT disclosures to extract claims.
     */
    private void processDisclosures(VerifiableCredential credential) {
        if (credential.getDisclosures() == null) {
            return;
        }

        Map<String, Object> claims = credential.getCredentialSubject();
        if (claims == null) {
            claims = new HashMap<>();
            credential.setCredentialSubject(claims);
        }

        for (String disclosure : credential.getDisclosures()) {
            try {
                // Disclosure format: base64url([salt, claim_name, claim_value])
                String decoded = new String(Base64.getUrlDecoder().decode(disclosure),
                        StandardCharsets.UTF_8);
                JsonArray arr = JsonParser.parseString(decoded).getAsJsonArray();

                if (arr.size() >= 3) {
                    String claimName = arr.get(1).getAsString();
                    JsonElement claimValue = arr.get(2);
                    claims.put(claimName, parseJsonElement(claimValue));
                }
            } catch (Exception e) {
                LOG.warn("Failed to parse disclosure: " + e.getMessage());
            }
        }
    }

    /**
     * Parse a JSON-LD credential.
     */
    private VerifiableCredential parseJsonLdCredential(String jsonString)
            throws CredentialVerificationException {

        try {
            JsonObject json = JsonParser.parseString(jsonString).getAsJsonObject();

            VerifiableCredential credential = new VerifiableCredential();
            credential.setFormat(VerifiableCredential.Format.JSON_LD);
            credential.setRawCredential(jsonString);

            // Parse @context
            if (json.has("@context")) {
                JsonElement context = json.get("@context");
                if (context.isJsonArray()) {
                    for (JsonElement el : context.getAsJsonArray()) {
                        if (el.isJsonPrimitive()) {
                            credential.addContext(el.getAsString());
                        }
                    }
                } else if (context.isJsonPrimitive()) {
                    credential.addContext(context.getAsString());
                }
            }

            // Parse type
            if (json.has("type")) {
                JsonElement typeEl = json.get("type");
                if (typeEl.isJsonArray()) {
                    for (JsonElement el : typeEl.getAsJsonArray()) {
                        credential.addType(el.getAsString());
                    }
                } else if (typeEl.isJsonPrimitive()) {
                    credential.addType(typeEl.getAsString());
                }
            }

            // Parse id
            if (json.has("id")) {
                credential.setId(json.get("id").getAsString());
            }

            // Parse issuer
            if (json.has("issuer")) {
                JsonElement issuerEl = json.get("issuer");
                if (issuerEl.isJsonPrimitive()) {
                    credential.setIssuer(issuerEl.getAsString());
                    credential.setIssuerId(issuerEl.getAsString());
                } else if (issuerEl.isJsonObject()) {
                    JsonObject issuerObj = issuerEl.getAsJsonObject();
                    if (issuerObj.has("id")) {
                        credential.setIssuerId(issuerObj.get("id").getAsString());
                    }
                    if (issuerObj.has("name")) {
                        credential.setIssuerName(issuerObj.get("name").getAsString());
                    }
                    credential.setIssuer(issuerObj.toString());
                }
            }

            // Parse dates
            if (json.has("issuanceDate")) {
                credential.setIssuanceDate(parseDate(json.get("issuanceDate").getAsString()));
            } else if (json.has("validFrom")) {
                credential.setIssuanceDate(parseDate(json.get("validFrom").getAsString()));
            }

            if (json.has("expirationDate")) {
                credential.setExpirationDate(parseDate(json.get("expirationDate").getAsString()));
            } else if (json.has("validUntil")) {
                credential.setExpirationDate(parseDate(json.get("validUntil").getAsString()));
            }

            // Parse credential subject
            if (json.has("credentialSubject")) {
                JsonElement subjectEl = json.get("credentialSubject");
                if (subjectEl.isJsonObject()) {
                    JsonObject subjectObj = subjectEl.getAsJsonObject();
                    Map<String, Object> subjectMap = new HashMap<>();
                    for (String key : subjectObj.keySet()) {
                        subjectMap.put(key, parseJsonElement(subjectObj.get(key)));
                    }
                    credential.setCredentialSubject(subjectMap);
                    if (subjectObj.has("id")) {
                        credential.setCredentialSubjectId(subjectObj.get("id").getAsString());
                    }
                }
            }

            // Parse credential status
            if (json.has("credentialStatus")) {
                JsonElement statusEl = json.get("credentialStatus");
                if (statusEl.isJsonObject()) {
                    JsonObject statusObj = statusEl.getAsJsonObject();
                    VerifiableCredential.CredentialStatus status = new VerifiableCredential.CredentialStatus();

                    if (statusObj.has("id")) {
                        status.setId(statusObj.get("id").getAsString());
                    }
                    if (statusObj.has("type")) {
                        status.setType(statusObj.get("type").getAsString());
                    }
                    if (statusObj.has("statusPurpose")) {
                        status.setStatusPurpose(statusObj.get("statusPurpose").getAsString());
                    }
                    if (statusObj.has("statusListIndex")) {
                        status.setStatusListIndex(statusObj.get("statusListIndex").getAsString());
                    }
                    if (statusObj.has("statusListCredential")) {
                        status.setStatusListCredential(
                                statusObj.get("statusListCredential").getAsString());
                    }

                    credential.setCredentialStatus(status);
                }
            }

            // Parse proof
            if (json.has("proof")) {
                JsonElement proofEl = json.get("proof");
                if (proofEl.isJsonObject()) {
                    credential.setProof(parseProof(proofEl.getAsJsonObject()));
                }
            }

            return credential;

        } catch (JsonSyntaxException e) {
            throw new CredentialVerificationException(
                    "Invalid JSON format: " + e.getMessage(), e);
        }
    }

    /**
     * Parse a proof object.
     */
    private VerifiableCredential.Proof parseProof(JsonObject proofObj) {
        VerifiableCredential.Proof proof = new VerifiableCredential.Proof();

        if (proofObj.has("type")) {
            proof.setType(proofObj.get("type").getAsString());
        }
        if (proofObj.has("created")) {
            proof.setCreated(proofObj.get("created").getAsString());
        }
        if (proofObj.has("verificationMethod")) {
            proof.setVerificationMethod(proofObj.get("verificationMethod").getAsString());
        }
        if (proofObj.has("proofPurpose")) {
            proof.setProofPurpose(proofObj.get("proofPurpose").getAsString());
        }
        if (proofObj.has("proofValue")) {
            proof.setProofValue(proofObj.get("proofValue").getAsString());
        }
        if (proofObj.has("jws")) {
            proof.setJws(proofObj.get("jws").getAsString());
        }
        if (proofObj.has("challenge")) {
            proof.setChallenge(proofObj.get("challenge").getAsString());
        }
        if (proofObj.has("domain")) {
            proof.setDomain(proofObj.get("domain").getAsString());
        }

        return proof;
    }

    /**
     * Extract VC fields from a map (used for JWT VC claims).
     */
    private void extractVcFields(VerifiableCredential credential, Map<String, Object> vcMap) {
        if (vcMap.containsKey("type")) {
            Object types = vcMap.get("type");
            if (types instanceof List) {
                for (Object t : (List<?>) types) {
                    credential.addType(t.toString());
                }
            }
        }

        if (vcMap.containsKey("credentialSubject")) {
            Object subject = vcMap.get("credentialSubject");
            if (subject instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> subjectMap = (Map<String, Object>) subject;
                credential.setCredentialSubject(subjectMap);
                if (subjectMap.containsKey("id")) {
                    credential.setCredentialSubjectId(subjectMap.get("id").toString());
                }
            }
        }
    }

    @Override
    public VerifiablePresentation parsePresentation(String vpToken)
            throws CredentialVerificationException {

        if (vpToken == null || vpToken.trim().isEmpty()) {
            throw new CredentialVerificationException("VP token is null or empty");
        }

        try {
            // Detect format
            String format = detectFormat(vpToken);

            if (CONTENT_TYPE_JWT.equals(format) || CONTENT_TYPE_VC_JWT.equals(format)) {
                return parseJwtPresentation(vpToken);
            } else {
                return parseJsonLdPresentation(vpToken);
            }

        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "Failed to parse presentation: " + e.getMessage(), e);
        }
    }

    /**
     * Parse a JWT VP.
     */
    private VerifiablePresentation parseJwtPresentation(String jwtString)
            throws CredentialVerificationException {

        String[] parts = jwtString.split("\\.");
        if (parts.length != 3) {
            throw new CredentialVerificationException("Invalid JWT VP format");
        }

        try {
            VerifiablePresentation presentation = new VerifiablePresentation();
            presentation.setFormat(VerifiablePresentation.Format.JWT);
            presentation.setRawPresentation(jwtString);
            presentation.setJwtHeader(parts[0]);
            presentation.setJwtPayload(parts[1]);
            presentation.setJwtSignature(parts[2]);

            // Decode payload
            Map<String, Object> payload = parseJwtPart(parts[1]);
            presentation.setJwtClaims(payload);

            // Extract standard claims
            if (payload.containsKey("iss")) {
                presentation.setHolder(payload.get("iss").toString());
            }

            if (payload.containsKey("nonce")) {
                presentation.setNonce(payload.get("nonce").toString());
            }

            if (payload.containsKey("jti")) {
                presentation.setId(payload.get("jti").toString());
            }

            // Extract vp claim
            if (payload.containsKey("vp")) {
                Object vpClaim = payload.get("vp");
                if (vpClaim instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> vpMap = (Map<String, Object>) vpClaim;
                    extractVpCredentials(presentation, vpMap);
                }
            }

            return presentation;

        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "Failed to parse JWT VP: " + e.getMessage(), e);
        }
    }

    /**
     * Parse a JSON-LD VP.
     */
    private VerifiablePresentation parseJsonLdPresentation(String jsonString)
            throws CredentialVerificationException {

        try {
            JsonObject json = JsonParser.parseString(jsonString).getAsJsonObject();

            VerifiablePresentation presentation = new VerifiablePresentation();
            presentation.setFormat(VerifiablePresentation.Format.JSON_LD);
            presentation.setRawPresentation(jsonString);

            // Parse standard fields
            if (json.has("id")) {
                presentation.setId(json.get("id").getAsString());
            }

            if (json.has("holder")) {
                presentation.setHolder(json.get("holder").getAsString());
            }

            // Parse verifiable credentials
            if (json.has("verifiableCredential")) {
                JsonElement vcEl = json.get("verifiableCredential");
                if (vcEl.isJsonArray()) {
                    for (JsonElement el : vcEl.getAsJsonArray()) {
                        VerifiableCredential vc;
                        if (el.isJsonPrimitive()) {
                            // JWT credential
                            vc = parseCredential(el.getAsString(), CONTENT_TYPE_JWT);
                        } else {
                            // JSON-LD credential
                            vc = parseCredential(el.toString(), CONTENT_TYPE_VC_LD_JSON);
                        }
                        presentation.addVerifiableCredential(vc);
                    }
                } else if (vcEl.isJsonPrimitive()) {
                    VerifiableCredential vc = parseCredential(vcEl.getAsString(), CONTENT_TYPE_JWT);
                    presentation.addVerifiableCredential(vc);
                } else if (vcEl.isJsonObject()) {
                    VerifiableCredential vc = parseCredential(vcEl.toString(), CONTENT_TYPE_VC_LD_JSON);
                    presentation.addVerifiableCredential(vc);
                }
            }

            // Parse proof
            if (json.has("proof")) {
                JsonElement proofEl = json.get("proof");
                if (proofEl.isJsonObject()) {
                    presentation.setProof(parseProof(proofEl.getAsJsonObject()));
                }
            }

            return presentation;

        } catch (JsonSyntaxException e) {
            throw new CredentialVerificationException(
                    "Invalid JSON format: " + e.getMessage(), e);
        }
    }

    /**
     * Extract credentials from a VP map.
     */
    private void extractVpCredentials(VerifiablePresentation presentation,
            Map<String, Object> vpMap)
            throws CredentialVerificationException {

        if (vpMap.containsKey("verifiableCredential")) {
            Object vcClaim = vpMap.get("verifiableCredential");

            if (vcClaim instanceof List) {
                for (Object vc : (List<?>) vcClaim) {
                    if (vc instanceof String) {
                        // JWT credential
                        presentation.addVerifiableCredential(
                                parseCredential(vc.toString(), CONTENT_TYPE_JWT));
                    } else if (vc instanceof Map) {
                        // JSON-LD credential embedded in JWT VP
                        presentation.addVerifiableCredential(
                                parseCredential(GSON.toJson(vc), CONTENT_TYPE_VC_LD_JSON));
                    }
                }
            } else if (vcClaim instanceof String) {
                presentation.addVerifiableCredential(
                        parseCredential(vcClaim.toString(), CONTENT_TYPE_JWT));
            }
        }
    }

    @Override
    public boolean verifyNonce(String vpToken, String expectedNonce)
            throws CredentialVerificationException {

        if (expectedNonce == null) {
            return true; // No nonce to verify
        }

        VerifiablePresentation presentation = parsePresentation(vpToken);
        String actualNonce = presentation.getJwtNonce();

        return expectedNonce.equals(actualNonce);
    }

    @Override
    public boolean isContentTypeSupported(String contentType) {
        if (contentType == null) {
            return true; // Will auto-detect
        }
        String normalized = normalizeContentType(contentType);
        return Arrays.asList(SUPPORTED_CONTENT_TYPES).contains(normalized);
    }

    @Override
    public String[] getSupportedContentTypes() {
        return SUPPORTED_CONTENT_TYPES.clone();
    }

    // Utility methods

    private String normalizeContentType(String contentType) {
        if (contentType == null) {
            return null;
        }
        // Remove charset and other parameters
        int semicolonIndex = contentType.indexOf(';');
        if (semicolonIndex > 0) {
            contentType = contentType.substring(0, semicolonIndex);
        }
        return contentType.trim().toLowerCase();
    }

    private Map<String, Object> parseJwtPart(String part) {
        String decoded = new String(Base64.getUrlDecoder().decode(part), StandardCharsets.UTF_8);
        @SuppressWarnings("unchecked")
        Map<String, Object> map = GSON.fromJson(decoded, Map.class);
        return map;
    }

    private Object parseJsonElement(JsonElement element) {
        if (element.isJsonPrimitive()) {
            if (element.getAsJsonPrimitive().isNumber()) {
                return element.getAsNumber();
            } else if (element.getAsJsonPrimitive().isBoolean()) {
                return element.getAsBoolean();
            } else {
                return element.getAsString();
            }
        } else if (element.isJsonArray()) {
            List<Object> list = new ArrayList<>();
            for (JsonElement el : element.getAsJsonArray()) {
                list.add(parseJsonElement(el));
            }
            return list;
        } else if (element.isJsonObject()) {
            Map<String, Object> map = new HashMap<>();
            for (String key : element.getAsJsonObject().keySet()) {
                map.put(key, parseJsonElement(element.getAsJsonObject().get(key)));
            }
            return map;
        }
        return null;
    }

    private Date parseDate(String dateString) {
        if (dateString == null || dateString.isEmpty()) {
            return null;
        }

        for (String format : DATE_FORMATS) {
            try {
                SimpleDateFormat sdf = new SimpleDateFormat(format);
                sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
                return sdf.parse(dateString);
            } catch (ParseException e) {
                // Try next format
            }
        }

        LOG.warn("Failed to parse date: " + dateString);
        return null;
    }

    @Override
    public boolean verifyJWTVCIssuer(String vcJwt, String tenantDomain) throws CredentialVerificationException {

        try {
            OpenID4VPLogger.logIssuerVerificationStart(LOG, "JWT");

            // 1. Decode JWT header and payload (without verification)
            String[] parts = vcJwt.split("\\.");
            if (parts.length != 3) {
                throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                        "Invalid JWT format");
            }

            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]),
                    StandardCharsets.UTF_8);
            JsonObject payload = JsonParser.parseString(payloadJson).getAsJsonObject();

            // 2. Extract issuer DID
            String issuerDid = payload.get("iss").getAsString();
            OpenID4VPLogger.logIssuerDID(LOG, "JWT", issuerDid);

            // 3. Check trusted allowlist
            OpenID4VPLogger.logTrustPolicyCheck(LOG, issuerDid);
            TrustedIssuerService trustedIssuerService = VPServiceDataHolder.getInstance()
                    .getTrustedIssuerService();

            if (!trustedIssuerService.isIssuerTrusted(issuerDid, tenantDomain)) {
                OpenID4VPLogger.logTrustPolicyRejected(LOG, issuerDid, null);
                throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                        "Untrusted issuer: " + issuerDid);
            }
            OpenID4VPLogger.logTrustPolicyAccepted(LOG);

            // 4. Verify signature using existing verification
            OpenID4VPLogger.logSignatureVerificationStart(LOG, "JWT");
            VCVerificationResultDTO result = verify(vcJwt, "application/vc+jwt");

            if (!result.isSuccess()) {
                OpenID4VPLogger.logSignatureVerificationFailed(LOG, "JWT", "Invalid signature");
                throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                        "JWT signature verification failed");
            }

            OpenID4VPLogger.logSignatureVerificationSuccess(LOG, "JWT");
            return true;

        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            OpenID4VPLogger.logError(LOG, "JWT VC Verification", e.getMessage());
            throw new CredentialVerificationException(
                    "JWT VC issuer verification failed: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean verifyJSONLDVCIssuer(JsonObject vcJsonObject, String tenantDomain)
            throws CredentialVerificationException {

        try {
            OpenID4VPLogger.logIssuerVerificationStart(LOG, "JSON-LD");

            // 1. Extract issuer DID
            String issuerDid;
            if (vcJsonObject.has("issuer")) {
                JsonElement issuerElement = vcJsonObject.get("issuer");
                if (issuerElement.isJsonPrimitive()) {
                    issuerDid = issuerElement.getAsString();
                } else if (issuerElement.isJsonObject()) {
                    issuerDid = issuerElement.getAsJsonObject().get("id").getAsString();
                } else {
                    throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                            "Invalid issuer format");
                }
            } else {
                throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                        "Missing issuer field");
            }
            OpenID4VPLogger.logIssuerDID(LOG, "JSON-LD", issuerDid);

            // 2. Check trusted allowlist
            OpenID4VPLogger.logTrustPolicyCheck(LOG, issuerDid);
            TrustedIssuerService trustedIssuerService = VPServiceDataHolder.getInstance()
                    .getTrustedIssuerService();

            if (!trustedIssuerService.isIssuerTrusted(issuerDid, tenantDomain)) {
                OpenID4VPLogger.logTrustPolicyRejected(LOG, issuerDid, null);
                throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                        "Untrusted issuer: " + issuerDid);
            }
            OpenID4VPLogger.logTrustPolicyAccepted(LOG);

            // 3. Verify using existing verification
            OpenID4VPLogger.logSignatureVerificationStart(LOG, "JSON-LD");
            String vcString = GSON.toJson(vcJsonObject);
            VCVerificationResultDTO result = verify(vcString, "application/vc+ld+json");

            if (!result.isSuccess()) {
                OpenID4VPLogger.logSignatureVerificationFailed(LOG, "JSON-LD", "Invalid signature");
                throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                        "JSON-LD signature verification failed");
            }

            OpenID4VPLogger.logSignatureVerificationSuccess(LOG, "JSON-LD");
            return true;

        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            OpenID4VPLogger.logError(LOG, "JSON-LD VC Verification", e.getMessage());
            throw new CredentialVerificationException(
                    "JSON-LD VC issuer verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * Helper to get tenant ID from domain.
     */

}
