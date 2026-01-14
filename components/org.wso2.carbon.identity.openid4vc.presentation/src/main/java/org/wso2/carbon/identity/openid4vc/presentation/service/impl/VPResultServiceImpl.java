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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.dao.VPRequestDAO;
import org.wso2.carbon.identity.openid4vc.presentation.dao.VPSubmissionDAO;
import org.wso2.carbon.identity.openid4vc.presentation.dao.impl.VPRequestDAOImpl;
import org.wso2.carbon.identity.openid4vc.presentation.dao.impl.VPSubmissionDAOImpl;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VCVerificationResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPSubmissionNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.model.VCVerificationStatus;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.model.VerifiableCredential;
import org.wso2.carbon.identity.openid4vc.presentation.model.VerifiablePresentation;
import org.wso2.carbon.identity.openid4vc.presentation.service.VCVerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPResultService;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Implementation of VPResultService for comprehensive result formatting.
 */
public class VPResultServiceImpl implements VPResultService {

    private static final Log log = LogFactory.getLog(VPResultServiceImpl.class);
    private static final Gson GSON = new Gson();

    private final VPRequestDAO vpRequestDAO;
    private final VPSubmissionDAO vpSubmissionDAO;
    private final VCVerificationService vcVerificationService;

    /**
     * Default constructor.
     */
    public VPResultServiceImpl() {
        this.vpRequestDAO = new VPRequestDAOImpl();
        this.vpSubmissionDAO = new VPSubmissionDAOImpl();
        this.vcVerificationService = new VCVerificationServiceImpl();
    }

    /**
     * Constructor for dependency injection.
     */
    public VPResultServiceImpl(VPRequestDAO vpRequestDAO, VPSubmissionDAO vpSubmissionDAO,
            VCVerificationService vcVerificationService) {
        this.vpRequestDAO = vpRequestDAO;
        this.vpSubmissionDAO = vpSubmissionDAO;
        this.vcVerificationService = vcVerificationService;
    }

    @Override
    public VPResultDTO getVPResult(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPSubmissionNotFoundException, VPException {

        if (log.isDebugEnabled()) {
            log.debug("Getting VP result for transaction: " + transactionId);
        }

        // Find request by transaction ID
        VPRequest request = vpRequestDAO.getVPRequestByTransactionId(transactionId, tenantId);
        if (request == null) {
            throw new VPRequestNotFoundException(transactionId);
        }

        // Find submission for this request
        VPSubmission submission = vpSubmissionDAO.getVPSubmissionByRequestId(request.getRequestId(), tenantId);
        if (submission == null) {
            // Check if there's an error submission
            if (request.getStatus() == VPRequestStatus.EXPIRED) {
                return buildExpiredResult(request);
            }
            throw new VPSubmissionNotFoundException(request.getRequestId());
        }

        return buildComprehensiveResult(request, submission, tenantId);
    }

    @Override
    public VPResultDTO getVPResultByRequestId(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPSubmissionNotFoundException, VPException {

        if (log.isDebugEnabled()) {
            log.debug("Getting VP result for request: " + requestId);
        }

        // Find request
        VPRequest request = vpRequestDAO.getVPRequestById(requestId, tenantId);
        if (request == null) {
            throw new VPRequestNotFoundException(requestId);
        }

        // Find submission
        VPSubmission submission = vpSubmissionDAO.getVPSubmissionByRequestId(requestId, tenantId);
        if (submission == null) {
            if (request.getStatus() == VPRequestStatus.EXPIRED) {
                return buildExpiredResult(request);
            }
            throw new VPSubmissionNotFoundException(requestId);
        }

        return buildComprehensiveResult(request, submission, tenantId);
    }

    @Override
    public VPResultDTO buildComprehensiveResult(VPRequest request, VPSubmission submission, int tenantId)
            throws VPException {

        VPResultDTO result = new VPResultDTO();
        result.setTransactionId(request.getTransactionId());
        result.setRequestId(request.getRequestId());
        result.setPresentationDefinitionId(request.getPresentationDefinitionId());
        result.setVerificationTimestamp(submission.getSubmittedAt());

        // Check for wallet error
        if (StringUtils.isNotBlank(submission.getError())) {
            result.setStatus("ERROR");
            result.setOverallResult("FAILED");
            result.setError(submission.getError());
            result.setErrorDescription(submission.getErrorDescription());
            return result;
        }

        // Parse and verify VP token
        String vpToken = submission.getVpToken();
        if (StringUtils.isBlank(vpToken)) {
            result.setStatus("ERROR");
            result.setOverallResult("FAILED");
            result.setError("invalid_vp_token");
            result.setErrorDescription("VP token is empty");
            return result;
        }

        try {
            // Parse VP to extract holder
            String holder = extractHolderFromVPToken(vpToken);
            result.setHolder(holder);

            // Get VC verification results
            List<VCVerificationResultDTO> vcResults = buildVCVerificationResults(vpToken, tenantId);
            result.setVcVerificationResults(vcResults);
            result.setVcCount(vcResults.size());

            // Determine overall status
            boolean allSuccess = vcResults.stream().allMatch(VCVerificationResultDTO::isSuccess);
            result.setOverallResult(allSuccess ? "SUCCESS" : "FAILED");
            result.setStatus(allSuccess ? "VERIFIED" : "VERIFICATION_FAILED");

        } catch (Exception e) {
            log.error("Error building comprehensive result", e);
            result.setStatus("ERROR");
            result.setOverallResult("FAILED");
            result.setError("verification_error");
            result.setErrorDescription(e.getMessage());
        }

        return result;
    }

    @Override
    public List<VCVerificationResultDTO> buildVCVerificationResults(String vpToken, int tenantId)
            throws VPException {

        List<VCVerificationResultDTO> results = new ArrayList<>();

        try {
            // Determine VP format and parse
            if (isJwtToken(vpToken)) {
                // Parse JWT VP
                results = parseAndVerifyJwtVP(vpToken);
            } else {
                // Parse JSON-LD VP
                results = parseAndVerifyJsonLdVP(vpToken);
            }
        } catch (Exception e) {
            log.error("Error building VC verification results", e);
            // Return single error result
            VCVerificationResultDTO errorResult = new VCVerificationResultDTO.Builder()
                    .vcIndex(0)
                    .verificationStatus(VCVerificationStatus.INVALID)
                    .error("Failed to parse VP: " + e.getMessage())
                    .build();
            results.add(errorResult);
        }

        return results;
    }

    @Override
    public VPResultSummaryDTO getVPResultSummary(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPSubmissionNotFoundException, VPException {

        VPResultDTO fullResult = getVPResult(transactionId, tenantId);

        VPResultSummaryDTO summary = new VPResultSummaryDTO();
        summary.setTransactionId(fullResult.getTransactionId());
        summary.setRequestId(fullResult.getRequestId());
        summary.setStatus(fullResult.getStatus());
        summary.setOverallResult(fullResult.getOverallResult());
        summary.setVerificationTimestamp(fullResult.getVerificationTimestamp());
        summary.setHolder(fullResult.getHolder());

        List<VCVerificationResultDTO> vcResults = fullResult.getVcVerificationResults();
        if (vcResults != null) {
            summary.setTotalCredentials(vcResults.size());
            summary.setVerifiedCredentials((int) vcResults.stream()
                    .filter(VCVerificationResultDTO::isSuccess).count());
            summary.setFailedCredentials(summary.getTotalCredentials() - summary.getVerifiedCredentials());
        }

        return summary;
    }

    @Override
    public boolean isVerificationSuccessful(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPSubmissionNotFoundException, VPException {

        VPResultDTO result = getVPResult(transactionId, tenantId);
        return "SUCCESS".equals(result.getOverallResult());
    }

    @Override
    public String getHolderFromResult(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPSubmissionNotFoundException, VPException {

        VPResultDTO result = getVPResult(transactionId, tenantId);
        return result.getHolder();
    }

    /**
     * Build result for expired request.
     */
    private VPResultDTO buildExpiredResult(VPRequest request) {
        VPResultDTO result = new VPResultDTO();
        result.setTransactionId(request.getTransactionId());
        result.setRequestId(request.getRequestId());
        result.setStatus("EXPIRED");
        result.setOverallResult("FAILED");
        result.setError("request_expired");
        result.setErrorDescription("The VP request has expired");
        return result;
    }

    /**
     * Check if the token is a JWT format.
     */
    private boolean isJwtToken(String token) {
        if (token == null) {
            return false;
        }
        token = token.trim();
        // JWT has 3 parts separated by dots
        String[] parts = token.split("\\.");
        return parts.length == 3;
    }

    /**
     * Extract holder from VP token.
     */
    private String extractHolderFromVPToken(String vpToken) {
        if (isJwtToken(vpToken)) {
            return extractHolderFromJwtVP(vpToken);
        } else {
            return extractHolderFromJsonLdVP(vpToken);
        }
    }

    /**
     * Extract holder from JWT VP.
     */
    private String extractHolderFromJwtVP(String vpToken) {
        try {
            String[] parts = vpToken.split("\\.");
            if (parts.length >= 2) {
                String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
                JsonObject claims = GSON.fromJson(payload, JsonObject.class);

                // Try 'iss' claim first (holder is usually the issuer of VP)
                if (claims.has("iss")) {
                    return claims.get("iss").getAsString();
                }
                // Try 'sub' claim
                if (claims.has("sub")) {
                    return claims.get("sub").getAsString();
                }
                // Try nested 'vp.holder'
                if (claims.has("vp") && claims.get("vp").isJsonObject()) {
                    JsonObject vp = claims.getAsJsonObject("vp");
                    if (vp.has("holder")) {
                        return vp.get("holder").getAsString();
                    }
                }
            }
        } catch (Exception e) {
            log.debug("Failed to extract holder from JWT VP: " + e.getMessage());
        }
        return null;
    }

    /**
     * Extract holder from JSON-LD VP.
     */
    private String extractHolderFromJsonLdVP(String vpToken) {
        try {
            JsonObject vp = GSON.fromJson(vpToken, JsonObject.class);
            if (vp.has("holder")) {
                JsonElement holder = vp.get("holder");
                if (holder.isJsonPrimitive()) {
                    return holder.getAsString();
                } else if (holder.isJsonObject() && holder.getAsJsonObject().has("id")) {
                    return holder.getAsJsonObject().get("id").getAsString();
                }
            }
        } catch (Exception e) {
            log.debug("Failed to extract holder from JSON-LD VP: " + e.getMessage());
        }
        return null;
    }

    /**
     * Parse and verify JWT VP.
     */
    private List<VCVerificationResultDTO> parseAndVerifyJwtVP(String vpToken) throws VPException {
        List<VCVerificationResultDTO> results = new ArrayList<>();

        try {
            String[] parts = vpToken.split("\\.");
            if (parts.length < 2) {
                throw new VPException("Invalid JWT VP format");
            }

            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonObject claims = GSON.fromJson(payload, JsonObject.class);

            JsonArray credentials = null;

            // Try to find verifiableCredential in vp claim
            if (claims.has("vp") && claims.get("vp").isJsonObject()) {
                JsonObject vp = claims.getAsJsonObject("vp");
                if (vp.has("verifiableCredential")) {
                    credentials = vp.getAsJsonArray("verifiableCredential");
                }
            }
            // Try direct verifiableCredential claim
            if (credentials == null && claims.has("verifiableCredential")) {
                credentials = claims.getAsJsonArray("verifiableCredential");
            }

            if (credentials == null || credentials.size() == 0) {
                VCVerificationResultDTO result = new VCVerificationResultDTO.Builder()
                        .vcIndex(0)
                        .verificationStatus(VCVerificationStatus.INVALID)
                        .error("No verifiable credentials found in VP")
                        .build();
                results.add(result);
                return results;
            }

            // Verify each credential
            for (int i = 0; i < credentials.size(); i++) {
                JsonElement vcElement = credentials.get(i);
                VCVerificationResultDTO result = verifyCredential(i, vcElement);
                results.add(result);
            }

        } catch (Exception e) {
            log.error("Error parsing JWT VP", e);
            throw new VPException("Failed to parse JWT VP: " + e.getMessage());
        }

        return results;
    }

    /**
     * Parse and verify JSON-LD VP.
     */
    private List<VCVerificationResultDTO> parseAndVerifyJsonLdVP(String vpToken) throws VPException {
        List<VCVerificationResultDTO> results = new ArrayList<>();

        try {
            JsonObject vp = GSON.fromJson(vpToken, JsonObject.class);

            if (!vp.has("verifiableCredential")) {
                VCVerificationResultDTO result = new VCVerificationResultDTO.Builder()
                        .vcIndex(0)
                        .verificationStatus(VCVerificationStatus.INVALID)
                        .error("No verifiable credentials found in VP")
                        .build();
                results.add(result);
                return results;
            }

            JsonArray credentials = vp.getAsJsonArray("verifiableCredential");

            for (int i = 0; i < credentials.size(); i++) {
                JsonElement vcElement = credentials.get(i);
                VCVerificationResultDTO result = verifyCredential(i, vcElement);
                results.add(result);
            }

        } catch (Exception e) {
            log.error("Error parsing JSON-LD VP", e);
            throw new VPException("Failed to parse JSON-LD VP: " + e.getMessage());
        }

        return results;
    }

    /**
     * Verify a single credential and build result DTO.
     */
    private VCVerificationResultDTO verifyCredential(int index, JsonElement vcElement) {
        try {
            String vcString;
            String format;
            String contentType;

            if (vcElement.isJsonPrimitive()) {
                // JWT VC
                vcString = vcElement.getAsString();
                format = "jwt_vc";
                contentType = "application/jwt";
            } else {
                // JSON-LD VC
                vcString = GSON.toJson(vcElement);
                format = "ldp_vc";
                contentType = "application/vc+ld+json";
            }

            // Use verification service to verify the credential
            VerifiableCredential vc = vcVerificationService.parseCredential(vcString, contentType);
            log.info("[VC_VERIFICATION] Verifying credential index: " + index + ", ID: " + vc.getId() + ", Issuer: "
                    + vc.getIssuer());

            boolean signatureValid = vcVerificationService.verifySignature(vc);
            if (signatureValid) {
                log.info("[VC_VERIFICATION] Signature verification PASSED for credential: " + vc.getId());
            } else {
                log.error("[VC_VERIFICATION] Signature verification FAILED for credential: " + vc.getId());
            }

            boolean expired = vcVerificationService.isExpired(vc);
            if (!expired) {
                log.info("[VC_VERIFICATION] Expiration check PASSED for credential: " + vc.getId());
            } else {
                log.warn("[VC_VERIFICATION] Credential EXPIRED: " + vc.getId());
            }

            boolean revoked = vcVerificationService.isRevoked(vc);
            if (!revoked) {
                log.info("[VC_VERIFICATION] Revocation check PASSED for credential: " + vc.getId());
            } else {
                log.warn("[VC_VERIFICATION] Credential REVOKED: " + vc.getId());
            }

            VCVerificationStatus status;
            String error = null;

            if (!signatureValid) {
                status = VCVerificationStatus.INVALID;
                error = "Signature verification failed";
            } else if (expired) {
                status = VCVerificationStatus.EXPIRED;
                error = "Credential has expired";
            } else if (revoked) {
                status = VCVerificationStatus.REVOKED;
                error = "Credential has been revoked";
            } else {
                status = VCVerificationStatus.SUCCESS;
                log.info("[VC_VERIFICATION] Credential verification SUCCESSFUL for ID: " + vc.getId());
            }

            List<String> types = vc.getType();
            return new VCVerificationResultDTO.Builder()
                    .vcIndex(index)
                    .verificationStatus(status)
                    .format(format)
                    .credentialId(vc.getId())
                    .credentialType(types != null && !types.isEmpty() ? types.get(0) : null)
                    .credentialTypes(types != null ? types.toArray(new String[0]) : null)
                    .issuer(vc.getIssuer())
                    .issuerId(vc.getIssuer())
                    .subject(vc.getCredentialSubject() != null ? extractSubjectId(vc.getCredentialSubject()) : null)
                    .issuanceDate(formatDate(vc.getIssuanceDate()))
                    .expirationDate(formatDate(vc.getExpirationDate()))
                    .signatureValid(signatureValid)
                    .expired(expired)
                    .revoked(revoked)
                    .error(error)
                    .build();

        } catch (Exception e) {
            log.error("Error verifying credential at index " + index, e);
            return new VCVerificationResultDTO.Builder()
                    .vcIndex(index)
                    .verificationStatus(VCVerificationStatus.INVALID)
                    .error("Verification failed: " + e.getMessage())
                    .build();
        }
    }

    /**
     * Extract subject ID from credential subject.
     */
    private String extractSubjectId(Object credentialSubject) {
        if (credentialSubject == null) {
            return null;
        }

        try {
            if (credentialSubject instanceof String) {
                return (String) credentialSubject;
            }

            JsonElement element = GSON.toJsonTree(credentialSubject);
            if (element.isJsonObject()) {
                JsonObject obj = element.getAsJsonObject();
                if (obj.has("id")) {
                    return obj.get("id").getAsString();
                }
            }
        } catch (Exception e) {
            log.debug("Failed to extract subject ID: " + e.getMessage());
        }

        return null;
    }

    /**
     * Format a Date object to ISO 8601 string.
     */
    private String formatDate(java.util.Date date) {
        if (date == null) {
            return null;
        }
        java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        sdf.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        return sdf.format(date);
    }
}
