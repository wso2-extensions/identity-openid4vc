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

package org.wso2.carbon.identity.openid4vc.presentation.servlet;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.cache.VPStatusListenerCache;
import org.wso2.carbon.identity.openid4vc.presentation.cache.WalletDataCache;
import org.wso2.carbon.identity.openid4vc.presentation.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.CredentialVerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPRequestExpiredException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPSubmissionValidationException;
import org.wso2.carbon.identity.openid4vc.presentation.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.service.VCVerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPSubmissionService;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.VPSubmissionServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.status.StatusNotificationService;
import org.wso2.carbon.identity.openid4vc.presentation.util.OpenID4VPLogger;
import org.wso2.carbon.identity.openid4vc.presentation.util.VPSubmissionValidator;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet handling VP (Verifiable Presentation) submissions from wallets.
 * Implements the OpenID4VP direct_post response mode.
 * 
 * Endpoint:
 * - POST /openid4vp/v1/response - Receive VP submission from wallet
 * 
 * The wallet submits via application/x-www-form-urlencoded with:
 * - vp_token: The VP token (JWT or JSON-LD)
 * - presentation_submission: JSON describing which credentials satisfy the
 * request
 * - state: The request ID (used as correlation)
 * - error: (Optional) Error code if wallet declined or failed
 * - error_description: (Optional) Error description
 */
public class VPSubmissionServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Log LOG = LogFactory.getLog(VPSubmissionServlet.class);

    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .create();

    private static final int DEFAULT_TENANT_ID = -1234;

    /**
     * VP Submission service instance.
     */
    private VPSubmissionService vpSubmissionService;

    /**
     * Status listener cache for long polling notifications.
     */
    private VPStatusListenerCache statusListenerCache;

    /**
     * Status notification service for coordinated notifications.
     */
    private StatusNotificationService statusNotificationService;

    /**
     * Wallet data cache for storing submissions.
     */
    private WalletDataCache walletDataCache;

    @Override
    public void init() throws ServletException {

        super.init();
        this.vpSubmissionService = new VPSubmissionServiceImpl();
        this.statusListenerCache = VPStatusListenerCache.getInstance();
        this.statusNotificationService = StatusNotificationService.getInstance();
        this.walletDataCache = WalletDataCache.getInstance();
    }

    /**
     * Handle POST requests - VP submission from wallet.
     *
     * @param request  HTTP request
     * @param response HTTP response
     * @throws ServletException If servlet error occurs
     * @throws IOException      If I/O error occurs
     */
    @Override
    protected void doPost(final HttpServletRequest request,
            final HttpServletResponse response)
            throws ServletException, IOException {

        LOG.info("========== VP SUBMISSION SERVLET CALLED ==========");
        LOG.info("Request URI: " + request.getRequestURI());
        LOG.info("Request URL: " + request.getRequestURL());
        LOG.info("Context Path: " + request.getContextPath());
        LOG.info("Servlet Path: " + request.getServletPath());
        LOG.info("==================================================");

        if (LOG.isDebugEnabled()) {
            LOG.debug("Received VP submission from wallet");
        }

        try {
            // Parse submission parameters
            VPSubmissionDTO submissionDTO = parseSubmission(request);

            // Validate submission using enhanced validator
            try {
                VPSubmissionValidator.validateSubmission(submissionDTO);
            } catch (VPSubmissionValidationException e) {
                LOG.warn("VP submission validation failed: " + e.getMessage());
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        OpenID4VPConstants.ErrorCodes.INVALID_REQUEST,
                        e.getMessage());
                return;
            }

            // Get tenant domain and verify all VCs in the VP
            String tenantDomain = getTenantDomain(request);
            
            // Verify issuer trust for all credentials before processing
            try {
                verifyAllCredentialIssuers(submissionDTO.getVpToken(), tenantDomain);
            } catch (CredentialVerificationException e) {
                LOG.error("Credential issuer verification failed: " + e.getMessage());
                sendErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                        "untrusted_issuer",
                        "Credential from untrusted issuer: " + e.getMessage());
                return;
            }

            // Get tenant ID
            int tenantId = getTenantId(request);

            // Process submission
            VPSubmission submission = vpSubmissionService.processVPSubmission(
                    submissionDTO, tenantId);

            LOG.info("[VP_SUBMISSION_SERVLET] VP submission processed, notifying status listeners...");
            // Notify status listeners for long polling
            notifyStatusListeners(submissionDTO.getState(), submission);
            LOG.info("[VP_SUBMISSION_SERVLET] Status listeners notified");

            LOG.info("[VP_SUBMISSION_SERVLET] Sending success response to wallet...");
            // Send success response
            sendSuccessResponse(response, submission);
            LOG.info("[VP_SUBMISSION_SERVLET] Success response sent to wallet");

            LOG.info("[VP_SUBMISSION_SERVLET] ========== VP SUBMISSION SERVLET COMPLETED SUCCESSFULLY ==========");
            LOG.info("[VP_SUBMISSION_SERVLET] Submission ID: " + submission.getSubmissionId());
            LOG.info("[VP_SUBMISSION_SERVLET] Request ID: " + submissionDTO.getState());
            LOG.info(
                    "[VP_SUBMISSION_SERVLET] ============================================================================");

        } catch (VPRequestNotFoundException e) {
            LOG.warn("VP submission for unknown request: " + e.getMessage());
            sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND,
                    OpenID4VPConstants.ErrorCodes.INVALID_REQUEST,
                    "Request not found: " + e.getRequestId());
        } catch (VPRequestExpiredException e) {
            LOG.warn("VP submission for expired request: " + e.getMessage());
            sendErrorResponse(response, HttpServletResponse.SC_GONE,
                    "expired_request", e.getMessage());
        } catch (VPException e) {
            LOG.error("Error processing VP submission", e);
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    OpenID4VPConstants.ErrorCodes.INVALID_REQUEST, e.getMessage());
        } catch (Exception e) {
            LOG.error("Unexpected error processing VP submission", e);
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    OpenID4VPConstants.ErrorCodes.SERVER_ERROR, "Internal server error");
        }
    }

    /**
     * Parse submission from request parameters.
     * Handles application/x-www-form-urlencoded and JSON content types.
     *
     * @param request HTTP request
     * @return Parsed VPSubmissionDTO
     * @throws IOException If parsing fails
     */
    private VPSubmissionDTO parseSubmission(final HttpServletRequest request)
            throws IOException {

        VPSubmissionDTO dto = new VPSubmissionDTO();
        String contentType = request.getContentType();

        if (contentType != null
                && contentType.contains(OpenID4VPConstants.HTTP.CONTENT_TYPE_FORM)) {
            // Standard form-encoded parameters (per OpenID4VP spec)
            parseFormEncodedSubmission(request, dto);
        } else if (contentType != null
                && contentType.contains(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON)) {
            // JSON body - some wallets may send JSON
            dto = parseJsonSubmission(request);
        } else {
            // Try form parameters as fallback
            parseFormEncodedSubmission(request, dto);
        }

        return dto;
    }

    /**
     * Parse form-encoded submission.
     *
     * @param request HTTP request
     * @param dto     DTO to populate
     */
    private void parseFormEncodedSubmission(final HttpServletRequest request,
            final VPSubmissionDTO dto) {

        dto.setVpToken(getDecodedParameter(request,
                OpenID4VPConstants.ResponseParams.VP_TOKEN));

        String presSubStr = getDecodedParameter(request,
                OpenID4VPConstants.ResponseParams.PRESENTATION_SUBMISSION);
        if (StringUtils.isNotBlank(presSubStr)) {
            try {
                dto.setPresentationSubmission(
                        JsonParser.parseString(presSubStr).getAsJsonObject());
            } catch (JsonSyntaxException e) {
                LOG.warn("Failed to parse presentation_submission: "
                        + e.getMessage());
            }
        }

        dto.setState(getDecodedParameter(request,
                OpenID4VPConstants.ResponseParams.STATE));
        dto.setError(getDecodedParameter(request,
                OpenID4VPConstants.ResponseParams.ERROR));
        dto.setErrorDescription(getDecodedParameter(request,
                OpenID4VPConstants.ResponseParams.ERROR_DESCRIPTION));
    }

    /**
     * Parse JSON submission body.
     *
     * @param request HTTP request
     * @return Parsed DTO
     * @throws IOException If reading fails
     */
    private VPSubmissionDTO parseJsonSubmission(final HttpServletRequest request)
            throws IOException {

        String body = new String(request.getInputStream().readAllBytes(),
                StandardCharsets.UTF_8);
        return GSON.fromJson(body, VPSubmissionDTO.class);
    }

    /**
     * Get URL-decoded parameter value.
     *
     * @param request   HTTP request
     * @param paramName Parameter name
     * @return Decoded value or original if decoding fails
     */
    private String getDecodedParameter(final HttpServletRequest request,
            final String paramName) {

        String value = request.getParameter(paramName);
        if (StringUtils.isNotBlank(value)) {
            try {
                return URLDecoder.decode(value, StandardCharsets.UTF_8.name());
            } catch (Exception e) {
                LOG.debug("Failed to decode parameter " + paramName + ": " + e.getMessage());
                return value;
            }
        }
        return value;
    }

    /**
     * Notify status listeners for long polling.
     *
     * @param requestId  The request ID (state)
     * @param submission The VP submission
     */
    private void notifyStatusListeners(final String requestId,
            final VPSubmission submission) {

        LOG.info("[VP_NOTIFICATION] ========== Notifying Status Listeners ==========");
        LOG.info("[VP_NOTIFICATION] Request ID: " + requestId);
        LOG.info("[VP_NOTIFICATION] Submission ID: " + submission.getSubmissionId());
        LOG.info("[VP_NOTIFICATION] Has Error: " + (StringUtils.isNotBlank(submission.getError())));

        if (StringUtils.isBlank(requestId)) {
            LOG.warn("[VP_NOTIFICATION] Request ID is blank, skipping notification");
            return;
        }

        // Store submission in wallet data cache for status checks
        if (walletDataCache != null) {
            LOG.info("[VP_NOTIFICATION] Storing submission in wallet data cache...");
            walletDataCache.storeSubmission(requestId, submission);
            LOG.info("[VP_NOTIFICATION] Submission stored in cache");
        } else {
            LOG.warn("[VP_NOTIFICATION] Wallet data cache is null");
        }

        // Use the centralized notification service
        if (statusNotificationService != null) {
            LOG.info("[VP_NOTIFICATION] Using centralized notification service");
            if (StringUtils.isNotBlank(submission.getError())) {
                LOG.info("[VP_NOTIFICATION] Notifying submission error: " + submission.getError());
                statusNotificationService.notifySubmissionError(
                        requestId,
                        submission.getError(),
                        submission.getErrorDescription());
            } else {
                LOG.info("[VP_NOTIFICATION] Notifying VP submitted successfully");
                statusNotificationService.notifyVPSubmitted(requestId, submission);
            }
            LOG.info("[VP_NOTIFICATION] Centralized notification completed");
        } else if (statusListenerCache != null) {
            // Fallback to direct notification
            LOG.info("[VP_NOTIFICATION] Using fallback status listener cache");
            String status;
            if (StringUtils.isNotBlank(submission.getError())) {
                status = VPRequestStatus.VP_SUBMITTED.name() + "_ERROR";
            } else {
                status = VPRequestStatus.VP_SUBMITTED.name();
            }
            LOG.info("[VP_NOTIFICATION] Notifying listeners with status: " + status);
            statusListenerCache.notifyListeners(requestId, status);
            LOG.info("[VP_NOTIFICATION] Fallback notification completed");
        } else {
            LOG.error("[VP_NOTIFICATION] Both statusNotificationService and statusListenerCache are null!");
        }

        LOG.info("[VP_NOTIFICATION] ========== Status Listeners Notified ==========");
    }

    /**
     * Send success response to wallet.
     *
     * @param response   HTTP response
     * @param submission The processed submission
     * @throws IOException If writing fails
     */
    private void sendSuccessResponse(final HttpServletResponse response,
            final VPSubmission submission)
            throws IOException {

        LOG.info("[VP_RESPONSE] Building success response for wallet...");
        LOG.info("[VP_RESPONSE] Submission ID: " + submission.getSubmissionId());
        LOG.info("[VP_RESPONSE] Transaction ID: " + submission.getTransactionId());

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON
                + ";charset=UTF-8");

        // Build response object per OpenID4VP spec
        JsonObject responseObj = new JsonObject();
        responseObj.addProperty("status", "received");
        responseObj.addProperty("submission_id", submission.getSubmissionId());

        // Add transaction ID if present for tracking
        if (submission.getTransactionId() != null) {
            responseObj.addProperty("transaction_id", submission.getTransactionId());
        }

        String responseJson = GSON.toJson(responseObj);
        LOG.info("[VP_RESPONSE] Response JSON: " + responseJson);

        try (PrintWriter writer = response.getWriter()) {
            writer.write(responseJson);
        }

        LOG.info("[VP_RESPONSE] Success response sent to wallet (HTTP 200)");
    }

    /**
     * Send error response per OAuth 2.0 spec.
     *
     * @param response         HTTP response
     * @param statusCode       HTTP status code
     * @param errorCode        Error code
     * @param errorDescription Error description
     * @throws IOException If writing fails
     */
    private void sendErrorResponse(final HttpServletResponse response,
            final int statusCode,
            final String errorCode,
            final String errorDescription)
            throws IOException {

        response.setStatus(statusCode);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON
                + ";charset=UTF-8");

        JsonObject errorObj = new JsonObject();
        errorObj.addProperty("error", errorCode);
        if (StringUtils.isNotBlank(errorDescription)) {
            errorObj.addProperty("error_description", errorDescription);
        }

        try (PrintWriter writer = response.getWriter()) {
            writer.write(GSON.toJson(errorObj));
        }
    }

    /**
     * Get tenant ID from request context.
     *
     * @param request HTTP request
     * @return Tenant ID
     */
    private int getTenantId(final HttpServletRequest request) {

        String tenantHeader = request.getHeader("X-Tenant-Id");
        if (StringUtils.isNotBlank(tenantHeader)) {
            try {
                return Integer.parseInt(tenantHeader);
            } catch (NumberFormatException e) {
                LOG.debug("Invalid tenant ID header: " + tenantHeader);
            }
        }
        return DEFAULT_TENANT_ID;
    }

    /**
     * Get tenant domain from request context.
     *
     * @param request HTTP request
     * @return Tenant domain
     */
    private String getTenantDomain(final HttpServletRequest request) {
        String tenantDomain = request.getHeader("X-Tenant-Domain");
        if (StringUtils.isNotBlank(tenantDomain)) {
            return tenantDomain;
        }
        return "carbon.super";
    }

    /**
     * Verify all credential issuers in the VP token.
     * Extracts all VCs from the VP and verifies each issuer against the trusted allowlist.
     *
     * @param vpToken      The VP token (JWT or JSON-LD)
     * @param tenantDomain The tenant domain
     * @throws CredentialVerificationException If any credential is from untrusted issuer
     */
    private void verifyAllCredentialIssuers(String vpToken, String tenantDomain)
            throws CredentialVerificationException {

        if (StringUtils.isBlank(vpToken)) {
            LOG.warn("VP token is blank, skipping issuer verification");
            return;
        }

        OpenID4VPLogger.logVPSubmissionStart(LOG);

        try {
            VCVerificationService vcVerifier = VPServiceDataHolder.getInstance()
                    .getVCVerificationService();

            // Determine if VP is JWT or JSON-LD
            JsonObject vp;
            if (vpToken.contains(".")) {
                // JWT VP - decode payload
                String[] parts = vpToken.split("\\.");
                if (parts.length >= 2) {
                    String payloadJson = new String(
                            java.util.Base64.getUrlDecoder().decode(parts[1]),
                            java.nio.charset.StandardCharsets.UTF_8);
                    vp = JsonParser.parseString(payloadJson).getAsJsonObject();
                    OpenID4VPLogger.logVPTokenFormat(LOG, "JWT");
                } else {
                    throw new CredentialVerificationException(
                            org.wso2.carbon.identity.openid4vc.presentation.model.VCVerificationStatus.INVALID,
                            "Invalid JWT VP format");
                }
            } else {
                // JSON-LD VP
                vp = JsonParser.parseString(vpToken).getAsJsonObject();
                OpenID4VPLogger.logVPTokenFormat(LOG, "JSON-LD");
            }

            // Extract verifiable credentials array
            if (!vp.has("verifiableCredential") && !vp.has("vp")) {
                LOG.warn("No verifiableCredential field in VP, skipping issuer verification");
                return;
            }

            JsonElement vcElement = vp.has("verifiableCredential") 
                    ? vp.get("verifiableCredential")
                    : vp.getAsJsonObject("vp").get("verifiableCredential");

            JsonArray verifiableCredentials;
            if (vcElement.isJsonArray()) {
                verifiableCredentials = vcElement.getAsJsonArray();
            } else {
                // Single credential - wrap in array
                verifiableCredentials = new JsonArray();
                verifiableCredentials.add(vcElement);
            }

            int credentialCount = verifiableCredentials.size();
            OpenID4VPLogger.logCredentialCount(LOG, credentialCount);

            // Verify each VC
            for (int i = 0; i < credentialCount; i++) {
                OpenID4VPLogger.logCredentialIndex(LOG, i + 1, credentialCount);

                JsonElement vcElem = verifiableCredentials.get(i);

                if (vcElem.isJsonPrimitive() && vcElem.getAsString().contains(".")) {
                    // JWT VC
                    String vcJwt = vcElem.getAsString();
                    OpenID4VPLogger.logCredentialType(LOG, "JWT");

                    boolean verified = vcVerifier.verifyJWTVCIssuer(vcJwt, tenantDomain);
                    if (!verified) {
                        OpenID4VPLogger.logCredentialVerificationFailed(LOG, i + 1,
                                "Issuer verification failed");
                        throw new CredentialVerificationException(
                                org.wso2.carbon.identity.openid4vc.presentation.model.VCVerificationStatus.INVALID,
                                "Credential " + (i + 1) + " from untrusted issuer");
                    }
                    OpenID4VPLogger.logCredentialVerificationSuccess(LOG, i + 1,
                            extractIssuerFromJWT(vcJwt), "JWT");

                } else if (vcElem.isJsonObject()) {
                    // JSON-LD VC
                    JsonObject vcObj = vcElem.getAsJsonObject();
                    OpenID4VPLogger.logCredentialType(LOG, "JSON-LD");

                    boolean verified = vcVerifier.verifyJSONLDVCIssuer(vcObj, tenantDomain);
                    if (!verified) {
                        OpenID4VPLogger.logCredentialVerificationFailed(LOG, i + 1,
                                "Issuer verification failed");
                        throw new CredentialVerificationException(
                                org.wso2.carbon.identity.openid4vc.presentation.model.VCVerificationStatus.INVALID,
                                "Credential " + (i + 1) + " from untrusted issuer");
                    }

                    String issuer = extractIssuerFromJsonLD(vcObj);
                    OpenID4VPLogger.logCredentialVerificationSuccess(LOG, i + 1, issuer, "JSON-LD");
                }
            }

            OpenID4VPLogger.logAllCredentialsVerified(LOG, credentialCount);
            OpenID4VPLogger.logVPVerificationComplete(LOG);

        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("Error verifying credential issuers: " + e.getMessage(), e);
            throw new CredentialVerificationException(
                    "Failed to verify credential issuers: " + e.getMessage(), e);
        }
    }

    /**
     * Extract issuer from JWT VC.
     *
     * @param vcJwt JWT VC token
     * @return Issuer DID
     */
    private String extractIssuerFromJWT(String vcJwt) {
        try {
            String[] parts = vcJwt.split("\\.");
            if (parts.length >= 2) {
                String payloadJson = new String(
                        java.util.Base64.getUrlDecoder().decode(parts[1]),
                        java.nio.charset.StandardCharsets.UTF_8);
                JsonObject payload = JsonParser.parseString(payloadJson).getAsJsonObject();
                return payload.get("iss").getAsString();
            }
        } catch (Exception e) {
            LOG.debug("Failed to extract issuer from JWT: " + e.getMessage());
        }
        return "unknown";
    }

    /**
     * Extract issuer from JSON-LD VC.
     *
     * @param vcObj JSON-LD VC object
     * @return Issuer DID
     */
    private String extractIssuerFromJsonLD(JsonObject vcObj) {
        try {
            if (vcObj.has("issuer")) {
                JsonElement issuer = vcObj.get("issuer");
                if (issuer.isJsonPrimitive()) {
                    return issuer.getAsString();
                } else if (issuer.isJsonObject()) {
                    return issuer.getAsJsonObject().get("id").getAsString();
                }
            }
        } catch (Exception e) {
            LOG.debug("Failed to extract issuer from JSON-LD: " + e.getMessage());
        }
        return "unknown";
    }
}
