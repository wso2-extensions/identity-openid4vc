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
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPRequestExpiredException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPSubmissionValidationException;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPSubmissionService;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.VPSubmissionServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.status.StatusNotificationService;
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
 * - POST /api/identity/openid4vp/v1/vp-response - Receive VP submission from wallet
 * 
 * The wallet submits via application/x-www-form-urlencoded with:
 * - vp_token: The VP token (JWT or JSON-LD)
 * - presentation_submission: JSON describing which credentials satisfy the request
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

            // Get tenant ID
            int tenantId = getTenantId(request);

            // Process submission
            VPSubmission submission = vpSubmissionService.processVPSubmission(
                    submissionDTO, tenantId);

            // Notify status listeners for long polling
            notifyStatusListeners(submissionDTO.getState(), submission);

            // Send success response
            sendSuccessResponse(response, submission);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Processed VP submission: " + submission.getSubmissionId()
                        + " for request: " + submissionDTO.getState());
            }

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

        if (StringUtils.isBlank(requestId)) {
            return;
        }

        // Store submission in wallet data cache for status checks
        if (walletDataCache != null) {
            walletDataCache.storeSubmission(requestId, submission);
        }

        // Use the centralized notification service
        if (statusNotificationService != null) {
            if (StringUtils.isNotBlank(submission.getError())) {
                statusNotificationService.notifySubmissionError(
                        requestId,
                        submission.getError(),
                        submission.getErrorDescription());
            } else {
                statusNotificationService.notifyVPSubmitted(requestId, submission);
            }
        } else if (statusListenerCache != null) {
            // Fallback to direct notification
            String status;
            if (StringUtils.isNotBlank(submission.getError())) {
                status = VPRequestStatus.VP_SUBMITTED.name() + "_ERROR";
            } else {
                status = VPRequestStatus.VP_SUBMITTED.name();
            }
            statusListenerCache.notifyListeners(requestId, status);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Notified status listeners for request: " + requestId);
        }
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

        try (PrintWriter writer = response.getWriter()) {
            writer.write(GSON.toJson(responseObj));
        }
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
}
