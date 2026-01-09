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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPRequestExpiredException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPSubmissionService;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.VPSubmissionServiceImpl;

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
    private static final Log log = LogFactory.getLog(VPSubmissionServlet.class);
    
    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .create();
    
    private static final int DEFAULT_TENANT_ID = -1234;

    private VPSubmissionService vpSubmissionService;

    @Override
    public void init() throws ServletException {
        super.init();
        this.vpSubmissionService = new VPSubmissionServiceImpl();
    }

    /**
     * Handle POST requests - VP submission from wallet.
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        if (log.isDebugEnabled()) {
            log.debug("Received VP submission from wallet");
        }

        try {
            // Parse submission parameters
            VPSubmissionDTO submissionDTO = parseSubmission(request);

            // Validate state parameter
            if (StringUtils.isBlank(submissionDTO.getState())) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        "invalid_request", "state parameter is required");
                return;
            }

            // Validate submission - either (vp_token + submission) OR error must be present
            if (!isValidSubmission(submissionDTO)) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        "invalid_request", 
                        "Either (vp_token, presentation_submission) or error is required");
                return;
            }

            // Get tenant ID
            int tenantId = getTenantId(request);

            // Process submission
            VPSubmission submission = vpSubmissionService.processVPSubmission(
                    submissionDTO, tenantId);

            // Send success response
            // Per OpenID4VP spec, response can include redirect_uri if applicable
            sendSuccessResponse(response, submission);

            if (log.isDebugEnabled()) {
                log.debug("Processed VP submission: " + submission.getSubmissionId());
            }

        } catch (VPRequestNotFoundException e) {
            log.warn("VP submission for unknown request: " + e.getMessage());
            sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND,
                    "invalid_request", "Request not found: " + e.getMessage());
        } catch (VPRequestExpiredException e) {
            log.warn("VP submission for expired request: " + e.getMessage());
            sendErrorResponse(response, HttpServletResponse.SC_GONE,
                    "expired_request", e.getMessage());
        } catch (VPException e) {
            log.error("Error processing VP submission", e);
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "invalid_request", e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error processing VP submission", e);
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "server_error", "Internal server error");
        }
    }

    /**
     * Parse submission from request parameters.
     * Handles application/x-www-form-urlencoded content type.
     */
    private VPSubmissionDTO parseSubmission(HttpServletRequest request) throws IOException {
        VPSubmissionDTO dto = new VPSubmissionDTO();
        
        String contentType = request.getContentType();
        
        if (contentType != null && contentType.contains(OpenID4VPConstants.HTTP.CONTENT_TYPE_FORM)) {
            // Standard form-encoded parameters
            dto.setVpToken(getDecodedParameter(request, OpenID4VPConstants.ResponseParams.VP_TOKEN));
            String presSubStr = getDecodedParameter(request, 
                    OpenID4VPConstants.ResponseParams.PRESENTATION_SUBMISSION);
            if (StringUtils.isNotBlank(presSubStr)) {
                dto.setPresentationSubmission(
                        com.google.gson.JsonParser.parseString(presSubStr).getAsJsonObject());
            }
            dto.setState(getDecodedParameter(request, OpenID4VPConstants.ResponseParams.STATE));
            dto.setError(getDecodedParameter(request, OpenID4VPConstants.ResponseParams.ERROR));
            dto.setErrorDescription(getDecodedParameter(request, 
                    OpenID4VPConstants.ResponseParams.ERROR_DESCRIPTION));
        } else if (contentType != null && contentType.contains(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON)) {
            // JSON body - some wallets may send JSON
            String body = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            dto = gson.fromJson(body, VPSubmissionDTO.class);
        } else {
            // Try form parameters as fallback
            dto.setVpToken(request.getParameter(OpenID4VPConstants.ResponseParams.VP_TOKEN));
            String presSubStr = request.getParameter(
                    OpenID4VPConstants.ResponseParams.PRESENTATION_SUBMISSION);
            if (StringUtils.isNotBlank(presSubStr)) {
                dto.setPresentationSubmission(
                        com.google.gson.JsonParser.parseString(presSubStr).getAsJsonObject());
            }
            dto.setState(request.getParameter(OpenID4VPConstants.ResponseParams.STATE));
            dto.setError(request.getParameter(OpenID4VPConstants.ResponseParams.ERROR));
            dto.setErrorDescription(request.getParameter(
                    OpenID4VPConstants.ResponseParams.ERROR_DESCRIPTION));
        }
        
        return dto;
    }

    /**
     * Get URL-decoded parameter value.
     */
    private String getDecodedParameter(HttpServletRequest request, String paramName) {
        String value = request.getParameter(paramName);
        if (StringUtils.isNotBlank(value)) {
            try {
                return URLDecoder.decode(value, StandardCharsets.UTF_8.name());
            } catch (Exception e) {
                return value;
            }
        }
        return value;
    }

    /**
     * Validate that submission has required fields.
     */
    private boolean isValidSubmission(VPSubmissionDTO dto) {
        // Either error OR (vp_token + presentation_submission) must be present
        if (StringUtils.isNotBlank(dto.getError())) {
            return true; // Error response is valid
        }
        
        // For success, vp_token is required
        // presentation_submission may be optional for some formats
        return StringUtils.isNotBlank(dto.getVpToken());
    }

    /**
     * Send success response to wallet.
     */
    private void sendSuccessResponse(HttpServletResponse response, VPSubmission submission)
            throws IOException {
        
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON + ";charset=UTF-8");
        
        // Build response object
        JsonObject responseObj = new JsonObject();
        responseObj.addProperty("status", "received");
        responseObj.addProperty("submission_id", submission.getSubmissionId());
        
        // If there's a redirect_uri configured, include it
        // responseObj.addProperty("redirect_uri", redirectUri);
        
        try (PrintWriter writer = response.getWriter()) {
            writer.write(gson.toJson(responseObj));
        }
    }

    /**
     * Send error response per OAuth 2.0 spec.
     */
    private void sendErrorResponse(HttpServletResponse response, int statusCode,
                                    String errorCode, String errorDescription) 
            throws IOException {
        
        response.setStatus(statusCode);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON + ";charset=UTF-8");
        
        JsonObject errorObj = new JsonObject();
        errorObj.addProperty("error", errorCode);
        if (StringUtils.isNotBlank(errorDescription)) {
            errorObj.addProperty("error_description", errorDescription);
        }
        
        try (PrintWriter writer = response.getWriter()) {
            writer.write(gson.toJson(errorObj));
        }
    }

    /**
     * Get tenant ID from request context.
     */
    private int getTenantId(HttpServletRequest request) {
        String tenantHeader = request.getHeader("X-Tenant-Id");
        if (StringUtils.isNotBlank(tenantHeader)) {
            try {
                return Integer.parseInt(tenantHeader);
            } catch (NumberFormatException e) {
                // Fall through to default
            }
        }
        return DEFAULT_TENANT_ID;
    }
}
