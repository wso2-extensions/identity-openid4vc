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
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.dto.ErrorDTO;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPSubmissionNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPResultService;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.VPResultServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.util.CORSUtil;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet for retrieving VP verification results.
 * 
 * Endpoints:
 * - GET /openid4vp/v1/vp-result/{transactionId} - Get full verification results
 * - GET /openid4vp/v1/vp-result/{transactionId}/summary - Get result summary
 * 
 * This endpoint is called by the relying party to retrieve the verification
 * results for a submitted VP. The transaction ID was provided when creating
 * the VP authorization request.
 */
public class VPResultServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    private static final int DEFAULT_TENANT_ID = -1234;

    private VPResultService vpResultService;

    @Override
    public void init() throws ServletException {
        super.init();

        this.vpResultService = new VPResultServiceImpl();
    }

    /**
     * Handle GET requests - Retrieve VP verification results.
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Parse transaction ID from path
        String pathInfo = request.getPathInfo();

        if (StringUtils.isBlank(pathInfo) || "/".equals(pathInfo)) {
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_TRANSACTION_ID, "Transaction ID is required");
            return;
        }

        String[] pathParts = pathInfo.substring(1).split("/");
        String transactionId = pathParts[0];
        boolean isSummary = pathParts.length > 1 && "summary".equals(pathParts[1]);

        int tenantId = getTenantId(request);

        try {
            if (isSummary) {
                // Get summary result
                VPResultService.VPResultSummaryDTO summaryDTO = vpResultService.getVPResultSummary(transactionId,
                        tenantId);
                sendJsonResponse(request, response, HttpServletResponse.SC_OK, summaryDTO);
            } else {
                // Get full verification result using enhanced service
                VPResultDTO resultDTO = vpResultService.getVPResult(transactionId, tenantId);
                sendJsonResponse(request, response, HttpServletResponse.SC_OK, resultDTO);
            }

        } catch (VPRequestNotFoundException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_NOT_FOUND,
                    ErrorDTO.ErrorCode.VP_REQUEST_NOT_FOUND,
                    "Transaction not found: " + transactionId);
        } catch (VPSubmissionNotFoundException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_NOT_FOUND,
                    ErrorDTO.ErrorCode.VP_SUBMISSION_NOT_FOUND,
                    "No submission found for transaction: " + transactionId);
        } catch (VPException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, e.getMessage());
        } catch (RuntimeException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorDTO.ErrorCode.INTERNAL_ERROR, "Internal server error");
        }
    }

    /**
     * Handle OPTIONS requests for CORS preflight.
     */
    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        CORSUtil.handlePreflight(request, response);
    }

    /**
     * Send JSON response.
     */
    private void sendJsonResponse(HttpServletRequest request, HttpServletResponse response,
            int statusCode, Object data)
            throws IOException {

        response.setStatus(statusCode);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON + ";charset=UTF-8");
        CORSUtil.addCORSHeaders(request, response);

        try (PrintWriter writer = response.getWriter()) {
            writer.write(gson.toJson(data));
        }
    }

    /**
     * Send error response.
     */
    private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
            int statusCode, ErrorDTO.ErrorCode errorCode, String message)
            throws IOException {

        ErrorDTO errorDTO = new ErrorDTO(errorCode, message, null);
        sendJsonResponse(request, response, statusCode, errorDTO);
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
