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

import com.google.gson.JsonObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.cache.WalletDataCache;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet endpoint to receive VP token from wallet callback.
 */
public class WalletResponseServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(WalletResponseServlet.class);
    private static final String CONTENT_TYPE_JSON = "application/json";
    private static final String PARAM_VP_TOKEN = "vp_token";
    private static final String PARAM_STATE = "state";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {

        response.setContentType(CONTENT_TYPE_JSON + "; charset=UTF-8");

        try {
            // Extract parameters
            String vpToken = request.getParameter(PARAM_VP_TOKEN);
            String state = request.getParameter(PARAM_STATE);

            if (log.isDebugEnabled()) {
                log.debug("Received wallet callback - state: " + state +
                         ", vpToken present: " + (vpToken != null && !vpToken.trim().isEmpty()));
            }

            // Validate required parameters
            if (vpToken == null || vpToken.trim().isEmpty()) {
                log.warn("Missing or empty vp_token parameter");
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "Missing required parameter: vp_token");
                return;
            }

            if (state == null || state.trim().isEmpty()) {
                log.warn("Missing or empty state parameter");
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "Missing required parameter: state");
                return;
            }

            // Store token in cache
            WalletDataCache.getInstance().storeToken(state, vpToken);

            if (log.isDebugEnabled()) {
                log.debug("Successfully stored VP token for state: " + state);
            }

            log.info("VP token received and stored for state: " + state);

            // Send success response
            sendSuccessResponse(response);

        } catch (Exception e) {
            log.error("Error processing wallet callback", e);
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "Internal server error processing request");
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType(CONTENT_TYPE_JSON + "; charset=UTF-8");
        sendErrorResponse(response, HttpServletResponse.SC_METHOD_NOT_ALLOWED,
            "GET method not supported. Use POST.");
    }

    /**
     * Send success JSON response.
     */
    private void sendSuccessResponse(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_OK);

        JsonObject jsonResponse = new JsonObject();
        jsonResponse.addProperty("status", "success");
        jsonResponse.addProperty("message", "Token received");

        try (PrintWriter out = response.getWriter()) {
            out.print(jsonResponse.toString());
            out.flush();
        }
    }

    /**
     * Send error JSON response.
     */
    private void sendErrorResponse(HttpServletResponse response, int statusCode, String message)
            throws IOException {
        response.setStatus(statusCode);

        JsonObject jsonResponse = new JsonObject();
        jsonResponse.addProperty("status", "error");
        jsonResponse.addProperty("message", message);

        try (PrintWriter out = response.getWriter()) {
            out.print(jsonResponse.toString());
            out.flush();
        }
    }
}

