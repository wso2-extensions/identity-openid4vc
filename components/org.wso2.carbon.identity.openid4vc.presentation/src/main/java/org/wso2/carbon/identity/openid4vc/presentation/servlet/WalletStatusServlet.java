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
 * Servlet to check if VP token has been received for polling from the login page.
 */
public class WalletStatusServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(WalletStatusServlet.class);
    private static final String CONTENT_TYPE_JSON = "application/json";
    private static final String PARAM_STATE = "state";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType(CONTENT_TYPE_JSON + "; charset=UTF-8");

        try {
            String state = request.getParameter(PARAM_STATE);

            log.info("=== WalletStatusServlet.doGet called ===");
            log.info("    state parameter: " + state);

            if (state == null || state.trim().isEmpty()) {
                log.warn("Missing required parameter: state");
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "Missing required parameter: state");
                return;
            }

            // Check if token exists in cache (without removing it)
            boolean tokenReceived = WalletDataCache.getInstance().hasToken(state);

            log.info("    Token received for state " + state + ": " + tokenReceived);

            if (log.isDebugEnabled()) {
                log.debug("Status check for state " + state + ": " +
                    (tokenReceived ? "token received" : "waiting"));
            }

            // Send status response
            sendStatusResponse(response, tokenReceived);

        } catch (Exception e) {
            log.error("Error checking wallet status", e);
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "Internal server error");
        }
    }

    /**
     * Send status response.
     */
    private void sendStatusResponse(HttpServletResponse response, boolean tokenReceived)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_OK);

        JsonObject jsonResponse = new JsonObject();
        jsonResponse.addProperty("status", "success");
        jsonResponse.addProperty("tokenReceived", tokenReceived);

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

