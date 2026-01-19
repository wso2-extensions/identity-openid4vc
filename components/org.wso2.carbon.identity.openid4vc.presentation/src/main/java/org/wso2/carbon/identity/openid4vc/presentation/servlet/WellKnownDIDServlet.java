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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.exception.DIDDocumentException;
import org.wso2.carbon.identity.openid4vc.presentation.service.DIDDocumentService;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.DIDDocumentServiceImpl;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet handling the /.well-known/did.json endpoint.
 * Serves the DID Document for WSO2 Identity Server using did:web method.
 * 
 * Endpoint:
 * - GET /.well-known/did.json - Returns the DID Document
 * 
 * The DID will be: did:web:{domain} where domain is extracted from the request.
 * For example:
 * - https://example.com/.well-known/did.json → did:web:example.com
 * - https://localhost:9443/.well-known/did.json → did:web:localhost%3A9443
 */
public class WellKnownDIDServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Log LOG = LogFactory.getLog(WellKnownDIDServlet.class);

    private static final int DEFAULT_TENANT_ID = -1234; // Super tenant

    private DIDDocumentService didDocumentService;

    @Override
    public void init() throws ServletException {
        super.init();
        this.didDocumentService = new DIDDocumentServiceImpl();
        LOG.info("WellKnownDIDServlet initialized successfully");
    }

    /**
     * Handle GET requests - Return DID Document.
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        LOG.debug("Received request for /.well-known/did.json");

        try {
            // Extract domain from request
            String domain = extractDomain(request);
            LOG.debug("Extracted domain: " + domain);

            // Get tenant ID (default to super tenant for now)
            // In a multi-tenant setup, this should be extracted from the request
            int tenantId = DEFAULT_TENANT_ID;

            // Generate DID document
            String didDocument = didDocumentService.getDIDDocument(domain, tenantId);

            LOG.info("Serving DID Document for domain: " + domain);

            // Send response
            response.setContentType("application/did+json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_OK);

            // Add CORS headers
            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
            response.setHeader("Access-Control-Allow-Headers", "Content-Type");

            PrintWriter out = response.getWriter();
            out.print(didDocument);
            out.flush();

            LOG.info("DID Document served successfully for domain: " + domain);

        } catch (DIDDocumentException e) {
            LOG.error("Failed to generate DID document", e);
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to generate DID document: " + e.getMessage());
        } catch (Exception e) {
            LOG.error("Unexpected error serving DID document", e);
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Internal server error");
        }
    }

    /**
     * Handle OPTIONS requests for CORS preflight.
     */
    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type");
        response.setStatus(HttpServletResponse.SC_OK);
    }

    /**
     * Extract domain from the configuration.
     * Returns the host and port if present.
     * 
     * @param request HTTP request (unused now)
     * @return Domain string (e.g., "example.com" or "localhost:9443")
     */
    private String extractDomain(HttpServletRequest request) {
        String baseUrl = org.wso2.carbon.identity.openid4vc.presentation.util.OpenID4VPUtil.getBaseUrl();
        // Remove protocol
        return baseUrl.replace("https://", "").replace("http://", "");
    }

    /**
     * Send error response.
     */
    private void sendErrorResponse(HttpServletResponse response, int statusCode, String message)
            throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(statusCode);

        String errorJson = String.format("{\"error\":\"%s\"}",
                message.replace("\"", "\\\""));

        PrintWriter out = response.getWriter();
        out.print(errorJson);
        out.flush();
    }
}
