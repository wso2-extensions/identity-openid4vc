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

package org.wso2.carbon.identity.openid4vc.presentation.server.servlet;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import org.apache.commons.lang.StringUtils;
import org.osgi.service.component.annotations.Component;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.server.cache.StandaloneVerificationCache;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.server.internal.VPServerDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.StandaloneVerificationSession;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.VPContext;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.RESPONSE_CONTENT_TYPE_CHARSET_UTF_8;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.RESPONSE_ERROR;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.RESPONSE_ERROR_CODE;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.RESPONSE_ERROR_DESCRIPTION;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.RESPONSE_REQUEST_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints.RESPONSE_STATUS;

/**
 * Servlet handling VP (Verifiable Presentation) authorization request operations.
 *
 * <p>Endpoints:</p>
 * <ul>
 *     <li>GET /oid4vp/v1/vp-request/{requestId} - Get authorization request JWT.</li>
 *     <li>GET /oid4vp/v1/vp-request/{requestId}/status - Get request status (with polling).</li>
 * </ul>
 */
@Component(
    service = Servlet.class,
    immediate = true,
    property = {
        "osgi.http.whiteboard.servlet.pattern=/oid4vp/v1/vp-request/*",
        "osgi.http.whiteboard.servlet.name=OpenID4VPRequest",
        "osgi.http.whiteboard.servlet.asyncSupported=true"
    }
)
public class VPRequestServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    @Override
    public void init() throws ServletException {

        super.init();
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        if (VPServerDataHolder.getVPRequestService() == null) {
            response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, "OpenID4VP feature is not enabled.");
            return;
        }
        String pathInfo = request.getPathInfo();

        if (StringUtils.isBlank(pathInfo) || "/".equals(pathInfo)) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Request ID is required in path."));
            return;
        }

        String[] pathParts = pathInfo.split("/");

        if (pathParts.length < 2) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Invalid path format."));
            return;
        }

        String requestId = pathParts[1];
        boolean isStatusRequest = pathParts.length >= 3 && "status".equals(pathParts[2]);

        try {
            VPContext vpContext = getVPContextByRequestId(requestId);
            if (vpContext == null) {
                if (isStatusRequest) {
                    JsonObject statusResponse = new JsonObject();
                    statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                    statusResponse.addProperty(RESPONSE_STATUS, VPRequestStatus.FAILED.name());
                    sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
                } else {
                    sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND,
                            new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND,
                                    "VP request not found: " + requestId));
                }
                return;
            }

            VPRequestStatus status = vpContext.getRequestStatus();

            if (status == VPRequestStatus.FAILED || status == VPRequestStatus.VERIFIED ||
                    status == VPRequestStatus.VP_SUBMITTED) {
                JsonObject statusResponse = new JsonObject();
                statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                statusResponse.addProperty(RESPONSE_STATUS, status.name());
                sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
                return;
            }

            if (status == VPRequestStatus.ACTIVE) {
                if (isStatusRequest) {
                    JsonObject statusResponse = new JsonObject();
                    statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                    statusResponse.addProperty(RESPONSE_STATUS, VPRequestStatus.ACTIVE.name());
                    sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
                } else {
                    handleRequestJwtRequest(response, requestId);
                }
                return;
            }

            if (isStatusRequest) {
                JsonObject statusResponse = new JsonObject();
                statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                statusResponse.addProperty(RESPONSE_STATUS, status.name());
                sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
            } else {
                throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_EXPIRED,
                        "VP request is not active: " + status);
            }

        } catch (VPAuthenticatorClientException e) {
            if (VPAuthenticatorErrorCode.VP_REQUEST_EXPIRED.getCode().equals(e.getCode())) {
                sendErrorResponse(response, HttpServletResponse.SC_GONE, e);
            } else {
                sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND, e);
            }
        } catch (VPAuthenticatorException e) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, e);
        } catch (RuntimeException | IOException e) {
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Internal server error.", e));
        }
    }

    private void handleRequestJwtRequest(HttpServletResponse response,
                                         String requestId) throws VPAuthenticatorException, IOException {

        // Standalone sessions are served via StandaloneVerificationService; auth-flow sessions via VPRequestService.
        StandaloneVerificationSession standaloneSession = StandaloneVerificationCache.getInstance().get(requestId);
        String requestJwt;
        if (standaloneSession != null) {
            requestJwt = VPServerDataHolder.getStandaloneVerificationService().generateRequestJwt(requestId);
        } else {
            requestJwt = VPServerDataHolder.getVPRequestService().generateRequestJwt(requestId);
        }

        if (StringUtils.isBlank(requestJwt)) {
            throw new VPAuthenticatorServerException(
                VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                "Failed to generate request JWT for request: " + requestId);
        }

        response.setContentType("application/oauth-authz-req+jwt");
        response.setStatus(HttpServletResponse.SC_OK);
        writeResponse(response, requestJwt);
    }

    private void writeResponse(HttpServletResponse response, String content) throws IOException {

        response.getOutputStream().write(content.getBytes(StandardCharsets.UTF_8));
        response.getOutputStream().flush();
    }

    private void sendJsonResponse(HttpServletResponse response, int statusCode, Object data)
            throws IOException {

        response.setStatus(statusCode);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON + RESPONSE_CONTENT_TYPE_CHARSET_UTF_8);

        writeResponse(response, gson.toJson(data));
    }

    private void sendErrorResponse(final HttpServletResponse response, final int statusCode,
            final VPAuthenticatorException exception)
            throws IOException {

        JsonObject errorObj = new JsonObject();
        errorObj.addProperty(RESPONSE_ERROR, exception.getOAuth2ErrorCode());
        errorObj.addProperty(RESPONSE_ERROR_DESCRIPTION, Encode.forJava(exception.getMessage()));
        errorObj.addProperty(RESPONSE_ERROR_CODE, exception.getCode());
        sendJsonResponse(response, statusCode, errorObj);
    }

    private VPContext getVPContextByRequestId(String requestId) {

        AuthenticationContext context = FrameworkUtils.getAuthenticationContextFromCache(requestId);
        if (context != null) {
            Object vpContextObj = context.getProperty(Constraints.CONTEXT_VP_CONTEXT);
            if (vpContextObj instanceof VPContext) {
                return (VPContext) vpContextObj;
            }
            return null;
        }

        // No auth context — check standalone verification cache.
        StandaloneVerificationSession standaloneSession = StandaloneVerificationCache.getInstance().get(requestId);
        if (standaloneSession != null) {
            VPContext vpContext = new VPContext(standaloneSession.getStatus());
            vpContext.setNonce(standaloneSession.getNonce());
            vpContext.setEphemeralPrivateKeyJwk(standaloneSession.getEphemeralPrivateKeyJwk());
            vpContext.setVerificationResult(standaloneSession.getVerificationResult());
            return vpContext;
        }

        return null;
    }
}
