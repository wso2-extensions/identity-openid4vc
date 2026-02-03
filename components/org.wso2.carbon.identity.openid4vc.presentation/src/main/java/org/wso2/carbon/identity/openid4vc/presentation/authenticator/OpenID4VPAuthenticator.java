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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.cache.VPRequestCache;
import org.wso2.carbon.identity.openid4vc.presentation.cache.WalletDataCache;
import org.wso2.carbon.identity.openid4vc.presentation.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPRequestCreateDTO;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.service.ApplicationPresentationDefinitionMappingService;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPSubmissionService;
import org.wso2.carbon.identity.openid4vc.presentation.util.QRCodeUtil;
import org.wso2.carbon.identity.openid4vc.presentation.util.URLValidator;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OpenID4VP Wallet Authenticator for WSO2 Identity Server.
 * 
 * This authenticator implements the OpenID for Verifiable Presentations
 * (OpenID4VP) protocol
 * to authenticate users by verifying their verifiable credentials from a
 * digital wallet.
 * 
 * Flow:
 * 1. User initiates login
 * 2. Authenticator generates VP request and displays QR code
 * 3. User scans QR with wallet app
 * 4. Wallet sends VP submission to direct_post endpoint
 * 5. Authenticator polls for result and completes authentication
 * 
 * Supported response modes:
 * - direct_post: Wallet posts VP directly to server
 * - direct_post.jwt: Wallet posts signed JWT response
 */
public class OpenID4VPAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = 1L;

    // Authenticator configuration properties
    private static final String AUTHENTICATOR_NAME = "OpenID4VPAuthenticator";
    private static final String AUTHENTICATOR_FRIENDLY_NAME = "Wallet (OpenID4VP)";

    // Request parameter names
    private static final String PARAM_VP_REQUEST_ID = "vp_request_id";

    private static final String PARAM_STATUS = "status";
    private static final String PARAM_POLL = "poll";

    // Session data keys
    private static final String SESSION_VP_REQUEST_ID = "openid4vp_request_id";
    private static final String SESSION_TRANSACTION_ID = "openid4vp_transaction_id";

    // Configuration property keys
    private static final String PROP_PRESENTATION_DEFINITION_ID = "PresentationDefinitionId";
    private static final String PROP_RESPONSE_MODE = "ResponseMode";
    private static final String PROP_TIMEOUT_SECONDS = "TimeoutSeconds";
    private static final String PROP_CLIENT_ID = "ClientId";
    private static final String PROP_DID_METHOD = "DIDMethod";
    private static final String PROP_SUBJECT_CLAIM = "SubjectClaim";

    private static final int DISPLAY_ORDER_3 = 3;
    private static final int DISPLAY_ORDER_4 = 4;
    private static final int DISPLAY_ORDER_5 = 5;
    private static final int SUPER_TENANT_ID_PLACEHOLDER = -1234;

    @Override
    public String getName() {
        return AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            // Create VP request
            VPRequestResponseDTO vpRequestResponse = createVPRequest(context);

            // Store request ID in session
            context.setProperty(SESSION_VP_REQUEST_ID, vpRequestResponse.getRequestId());
            context.setProperty(SESSION_TRANSACTION_ID, vpRequestResponse.getTransactionId());

            // Generate QR code content
            String qrContent = QRCodeUtil.generateRequestUriQRContent(
                    vpRequestResponse.getRequestUri(),
                    vpRequestResponse.getAuthorizationDetails().getClientId());

            // Redirect to login page with QR code data
            String loginPage = getLoginPage(context);
            String queryParams = buildQueryParams(vpRequestResponse, qrContent, context);

            String redirectUrl = loginPage + queryParams;
            if (!URLValidator.isValidURL(redirectUrl)) {
                throw new AuthenticationFailedException("Invalid redirect URL");
            }
            response.sendRedirect(redirectUrl);

        } catch (VPException e) {
            throw new AuthenticationFailedException("Failed to create VP request", e);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Failed to redirect to login page", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            // Get VP result
            VPSubmissionService submissionService = getVPSubmissionService();
            int tenantId = getTenantId(context);

            // Get the request ID from session
            String requestId = (String) context.getProperty(SESSION_VP_REQUEST_ID);

            VPSubmission submission = submissionService.getVPSubmissionByRequestId(requestId, tenantId);

            if (submission == null || StringUtils.isBlank(submission.getVpToken())) {
                throw new AuthenticationFailedException("VP token not found in submission");
            }

            // Extract credentials from VP Token
            String vpToken = submission.getVpToken();
            String username = null;

            try {
                JsonObject vpData = null;

                // Check if VP token is JSON-LD format (starts with { or [)
                String trimmedToken = vpToken.trim();
                if (trimmedToken.startsWith("{") || trimmedToken.startsWith("[")) {
                    try {
                        JsonElement parsed = JsonParser.parseString(trimmedToken);
                        if (parsed.isJsonObject()) {
                            vpData = parsed.getAsJsonObject();
                        }
                    } catch (Exception e) {
                        // ignore and continue
                    }
                }

                // If not JSON-LD, try SD-JWT format (contains ~)
                if (vpData == null && vpToken.contains("~")) {
                    String[] sdParts = vpToken.split("~");
                    String issuerJwt = sdParts[0];
                    // Extracted issuer JWT from SD-JWT

                    String[] jwtParts = issuerJwt.split("\\.");
                    if (jwtParts.length >= 2) {
                        String payload = new String(Base64.getUrlDecoder().decode(jwtParts[1]), StandardCharsets.UTF_8);
                        // Decoding SD-JWT payload
                        vpData = JsonParser.parseString(payload).getAsJsonObject();
                    }
                }

                // If not SD-JWT, try standard 3-part JWT
                if (vpData == null) {
                    String[] dotParts = vpToken.split("\\.");
                    if (dotParts.length == 3) {
                        String payload = new String(Base64.getUrlDecoder().decode(dotParts[1]), StandardCharsets.UTF_8);
                        // Decoding JWT payload
                        vpData = JsonParser.parseString(payload).getAsJsonObject();
                    } else {
                        if (dotParts.length > 3) {
                            try {
                                String payload = new String(Base64.getUrlDecoder().decode(dotParts[1]),
                                        StandardCharsets.UTF_8);
                                vpData = JsonParser.parseString(payload).getAsJsonObject();
                            } catch (Exception e) {
                                // ignore
                            }
                        }

                        if (vpData == null) {
                            throw new VPException(
                                    "Unsupported VP token format: expected JSON-LD, 3-part JWT, or SD-JWT");
                        }
                    }
                }

                // Extract VP wrapper if present
                JsonObject vp = vpData.has("vp") ? vpData.getAsJsonObject("vp") : vpData;
                // VP object extracted

                // Get verifiable credentials
                if (!vp.has("verifiableCredential")) {
                    throw new VPException("No verifiableCredential found in VP");
                }

                JsonElement vcElement = vp.get("verifiableCredential");
                String vcToken;

                if (vcElement.isJsonArray()) {
                    JsonArray vcArray = vcElement.getAsJsonArray();
                    if (vcArray.size() == 0) {
                        throw new VPException("Empty verifiableCredential array");
                    }
                    JsonElement firstVc = vcArray.get(0);
                    if (firstVc.isJsonPrimitive()) {
                        vcToken = firstVc.getAsString();
                    } else if (firstVc.isJsonObject()) {
                        JsonObject vcObj = firstVc.getAsJsonObject();
                        JsonObject credentialSubject = vcObj.has("credentialSubject")
                                ? vcObj.getAsJsonObject("credentialSubject")
                                : null;

                        if (credentialSubject != null) {
                            // Extracting user identifier from credential subject
                            if (credentialSubject.has("email")) {
                                username = credentialSubject.get("email").getAsString();
                            } else if (credentialSubject.has("username")) {
                                username = credentialSubject.get("username").getAsString();
                            } else if (credentialSubject.has("id")) {
                                username = credentialSubject.get("id").getAsString();
                            }
                        }
                        vcToken = null;
                    } else {
                        throw new VPException("Unexpected VC format in array");
                    }
                } else if (vcElement.isJsonPrimitive()) {
                    vcToken = vcElement.getAsString();
                } else if (vcElement.isJsonObject()) {
                    JsonObject vcObj = vcElement.getAsJsonObject();
                    vcToken = null;
                    if (vcObj.has("credentialSubject")) {
                        JsonObject credentialSubject = vcObj.getAsJsonObject("credentialSubject");
                        if (credentialSubject.has("email")) {
                            username = credentialSubject.get("email").getAsString();
                        } else if (credentialSubject.has("username")) {
                            username = credentialSubject.get("username").getAsString();
                        }
                    }
                } else {
                    throw new VPException("Unexpected verifiableCredential format");
                }

                // If we have a JWT/SD-JWT VC token, decode it
                if (StringUtils.isNotBlank(vcToken)) {

                    String vcIssuerJwt;
                    if (vcToken.contains("~")) {
                        vcIssuerJwt = vcToken.split("~")[0];
                    } else {
                        vcIssuerJwt = vcToken;
                    }

                    String[] vcParts = vcIssuerJwt.split("\\.");
                    if (vcParts.length >= 2) {
                        String vcPayloadStr = new String(Base64.getUrlDecoder().decode(vcParts[1]),
                                StandardCharsets.UTF_8);

                        JsonElement vcParsed = JsonParser.parseString(vcPayloadStr);
                        if (vcParsed.isJsonObject()) {
                            JsonObject vcPayload = vcParsed.getAsJsonObject();
                            JsonObject vc = vcPayload.has("vc") ? vcPayload.getAsJsonObject("vc") : vcPayload;
                            JsonObject credentialSubject = vc.getAsJsonObject("credentialSubject");

                            if (credentialSubject != null) {
                                if (credentialSubject.has("email")) {
                                    username = credentialSubject.get("email").getAsString();
                                }
                                if (credentialSubject.has("username")) {
                                    username = credentialSubject.get("username").getAsString();
                                }
                                if (StringUtils.isBlank(username)) {
                                    String[] fields = { "id", "sub", "name", "holder" };
                                    for (String field : fields) {
                                        if (credentialSubject.has(field)
                                                && credentialSubject.get(field).isJsonPrimitive()) {
                                            username = credentialSubject.get(field).getAsString();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

            } catch (Exception e) {
                throw new AuthenticationFailedException(
                        "Failed to extract credentials from VP token: " + e.getMessage(), e);
            }

            if (StringUtils.isBlank(username)) {
                cleanupVPData(requestId, tenantId);
                throw new AuthenticationFailedException("No user identifier found in VP");
            }

            // Create Federated Authenticated User
            AuthenticatedUser authenticatedUser = AuthenticatedUser
                    .createFederateAuthenticatedUserFromSubjectIdentifier(username);
            authenticatedUser.setFederatedUser(true);

            if (context.getExternalIdP() != null) {
                authenticatedUser.setFederatedIdPName(context.getExternalIdP().getIdPName());
            }

            authenticatedUser.setTenantDomain(context.getTenantDomain());

            // Extract and set user claims/attributes from VP
            Map<ClaimMapping, String> userAttributes = extractClaimsFromVP(submission.getVpToken());
            authenticatedUser.setUserAttributes(userAttributes);

            context.setSubject(authenticatedUser);

            // Cleanup VP data after successful authentication
            cleanupVPData(requestId, tenantId);

        } catch (VPException e) {
            String reqId = (String) context.getProperty(SESSION_VP_REQUEST_ID);
            cleanupVPData(reqId, getTenantId(context));
            throw new AuthenticationFailedException("Failed to process VP submission", e);
        }
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        // Check if this is a polling request
        String poll = request.getParameter(PARAM_POLL);
        if ("true".equals(poll)) {
            return handlePollRequest(request, response, context);
        }

        // Check if status is being reported
        String status = request.getParameter(PARAM_STATUS);
        if (StringUtils.isNotBlank(status)) {
            return handleStatusCallback(request, response, context, status);
        }

        return super.process(request, response, context);
    }

    /**
     * Handle polling request from the login page.
     */
    private AuthenticatorFlowStatus handlePollRequest(HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationContext context)
            throws AuthenticationFailedException {

        String requestId = (String) context.getProperty(SESSION_VP_REQUEST_ID);
        if (StringUtils.isBlank(requestId)) {
            throw new AuthenticationFailedException("VP request ID not found in session");
        }

        try {
            VPRequestService requestService = getVPRequestService();
            int tenantId = getTenantId(context);
            VPRequest vpRequest = requestService.getVPRequestById(requestId, tenantId);

            if (vpRequest == null) {
                sendPollResponse(response, "error", "Request not found");
                return AuthenticatorFlowStatus.INCOMPLETE;
            }

            VPRequestStatus status = vpRequest.getStatus();

            if (VPRequestStatus.VP_SUBMITTED.equals(status) ||
                    VPRequestStatus.COMPLETED.equals(status)) {

                sendPollResponse(response, status.getValue().toLowerCase(), null);

                if (VPRequestStatus.COMPLETED.equals(status)) {
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                }
            } else if (VPRequestStatus.EXPIRED.equals(status)) {
                sendPollResponse(response, "expired", "Request expired");
                throw new AuthenticationFailedException("VP request has expired");
            } else if (VPRequestStatus.CANCELLED.equals(status)) {
                sendPollResponse(response, "cancelled", "Request was cancelled");
                throw new AuthenticationFailedException("VP request was cancelled");
            } else {
                sendPollResponse(response, "pending", null);
            }

            return AuthenticatorFlowStatus.INCOMPLETE;

        } catch (VPException e) {
            sendPollResponse(response, "error", e.getMessage());
            return AuthenticatorFlowStatus.INCOMPLETE;
        }
    }

    /**
     * Handle status callback from the frontend.
     */
    private AuthenticatorFlowStatus handleStatusCallback(HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationContext context,
            String status)
            throws AuthenticationFailedException {

        if ("success".equals(status)) {
            processAuthenticationResponse(request, response, context);
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if ("failed".equals(status)) {
            throw new AuthenticationFailedException("VP verification failed");
        } else if ("expired".equals(status)) {
            throw new AuthenticationFailedException("VP request expired");
        }

        return AuthenticatorFlowStatus.INCOMPLETE;
    }

    /**
     * Send polling response to the client.
     */
    private void sendPollResponse(HttpServletResponse response, String status, String error) {
        try {
            response.setContentType("application/json;charset=UTF-8");

            StringBuilder json = new StringBuilder();
            json.append("{\"status\":\"").append(status).append("\"");
            if (error != null) {
                json.append(",\"error\":\"").append(error.replace("\"", "\\\"")).append("\"");
            }
            json.append("}");

            response.getWriter().write(json.toString());
        } catch (IOException e) {
            // ignore
        }
    }

    /**
     * Create a VP request for the authentication session.
     */
    private VPRequestResponseDTO createVPRequest(AuthenticationContext context) throws VPException {
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();

        // Set DID Method if configured
        String didMethod = authenticatorProperties.get(PROP_DID_METHOD);
        if (StringUtils.isNotBlank(didMethod)) {
            createDTO.setDidMethod(didMethod);
        }

        // Set client ID from config or generate from tenant
        String clientId = authenticatorProperties.get(PROP_CLIENT_ID);
        if (StringUtils.isBlank(clientId)) {
            clientId = buildClientId(context);
        }
        createDTO.setClientId(clientId);

        // NEW: Use per-application presentation definition mapping
        // Resolution order:
        // 1. Check application-specific mapping in
        // IDN_APPLICATION_PRESENTATION_DEFINITION table
        // 2. Fall back to authenticator configuration property (backward compatible)
        // 3. Use inline default definition if neither exists
        String presentationDefId = resolvePresentationDefinitionId(context);

        if (StringUtils.isNotBlank(presentationDefId)) {
            createDTO.setPresentationDefinitionId(presentationDefId);
        } else {
            // Create a default presentation definition requesting any verifiable credential
            createDTO.setPresentationDefinition(createDefaultPresentationDefinition());
        }

        // Set response mode
        String responseMode = authenticatorProperties.get(PROP_RESPONSE_MODE);
        if (StringUtils.isBlank(responseMode)) {
            responseMode = OpenID4VPConstants.Protocol.RESPONSE_MODE_DIRECT_POST;
        }
        createDTO.setResponseMode(responseMode);

        // Set transaction ID to context identifier for correlation
        createDTO.setTransactionId(context.getContextIdentifier());

        // Create VP request
        VPRequestService vpRequestService = getVPRequestService();
        int tenantId = getTenantId(context);
        return vpRequestService.createVPRequest(createDTO, tenantId);
    }

    /**
     * Resolve the presentation definition ID for the application.
     * 
     * Resolution order:
     * 1. Check application-specific mapping in
     * IDN_APPLICATION_PRESENTATION_DEFINITION
     * 2. Check authenticator configuration property
     * 3. Return null to use inline default
     * 
     * @param context Authentication context
     * @return Presentation definition ID or null
     * @throws VPException If error occurs during resolution
     */
    private String resolvePresentationDefinitionId(AuthenticationContext context) throws VPException {
        String applicationId = context.getServiceProviderName();
        int tenantId = getTenantId(context);

        try {
            // Step 1: Try application-specific mapping
            // Note: The authenticator context provides the Service Provider NAME
            // But the mapping service expects the Application Resource ID (UUID)

            // Resolve Application UUID
            String appResourceId = null;
            try {
                ApplicationManagementService applicationMgtService = VPServiceDataHolder.getInstance()
                        .getApplicationManagementService();
                if (applicationMgtService != null) {
                    ServiceProvider serviceProvider = applicationMgtService.getServiceProvider(applicationId,
                            context.getTenantDomain());
                    if (serviceProvider != null) {
                        appResourceId = serviceProvider.getApplicationResourceId();
                    }
                }
            } catch (Exception e) {
                // ignore
            }

            // If we couldn't resolve the UUID, fallback to using the name (backward
            // compatibility / legacy behavior)
            String lookupId = StringUtils.isNotBlank(appResourceId)
                    ? appResourceId
                    : applicationId;

            String appDefinitionId = getApplicationPresentationDefinitionMappingService()
                    .getApplicationPresentationDefinitionId(lookupId, tenantId);

            if (StringUtils.isNotBlank(appDefinitionId)) {
                return appDefinitionId;
            }

        } catch (Exception e) {
            // ignore
        }

        // Step 2: Fall back to authenticator configuration
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String configId = authenticatorProperties.get(PROP_PRESENTATION_DEFINITION_ID);

            if (StringUtils.isNotBlank(configId)) {
                return configId;
            }

        } catch (Exception e) {
            // ignore
        }

        // Step 3: Will use inline default
        return null;
    }

    /**
     * Get the Application Presentation Definition Mapping Service.
     * 
     * @return ApplicationPresentationDefinitionMappingService
     * @throws VPException If service is not available
     */
    private ApplicationPresentationDefinitionMappingService getApplicationPresentationDefinitionMappingService()
            throws VPException {
        ApplicationPresentationDefinitionMappingService service = VPServiceDataHolder
                .getInstance().getApplicationPresentationDefinitionMappingService();

        if (service == null) {
            throw new VPException(
                    "Application Presentation Definition Mapping Service not available");
        }
        return service;
    }

    /**
     * Create a default presentation definition that accepts any verifiable
     * credential.
     * This is used when no specific presentation definition is configured.
     */
    private JsonObject createDefaultPresentationDefinition() {
        JsonObject presentationDef = new JsonObject();
        presentationDef.addProperty("id", "default-wallet-auth");
        presentationDef.addProperty("name", "Wallet Authentication");
        presentationDef.addProperty("purpose",
                "Authenticate using your digital wallet");

        // Create input descriptors - accepts any VC
        JsonArray inputDescriptors = new JsonArray();
        JsonObject descriptor = new JsonObject();
        descriptor.addProperty("id", "any-credential");
        descriptor.addProperty("name", "Any Verifiable Credential");
        descriptor.addProperty("purpose",
                "Present any verifiable credential from your wallet");

        // Add constraints - accept any type of credential
        JsonObject constraints = new JsonObject();
        JsonArray fields = new JsonArray();

        // Require credential type field
        JsonObject typeField = new JsonObject();
        JsonArray pathArray = new JsonArray();
        pathArray.add("$.type");
        pathArray.add("$.vc.type");
        pathArray.add("$.vct");
        typeField.add("path", pathArray);

        fields.add(typeField);
        constraints.add("fields", fields);
        descriptor.add("constraints", constraints);

        inputDescriptors.add(descriptor);
        presentationDef.add("input_descriptors", inputDescriptors);
        return presentationDef;
    }

    /**
     * Build client ID for the request.
     *
     * @param context Authentication context
     * @return Client ID
     */
    private String buildClientId(final AuthenticationContext context) {
        // Use fixed DID for demo purposes as requested
        return "did:web:masked-unprofitably-ardith.ngrok-free.dev";
    }

    /**
     * Get tenant ID from authentication context.
     *
     * @param context Authentication context
     * @return Tenant ID
     */
    private int getTenantId(final AuthenticationContext context) {
        // Default to super tenant
        int tenantId = SUPER_TENANT_ID_PLACEHOLDER;

        String tenantDomain = context.getTenantDomain();
        if (StringUtils.isNotBlank(tenantDomain)) {
            try {
                // In production, use TenantManager to resolve tenant ID
                // For now, use simple mapping
                if ("carbon.super".equals(tenantDomain)) {
                    tenantId = SUPER_TENANT_ID_PLACEHOLDER;
                }
            } catch (Exception e) {
                // ignore
            }
        }

        return tenantId;
    }

    /**
     * Get login page URL.
     *
     * @param context Authentication context
     * @return Login page URL
     */
    private String getLoginPage(final AuthenticationContext context) {
        String loginPage = IdentityUtil.getProperty("OpenID4VP.LoginPage");
        if (StringUtils.isBlank(loginPage)) {
            loginPage = "/authenticationendpoint/wallet_login.jsp";
        }
        return loginPage;
    }

    /**
     * Build query parameters for the redirect.
     *
     * @param vpRequestResponse VP request response
     * @param qrContent         QR content
     * @param context           Authentication context
     * @return Query parameters string
     */
    private String buildQueryParams(final VPRequestResponseDTO vpRequestResponse,
            final String qrContent,
            final AuthenticationContext context) {
        StringBuilder params = new StringBuilder();
        params.append("?");
        params.append("sessionDataKey=")
                .append(context.getContextIdentifier());
        params.append("&requestId=")
                .append(vpRequestResponse.getRequestId());
        params.append("&transactionId=").append(
                vpRequestResponse.getTransactionId());
        params.append("&requestUri=").append(urlEncode(
                vpRequestResponse.getRequestUri()));
        params.append("&qrContent=").append(urlEncode(qrContent));

        return params.toString();
    }

    /**
     * URL encode a string.
     */
    private String urlEncode(String value) {
        try {
            return java.net.URLEncoder.encode(value, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            return value;
        }
    }

    /**
     * Get VPRequestService instance.
     */
    private VPRequestService getVPRequestService() {
        return VPServiceDataHolder.getInstance().getVPRequestService();
    }

    /**
     * Get VPSubmissionService instance.
     */
    private VPSubmissionService getVPSubmissionService() {
        return VPServiceDataHolder.getInstance().getVPSubmissionService();
    }

    /**
     * Cleanup VP request and submission data after authentication flow.
     * Called after both successful and failed authentication to comply with
     * OID4VP data minimization principles.
     *
     * @param requestId Request ID to cleanup
     * @param tenantId  Tenant ID
     */
    private void cleanupVPData(String requestId, int tenantId) {
        if (StringUtils.isBlank(requestId)) {
            return;
        }

        try {
            // Delete submission first (foreign key consideration)
            VPSubmissionService submissionService = getVPSubmissionService();
            submissionService.deleteSubmissionsForRequest(requestId,
                    tenantId);
            // Delete VP request
            VPRequestService requestService = getVPRequestService();
            requestService.deleteVPRequest(requestId, tenantId);

            // Clear from caches
            VPRequestCache.getInstance().remove(requestId);
            WalletDataCache.getInstance().retrieveSubmission(requestId);

        } catch (Exception e) {
            // Log but don't fail authentication due to cleanup errors
        }
    }

    /**
     * Extract claims from VP token for federated user attributes.
     * 
     * @param vpToken Raw VP token (JWT or JSON-LD)
     * @return Map of claim mappings to values
     */
    private Map<ClaimMapping, String> extractClaimsFromVP(
            final String vpToken) {
        Map<ClaimMapping, String> claims = new HashMap<>();

        try {
            JsonObject vpData = null;
            String trimmedToken = vpToken.trim();

            // Minimal parsing logic to find credentialSubject
            // (simplified for this migration)
            if (trimmedToken.startsWith("{") || trimmedToken.startsWith("[")) {
                JsonElement parsed = JsonParser.parseString(trimmedToken);
                if (parsed.isJsonObject()) {
                    vpData = parsed.getAsJsonObject();
                }
            } else {
                String[] parts = vpToken.split("\\.");
                if (parts.length >= 2) {
                    String payload = new String(Base64.getUrlDecoder()
                            .decode(parts[1]), StandardCharsets.UTF_8);
                    vpData = JsonParser.parseString(payload).getAsJsonObject();
                }
            }

            if (vpData == null) {
                return claims;
            }

            // Look for credentialSubject
            JsonObject vc = null;
            if (vpData.has("vc")) {
                vc = vpData.getAsJsonObject("vc");
            } else if (vpData.has("verifiableCredential")) {
                JsonElement vcElem = vpData.get("verifiableCredential");
                if (vcElem.isJsonArray()) {
                    vc = vcElem.getAsJsonArray().get(0).getAsJsonObject();
                } else if (vcElem.isJsonObject()) {
                    vc = vcElem.getAsJsonObject();
                }
            } else {
                vc = vpData;
            }

            if (vc != null && vc.has("credentialSubject")) {
                JsonObject subject = vc.getAsJsonObject("credentialSubject");
                for (Map.Entry<String, JsonElement> entry : subject.entrySet()) {
                    if (entry.getValue().isJsonPrimitive()) {
                        String claimUri = "http://wso2.org/claims/"
                                + entry.getKey();
                        claims.put(ClaimMapping.build(claimUri, entry.getKey(),
                                null, false),
                                entry.getValue().getAsString());
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }

        return claims;
    }

    /**
     * Check if retry authentication is enabled.
     *
     * @return False
     */
    @Override
    protected boolean retryAuthenticationEnabled() {
        return false;
    }

    /**
     * Get the context identifier.
     *
     * @param request HTTP request
     * @return Context identifier
     */
    @Override
    public String getContextIdentifier(final HttpServletRequest request) {
        return request.getParameter("sessionDataKey");
    }

    /**
     * Check if the authenticator can handle the request.
     *
     * @param request HTTP request
     * @return True if can handle
     */
    @Override
    public boolean canHandle(final HttpServletRequest request) {
        String sessionDataKey = request.getParameter("sessionDataKey");
        String vpRequestId = request.getParameter(PARAM_VP_REQUEST_ID);
        String poll = request.getParameter(PARAM_POLL);
        String status = request.getParameter(PARAM_STATUS);

        // Handle polling requests from login page
        if (StringUtils.isNotBlank(poll)
                && StringUtils.isNotBlank(sessionDataKey)) {
            return true;
        }

        // Handle status callbacks
        if (StringUtils.isNotBlank(status)
                && StringUtils.isNotBlank(sessionDataKey)) {
            return true;
        }

        // Handle VP request callbacks
        if (StringUtils.isNotBlank(vpRequestId)
                && StringUtils.isNotBlank(sessionDataKey)) {
            return true;
        }

        return false;
    }

    /**
     * Get configuration properties.
     *
     * @return List of properties
     */
    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<>();

        Property presentationDefId = new Property();
        presentationDefId.setName(PROP_PRESENTATION_DEFINITION_ID);
        presentationDefId.setDisplayName("Presentation Definition ID");
        presentationDefId.setDescription(
                "ID of the presentation definition to use for VP requests");
        presentationDefId.setDisplayOrder(1);
        presentationDefId.setRequired(false);
        configProperties.add(presentationDefId);

        Property responseMode = new Property();
        responseMode.setName(PROP_RESPONSE_MODE);
        responseMode.setDisplayName("Response Mode");
        responseMode.setDescription(
                "Response mode for VP submissions "
                        + "(direct_post or direct_post.jwt)");
        responseMode.setDisplayOrder(2);
        responseMode.setDefaultValue("direct_post");
        responseMode.setRequired(false);
        configProperties.add(responseMode);

        Property timeout = new Property();
        timeout.setName(PROP_TIMEOUT_SECONDS);
        timeout.setDisplayName("Timeout (seconds)");
        timeout.setDescription("Timeout for VP requests in seconds");
        timeout.setDisplayOrder(DISPLAY_ORDER_3);
        timeout.setDefaultValue("300");
        timeout.setRequired(false);
        configProperties.add(timeout);

        Property clientId = new Property();
        clientId.setName(PROP_CLIENT_ID);
        clientId.setDisplayName("Client ID");
        clientId.setDescription(
                "Client ID to use in VP requests "
                        + "(auto-generated if not specified)");
        clientId.setDisplayOrder(DISPLAY_ORDER_4);
        clientId.setRequired(false);
        configProperties.add(clientId);

        Property subjectClaim = new Property();
        subjectClaim.setName(PROP_SUBJECT_CLAIM);
        subjectClaim.setDisplayName("Subject Claim");
        subjectClaim.setDescription(
                "Claim path to use as the authenticated subject identifier");
        subjectClaim.setDisplayOrder(DISPLAY_ORDER_5);
        subjectClaim.setDefaultValue("credentialSubject.id");
        subjectClaim.setRequired(false);
        configProperties.add(subjectClaim);

        return configProperties;
    }
}
