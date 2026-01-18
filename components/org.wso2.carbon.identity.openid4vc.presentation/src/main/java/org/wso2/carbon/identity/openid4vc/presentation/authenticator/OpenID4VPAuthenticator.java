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
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPRequestCreateDTO;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPSubmissionService;
import org.wso2.carbon.identity.openid4vc.presentation.util.QRCodeUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
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
        implements LocalApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(OpenID4VPAuthenticator.class);
    private static final long serialVersionUID = 1L;
    private static final String LOG_PREFIX = "[OPENID4VP]";

    // Authenticator configuration properties
    private static final String AUTHENTICATOR_NAME = "OpenID4VPAuthenticator";
    private static final String AUTHENTICATOR_FRIENDLY_NAME = "Wallet (OpenID4VP)";

    // Request parameter names
    private static final String PARAM_VP_REQUEST_ID = "vp_request_id";
    private static final String PARAM_TRANSACTION_ID = "transaction_id";
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
    private static final String PROP_SUBJECT_CLAIM = "SubjectClaim";

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

        log.info(LOG_PREFIX + " ========================================");
        log.info(LOG_PREFIX + " initiateAuthenticationRequest() - START");
        log.info(LOG_PREFIX + " Session ID: " + context.getContextIdentifier());
        log.info(LOG_PREFIX + " SP Name: " + context.getServiceProviderName());
        log.info(LOG_PREFIX + " ========================================");

        try {
            // Create VP request
            VPRequestResponseDTO vpRequestResponse = createVPRequest(context);

            log.info(LOG_PREFIX + " VP Request created successfully");
            log.info(LOG_PREFIX + " Request ID: " + vpRequestResponse.getRequestId());
            log.info(LOG_PREFIX + " Transaction ID: " + vpRequestResponse.getTransactionId());
            log.info(LOG_PREFIX + " Request URI: " + vpRequestResponse.getRequestUri());

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

            log.info(LOG_PREFIX + " Redirecting to login page: " + loginPage);
            log.info(LOG_PREFIX + " initiateAuthenticationRequest() - END");

            response.sendRedirect(loginPage + queryParams);

        } catch (VPException e) {
            log.error(LOG_PREFIX + " Error creating VP request", e);
            throw new AuthenticationFailedException("Failed to create VP request", e);
        } catch (IOException e) {
            log.error(LOG_PREFIX + " Error redirecting to login page", e);
            throw new AuthenticationFailedException("Failed to redirect to login page", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationContext context)
            throws AuthenticationFailedException {

        log.info(LOG_PREFIX + " ========================================");
        log.info(LOG_PREFIX + " processAuthenticationResponse() - START");
        log.info(LOG_PREFIX + " Session ID: " + context.getContextIdentifier());
        log.info(LOG_PREFIX + " ========================================");

        try {
            // Get VP result
            VPSubmissionService submissionService = getVPSubmissionService();
            int tenantId = getTenantId(context);

            // Get the request ID from session
            String requestId = (String) context.getProperty(SESSION_VP_REQUEST_ID);
            log.info(LOG_PREFIX + " Retrieving VP submission for request: " + requestId);

            VPSubmission submission = submissionService.getVPSubmissionByRequestId(requestId, tenantId);

            if (submission == null || StringUtils.isBlank(submission.getVpToken())) {
                log.error(LOG_PREFIX + " VP token not found in submission");
                throw new AuthenticationFailedException("VP token not found in submission");
            }

            log.info(LOG_PREFIX + " VP Token retrieved, length: " + submission.getVpToken().length());

            // Extract credentials from VP Token
            String vpToken = submission.getVpToken();
            String username = null;
            String password = null;

            try {
                // Parse JWT payload (part 1)
                String[] parts = vpToken.split("\\.");
                if (parts.length < 2) {
                    throw new VPException("Invalid VP token format");
                }

                String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
                JsonObject vpPayload = JsonParser.parseString(payload).getAsJsonObject();

                // Get nested VC JWT
                JsonObject vp = vpPayload.getAsJsonObject("vp");
                JsonArray vcArray = vp.getAsJsonArray("verifiableCredential");
                String vcJwt = vcArray.get(0).getAsString();

                // Parse inner VC (part 1)
                String[] vcParts = vcJwt.split("\\.");
                String vcPayloadStr = new String(Base64.getUrlDecoder().decode(vcParts[1]), StandardCharsets.UTF_8);
                JsonObject vcPayload = JsonParser.parseString(vcPayloadStr).getAsJsonObject();

                // Extract credentials from credentialSubject
                JsonObject vc = vcPayload.getAsJsonObject("vc");
                JsonObject credentialSubject = vc.getAsJsonObject("credentialSubject");

                username = credentialSubject.get("username").getAsString();
                password = credentialSubject.get("password").getAsString();

                log.info(LOG_PREFIX + " Extracted credentials for user: " + username);

            } catch (Exception e) {
                log.error(LOG_PREFIX + " Error extracting credentials from VP token", e);
                throw new AuthenticationFailedException("Failed to extract credentials from VP token", e);
            }

            // Authenticate against user store
            if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(password)) {
                try {
                    UserStoreManager userStoreManager = (UserStoreManager) VPServiceDataHolder
                            .getInstance().getRealmService()
                            .getTenantUserRealm(tenantId).getUserStoreManager();

                    log.info(LOG_PREFIX + " Authenticating user against user store...");
                    boolean isAuthenticated = userStoreManager.authenticate(username, password);

                    if (!isAuthenticated) {
                        log.error(LOG_PREFIX + " Authentication failed for user: " + username);
                        throw new AuthenticationFailedException("Invalid credentials found in VP");
                    }

                    log.info(LOG_PREFIX + " Authentication successful for user: " + username);

                    // Set authenticated user
                    AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                    authenticatedUser.setUserName(username);
                    authenticatedUser.setAuthenticatedSubjectIdentifier(username);
                    authenticatedUser.setTenantDomain(context.getTenantDomain());

                    // Explicitly set user store domain (required for some WSO2 versions to resolve
                    // ID)
                    if (StringUtils.isBlank(authenticatedUser.getUserStoreDomain())) {
                        authenticatedUser.setUserStoreDomain("PRIMARY");
                    }

                    // Resolve and set User ID (Required for IS 7.0+)
                    try {
                        String userId = userStoreManager.getUserClaimValue(username,
                                "http://wso2.org/claims/userid", null);
                        if (StringUtils.isBlank(userId)) {
                            userId = userStoreManager.getUserClaimValue(username,
                                    "http://wso2.org/claims/id", null);
                        }

                        if (StringUtils.isNotBlank(userId)) {
                            authenticatedUser.setUserId(userId);
                            log.info(LOG_PREFIX + " Resolved User ID for " + username + ": " + userId);
                        } else {
                            log.warn(LOG_PREFIX + " User ID claim not found for user: " + username);
                        }
                    } catch (org.wso2.carbon.user.api.UserStoreException e) {
                        log.warn(LOG_PREFIX + " Could not resolve User ID for user: " + username +
                                ". Post-authentication steps might fail.", e);
                    }

                    context.setSubject(authenticatedUser);

                } catch (UserStoreException e) {
                    log.error(LOG_PREFIX + " Error accessing user store", e);
                    throw new AuthenticationFailedException("Error accessing user store", e);
                }
            } else {
                log.error(LOG_PREFIX + " Username or password not found in VP payload");
                throw new AuthenticationFailedException("Credentials not found in VP");
            }

        } catch (VPException e) {
            log.error(LOG_PREFIX + " Error processing VP submission", e);
            throw new AuthenticationFailedException("Failed to process VP submission", e);
        }
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        log.info(LOG_PREFIX + " ========================================");
        log.info(LOG_PREFIX + " process() CALLED");
        log.info(LOG_PREFIX + " Session ID: " + context.getContextIdentifier());
        log.info(LOG_PREFIX + " ========================================");

        // Check if this is a polling request
        String poll = request.getParameter(PARAM_POLL);
        if ("true".equals(poll)) {
            log.info(LOG_PREFIX + " POLLING REQUEST detected");
            return handlePollRequest(request, response, context);
        }

        // Check if status is being reported
        String status = request.getParameter(PARAM_STATUS);
        if (StringUtils.isNotBlank(status)) {
            log.info(LOG_PREFIX + " STATUS CALLBACK detected: " + status);
            return handleStatusCallback(request, response, context, status);
        }

        log.info(LOG_PREFIX + " DEFAULT FLOW - calling super.process()");
        // Default behavior
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

            // Check if VP has been submitted
            if (VPRequestStatus.VP_SUBMITTED.equals(status) ||
                    VPRequestStatus.COMPLETED.equals(status)) {

                sendPollResponse(response, status.getValue().toLowerCase(), null);

                if (VPRequestStatus.COMPLETED.equals(status)) {
                    // VP verified, complete authentication
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                }
            } else if (VPRequestStatus.EXPIRED.equals(status)) {
                sendPollResponse(response, "expired", "Request expired");
                throw new AuthenticationFailedException("VP request has expired");
            } else if (VPRequestStatus.CANCELLED.equals(status)) {
                sendPollResponse(response, "cancelled", "Request was cancelled");
                throw new AuthenticationFailedException("VP request was cancelled");
            } else {
                // Still pending (ACTIVE)
                sendPollResponse(response, "pending", null);
            }

            return AuthenticatorFlowStatus.INCOMPLETE;

        } catch (VPException e) {
            log.error("Error checking VP request status", e);
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
            // Process the authentication response
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
            log.error("Error sending poll response", e);
        }
    }

    /**
     * Create a VP request for the authentication session.
     */
    private VPRequestResponseDTO createVPRequest(AuthenticationContext context) throws VPException {
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();

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
            log.debug(LOG_PREFIX + " Using presentation definition ID: " + presentationDefId);
            createDTO.setPresentationDefinitionId(presentationDefId);
        } else {
            // Create a default presentation definition requesting any verifiable credential
            log.info(LOG_PREFIX + " No presentation definition configured, using default inline definition");
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
            log.debug(LOG_PREFIX + " Resolving presentation definition for application: " + applicationId);

            String appDefinitionId = getApplicationPresentationDefinitionMappingService()
                    .getApplicationPresentationDefinitionId(applicationId, tenantId);

            if (StringUtils.isNotBlank(appDefinitionId)) {
                log.info(LOG_PREFIX + " Found application-specific presentation definition: " + appDefinitionId);
                return appDefinitionId;
            }

            log.debug(LOG_PREFIX + " No application-specific mapping found for: " + applicationId);
        } catch (Exception e) {
            log.warn(LOG_PREFIX + " Error looking up app-specific mapping, falling back to configuration", e);
        }

        // Step 2: Fall back to authenticator configuration
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String configId = authenticatorProperties.get(PROP_PRESENTATION_DEFINITION_ID);

            if (StringUtils.isNotBlank(configId)) {
                log.debug(LOG_PREFIX + " Using authenticator-configured presentation definition: " + configId);
                return configId;
            }

            log.debug(LOG_PREFIX + " No presentation definition in authenticator configuration");
        } catch (Exception e) {
            log.warn(LOG_PREFIX + " Error checking authenticator configuration", e);
        }

        // Step 3: Will use inline default
        log.debug(LOG_PREFIX + " No presentation definition configured, will use inline default");
        return null;
    }

    /**
     * Get the Application Presentation Definition Mapping Service.
     * 
     * @return ApplicationPresentationDefinitionMappingService
     * @throws VPException If service is not available
     */
    private org.wso2.carbon.identity.openid4vc.presentation.service.ApplicationPresentationDefinitionMappingService getApplicationPresentationDefinitionMappingService()
            throws VPException {
        org.wso2.carbon.identity.openid4vc.presentation.service.ApplicationPresentationDefinitionMappingService service = VPServiceDataHolder
                .getInstance().getApplicationPresentationDefinitionMappingService();

        if (service == null) {
            throw new VPException("Application Presentation Definition Mapping Service not available");
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
        presentationDef.addProperty("purpose", "Authenticate using your digital wallet");

        // Create input descriptors - accepts any VC
        JsonArray inputDescriptors = new JsonArray();
        JsonObject descriptor = new JsonObject();
        descriptor.addProperty("id", "any-credential");
        descriptor.addProperty("name", "Any Verifiable Credential");
        descriptor.addProperty("purpose", "Present any verifiable credential from your wallet");

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
     * Build client ID from context.
     */
    private String buildClientId(AuthenticationContext context) {
        // Use fixed DID for demo purposes as requested
        return "did:web:masked-unprofitably-ardith.ngrok-free.dev";
    }

    /**
     * Get tenant ID from authentication context.
     */
    private int getTenantId(AuthenticationContext context) {
        // Default to super tenant
        int tenantId = -1234;

        String tenantDomain = context.getTenantDomain();
        if (StringUtils.isNotBlank(tenantDomain)) {
            try {
                // In production, use TenantManager to resolve tenant ID
                // For now, use simple mapping
                if ("carbon.super".equals(tenantDomain)) {
                    tenantId = -1234;
                }
            } catch (Exception e) {
                log.warn("Error resolving tenant ID for domain: " + tenantDomain, e);
            }
        }

        return tenantId;
    }

    /**
     * Get login page URL.
     */
    private String getLoginPage(AuthenticationContext context) {
        String loginPage = IdentityUtil.getProperty("OpenID4VP.LoginPage");
        if (StringUtils.isBlank(loginPage)) {
            loginPage = "/authenticationendpoint/wallet_login.jsp";
        }
        return loginPage;
    }

    /**
     * Build query parameters for login page redirect.
     */
    private String buildQueryParams(VPRequestResponseDTO vpRequestResponse,
            String qrContent,
            AuthenticationContext context) {
        StringBuilder params = new StringBuilder();
        params.append("?");
        params.append("sessionDataKey=").append(context.getContextIdentifier());
        params.append("&requestId=").append(vpRequestResponse.getRequestId());
        params.append("&transactionId=").append(vpRequestResponse.getTransactionId());
        params.append("&requestUri=").append(urlEncode(vpRequestResponse.getRequestUri()));
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

    @Override
    protected boolean retryAuthenticationEnabled() {
        return false;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter("sessionDataKey");
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {
        String sessionDataKey = request.getParameter("sessionDataKey");
        String vpRequestId = request.getParameter(PARAM_VP_REQUEST_ID);
        String poll = request.getParameter(PARAM_POLL);
        String authenticator = request.getParameter("authenticator");
        String status = request.getParameter(PARAM_STATUS);

        log.info(LOG_PREFIX + " ========================================");
        log.info(LOG_PREFIX + " canHandle() CALLED");
        log.info(LOG_PREFIX + " sessionDataKey: " + sessionDataKey);
        log.info(LOG_PREFIX + " vpRequestId: " + vpRequestId);
        log.info(LOG_PREFIX + " poll: " + poll);
        log.info(LOG_PREFIX + " authenticator: " + authenticator);
        log.info(LOG_PREFIX + " status: " + status);
        log.info(LOG_PREFIX + " ========================================");

        // Handle polling requests from login page
        if (StringUtils.isNotBlank(poll) && StringUtils.isNotBlank(sessionDataKey)) {
            log.info(LOG_PREFIX + " canHandle=true (polling request)");
            return true;
        }

        // Handle status callbacks
        if (StringUtils.isNotBlank(status) && StringUtils.isNotBlank(sessionDataKey)) {
            log.info(LOG_PREFIX + " canHandle=true (status callback)");
            return true;
        }

        // Handle VP request callbacks
        if (StringUtils.isNotBlank(vpRequestId) && StringUtils.isNotBlank(sessionDataKey)) {
            log.info(LOG_PREFIX + " canHandle=true (VP request callback)");
            return true;
        }

        log.info(LOG_PREFIX + " canHandle=false (no matching condition)");
        return false;
    }

    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<>();

        Property presentationDefId = new Property();
        presentationDefId.setName(PROP_PRESENTATION_DEFINITION_ID);
        presentationDefId.setDisplayName("Presentation Definition ID");
        presentationDefId.setDescription("ID of the presentation definition to use for VP requests");
        presentationDefId.setDisplayOrder(1);
        presentationDefId.setRequired(false);
        configProperties.add(presentationDefId);

        Property responseMode = new Property();
        responseMode.setName(PROP_RESPONSE_MODE);
        responseMode.setDisplayName("Response Mode");
        responseMode.setDescription("Response mode for VP submissions (direct_post or direct_post.jwt)");
        responseMode.setDisplayOrder(2);
        responseMode.setDefaultValue("direct_post");
        responseMode.setRequired(false);
        configProperties.add(responseMode);

        Property timeout = new Property();
        timeout.setName(PROP_TIMEOUT_SECONDS);
        timeout.setDisplayName("Timeout (seconds)");
        timeout.setDescription("Timeout for VP requests in seconds");
        timeout.setDisplayOrder(3);
        timeout.setDefaultValue("300");
        timeout.setRequired(false);
        configProperties.add(timeout);

        Property clientId = new Property();
        clientId.setName(PROP_CLIENT_ID);
        clientId.setDisplayName("Client ID");
        clientId.setDescription("Client ID to use in VP requests (auto-generated if not specified)");
        clientId.setDisplayOrder(4);
        clientId.setRequired(false);
        configProperties.add(clientId);

        Property subjectClaim = new Property();
        subjectClaim.setName(PROP_SUBJECT_CLAIM);
        subjectClaim.setDisplayName("Subject Claim");
        subjectClaim.setDescription("Claim path to use as the authenticated subject identifier");
        subjectClaim.setDisplayOrder(5);
        subjectClaim.setDefaultValue("credentialSubject.id");
        subjectClaim.setRequired(false);
        configProperties.add(subjectClaim);

        return configProperties;
    }
}
