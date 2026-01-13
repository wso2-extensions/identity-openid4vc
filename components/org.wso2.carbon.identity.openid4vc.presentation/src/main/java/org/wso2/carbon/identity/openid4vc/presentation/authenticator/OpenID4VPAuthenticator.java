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
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPSubmissionService;
import org.wso2.carbon.identity.openid4vc.presentation.util.QRCodeUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OpenID4VP Wallet Authenticator for WSO2 Identity Server.
 * 
 * This authenticator implements the OpenID for Verifiable Presentations (OpenID4VP) protocol
 * to authenticate users by verifying their verifiable credentials from a digital wallet.
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
                    vpRequestResponse.getRequestUri());
            
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

        // Get transaction ID from session
        String transactionId = (String) context.getProperty(SESSION_TRANSACTION_ID);
        
        log.info(LOG_PREFIX + " Transaction ID from context: " + transactionId);
        
        if (StringUtils.isBlank(transactionId)) {
            log.error(LOG_PREFIX + " Transaction ID not found in session");
            throw new AuthenticationFailedException("Transaction ID not found in session");
        }

        try {
            // Get VP result
            VPSubmissionService submissionService = getVPSubmissionService();
            int tenantId = getTenantId(context);
            
            log.info(LOG_PREFIX + " Retrieving VP result for transaction: " + transactionId);
            log.info(LOG_PREFIX + " Tenant ID: " + tenantId);
            
            VPResultDTO result = submissionService.getVPResult(transactionId, tenantId);
            
            if (result == null) {
                log.error(LOG_PREFIX + " VP submission not found for transaction");
                throw new AuthenticationFailedException("VP submission not found for transaction");
            }
            
            log.info(LOG_PREFIX + " VP Result retrieved successfully");
            
            // Check for errors
            if (StringUtils.isNotBlank(result.getError())) {
                log.error(LOG_PREFIX + " Wallet returned error: " + result.getError());
                log.error(LOG_PREFIX + " Error description: " + result.getErrorDescription());
                String errorMsg = StringUtils.isNotBlank(result.getErrorDescription())
                        ? result.getErrorDescription()
                        : "Wallet returned error: " + result.getError();
                throw new AuthenticationFailedException(errorMsg);
            }
            
            // Check verification status from the VC results
            if (result.getVcVerificationResults() == null || result.getVcVerificationResults().isEmpty()) {
                log.error(LOG_PREFIX + " No verification results found");
                throw new AuthenticationFailedException("No verification results found");
            }
            
            log.info(LOG_PREFIX + " Number of VC verification results: " + result.getVcVerificationResults().size());
            
            // Check if all VCs are verified successfully
            for (org.wso2.carbon.identity.openid4vc.presentation.dto.VCVerificationResultDTO vcResult :
                    result.getVcVerificationResults()) {
                if (!vcResult.isSuccess()) {
                    log.error(LOG_PREFIX + " VC verification failed: " + vcResult.getError());
                    String errorMsg = StringUtils.isNotBlank(vcResult.getError())
                            ? vcResult.getError()
                            : "Credential verification failed";
                    throw new AuthenticationFailedException(errorMsg);
                }
            }
            
            // Extract authenticated user from VP
            AuthenticatedUser authenticatedUser = extractAuthenticatedUser(result, context);
            
            // Set authenticated user
            context.setSubject(authenticatedUser);
            
            // Store verification details in context for potential use by other components
            storeVerificationDetails(context, result);
            
            if (log.isDebugEnabled()) {
                log.debug("OpenID4VP authentication successful for user: " + 
                        authenticatedUser.getAuthenticatedSubjectIdentifier());
            }
            
        } catch (VPException e) {
            log.error("Error processing VP result", e);
            throw new AuthenticationFailedException("Failed to process VP result", e);
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
        
        // Set presentation definition ID or create default inline definition
        String presentationDefId = authenticatorProperties.get(PROP_PRESENTATION_DEFINITION_ID);
        if (StringUtils.isNotBlank(presentationDefId)) {
            createDTO.setPresentationDefinitionId(presentationDefId);
        } else {
            // Create a default presentation definition requesting any verifiable credential
            log.info(LOG_PREFIX + " No presentation definition configured, using default");
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
     * Create a default presentation definition that accepts any verifiable credential.
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
     * Extract authenticated user from VP result.
     */
    private AuthenticatedUser extractAuthenticatedUser(VPResultDTO result, 
                                                        AuthenticationContext context)
            throws AuthenticationFailedException {
        
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String subjectClaimPath = authenticatorProperties.get(PROP_SUBJECT_CLAIM);
        if (StringUtils.isBlank(subjectClaimPath)) {
            subjectClaimPath = "credentialSubject.id";
        }
        
        // For now, use the transaction ID as the subject identifier
        // In a full implementation, you would extract from the VP token claims
        String subjectId = result.getTransactionId();
        if (StringUtils.isBlank(subjectId)) {
            throw new AuthenticationFailedException("Subject identifier not found in presentation");
        }
        
        // Create authenticated user
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(subjectId);
        authenticatedUser.setTenantDomain(context.getTenantDomain());
        authenticatedUser.setFederatedUser(false);
        
        return authenticatedUser;
    }

    /**
     * Store verification details in authentication context.
     */
    private void storeVerificationDetails(AuthenticationContext context, VPResultDTO result) {
        Map<String, Object> vpDetails = new HashMap<>();
        vpDetails.put("transactionId", result.getTransactionId());
        vpDetails.put("vcVerificationResults", result.getVcVerificationResults());
        
        context.setProperty("openid4vp_verification_details", vpDetails);
    }

    /**
     * Build client ID from context.
     */
    private String buildClientId(AuthenticationContext context) {
        String baseUrl = IdentityUtil.getServerURL("", true, true);
        return baseUrl + "/oauth2/token";
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
