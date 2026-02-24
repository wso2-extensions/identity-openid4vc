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

package org.wso2.carbon.identity.openid4vc.oid4vp.presentation;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
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
import org.wso2.carbon.identity.openid4vc.oid4vp.presentation.cache.VPStatusListenerCache;
import org.wso2.carbon.identity.openid4vc.oid4vp.presentation.cache.WalletDataCache;
import org.wso2.carbon.identity.openid4vc.oid4vp.presentation.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.oid4vp.presentation.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.oid4vp.presentation.util.QRCodeUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.dto.DescriptorMapDTO;
import org.wso2.carbon.identity.openid4vc.presentation.common.dto.PresentationSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.common.dto.VPRequestCreateDTO;
import org.wso2.carbon.identity.openid4vc.presentation.common.dto.VPRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.common.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.common.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.common.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.common.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.common.util.SecurityUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
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
        implements FederatedApplicationAuthenticator, VPStatusListenerCache.StatusCallback {

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
    private static final String PROP_PRESENTATION_DEFINITION_ID = "presentationDefinition";
    private static final String PROP_RESPONSE_MODE = "ResponseMode";
    private static final String PROP_TIMEOUT_SECONDS = "TimeoutSeconds";
    private static final String PROP_CLIENT_ID = "ClientId";
    private static final String PROP_DID_METHOD = "DIDMethod";
    private static final String PROP_SUBJECT_CLAIM = "SubjectClaim";

    private static final int DISPLAY_ORDER_3 = 3;
    private static final int DISPLAY_ORDER_4 = 4;
    private static final int DISPLAY_ORDER_5 = 5;
    private static final int SUPER_TENANT_ID_PLACEHOLDER = -1234;

    // Instance variable to store received VP submission (direct processing)
    private volatile VPSubmission receivedSubmission;

    // StatusCallback interface implementation for direct processing
    @Override
    public void onStatusChange(String status) {
        // Legacy callback - not used in direct processing
    }

    @Override
    public void onTimeout() {
        // Timeout callback - not used in direct processing
    }

    @Override
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public void onSubmissionReceived(VPSubmission submission) {
        // Direct processing: store submission for processAuthenticationResponse
        this.receivedSubmission = submission;
    }

    @Override
    public String getName() {
        return AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    @SuppressFBWarnings("UNVALIDATED_REDIRECT")
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

            // Register this authenticator as a listener for direct processing
            VPStatusListenerCache listenerCache = VPStatusListenerCache.getInstance();
            listenerCache.registerListener(
                    vpRequestResponse.getRequestId(),
                    "auth-" + context.getContextIdentifier(),
                    this  // Pass this authenticator instance as the callback
            );

            // Generate QR code content
            String qrContent = QRCodeUtil.generateRequestUriQRContent(
                    vpRequestResponse.getRequestUri(),
                    vpRequestResponse.getAuthorizationDetails().getClientId());

            // Redirect to login page with QR code data
            String loginPage = getLoginPage(context);
            String queryParams = buildQueryParams(vpRequestResponse, qrContent, context);

            String redirectUrl = loginPage + queryParams;
            if (!SecurityUtils.isSafeRedirectUri(redirectUrl)) {
                throw new AuthenticationFailedException("Invalid redirect URL");
            }
            response.sendRedirect(redirectUrl);

        } catch (VPException e) {
            throw new AuthenticationFailedException("Failed to create VP request", e);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Failed to redirect to login page", e);
        }
    }

    /**
     * Extract VP token format from presentation_submission.
     * Uses the standard DIF Presentation Exchange descriptor_map to identify the format.
     *
     * @param submission VP submission containing presentation_submission JSON
     * @return Format string (e.g., "vc+sd-jwt", "ldp_vp", "jwt_vp", "jwt_vp_json")
     * @throws VPException If presentation_submission is missing, invalid, or format cannot be determined
     */
    private String extractVPTokenFormat(VPSubmission submission) throws VPException {
        String presentationSubmissionJson = submission.getPresentationSubmission();

        if (StringUtils.isBlank(presentationSubmissionJson)) {
            throw new VPException("presentation_submission is required but was not provided");
        }

        try {
            Gson gson = new Gson();
            PresentationSubmissionDTO presentationSubmission = gson.fromJson(
                    presentationSubmissionJson, PresentationSubmissionDTO.class);

            if (presentationSubmission == null) {
                throw new VPException("presentation_submission could not be parsed");
            }

            java.util.List<DescriptorMapDTO> descriptorMap = presentationSubmission.getDescriptorMap();
            if (descriptorMap == null || descriptorMap.isEmpty()) {
                throw new VPException("descriptor_map is empty in presentation_submission");
            }

            // Get format from first descriptor entry
            DescriptorMapDTO firstDescriptor = descriptorMap.get(0);
            String format = firstDescriptor.getFormat();

            if (StringUtils.isBlank(format)) {
                throw new VPException("format field is missing in descriptor_map");
            }

            // Normalize format string to handle variations for sd-jwt
            // Examples: "vc sd-jwt" -> "vc+sd-jwt", "vc_sd_jwt" -> "vc+sd-jwt"
            String normalizedFormat = format.trim()
                    .toLowerCase(Locale.ENGLISH);
                    
            if ("vc sd-jwt".equals(normalizedFormat) || "vc_sd_jwt".equals(normalizedFormat) 
                    || "vc_sd-jwt".equals(normalizedFormat)) {
                normalizedFormat = "vc+sd-jwt";
            }

            return normalizedFormat;


        } catch (JsonSyntaxException e) {
            throw new VPException("Invalid presentation_submission JSON: " + e.getMessage(), e);
        }
    }


    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {

        // Retrieve Session Info first to get requestId
        String requestId = (String) context.getProperty(SESSION_VP_REQUEST_ID);

        // Try to get submission from instance variable (direct listener) or Cache (polling/redirect)
        VPSubmission submission = this.receivedSubmission;
        if (submission == null && StringUtils.isNotBlank(requestId)) {
            // Fallback: Check WalletDataCache
             submission = WalletDataCache.getInstance().getSubmission(requestId);
        }

        if (submission == null) {
            throw new AuthenticationFailedException("No VP submission received");
        }

        try {
            int tenantId = getTenantId(context);
            VPRequest vpRequest = null;
            PresentationDefinition presentationDefinition = null;

            if (StringUtils.isNotBlank(requestId)) {
                try {
                    vpRequest = getVPRequestService().getVPRequestById(requestId, tenantId);
                    if (vpRequest != null && StringUtils.isNotBlank(vpRequest.getPresentationDefinitionId())) {
                        presentationDefinition = VPServiceDataHolder.getInstance()
                                .getPresentationDefinitionService()
                                .getPresentationDefinitionById(vpRequest.getPresentationDefinitionId(), tenantId);
                    }
                } catch (VPException e) {
                    // Ignore for now or handle appropriately
                }
            }

            String format = extractVPTokenFormat(submission);
            String vpToken = submission.getVpToken();
            String username = null;
            Map<String, Object> verifiedClaims = new HashMap<>();

            if (OpenID4VPConstants.VCFormats.VC_SD_JWT.equals(format)) {
                String expectedNonce = (vpRequest != null) ? vpRequest.getNonce() : "unknown";
                String expectedAudience = (vpRequest != null) ? vpRequest.getClientId() : "unknown";
                String pdJson = (presentationDefinition != null) ? presentationDefinition.getDefinitionJson() : "{}";
                
                // Call VC Verification Service
                verifiedClaims = VPServiceDataHolder.getInstance().getVCVerificationService()
                    .verifySdJwtToken(vpToken, expectedNonce, expectedAudience, pdJson);

                if (verifiedClaims.containsKey("email")) {
                    username = (String) verifiedClaims.get("email");
                } else if (verifiedClaims.containsKey("username")) {
                    username = (String) verifiedClaims.get("username");
                } else if (verifiedClaims.containsKey("sub")) {
                    username = (String) verifiedClaims.get("sub");
                }
            
            } else {
                // Legacy / Other formats
                try {
                    // Verify basic signature/expiry
                    VPServiceDataHolder.getInstance().getVCVerificationService().verifyVPToken(vpToken);
                } catch (Exception e) {
                     throw new AuthenticationFailedException("VP Token verification failed: " + e.getMessage(), e);
                }

                JsonObject vpData = null;
                if (OpenID4VPConstants.VCFormats.LDP_VP.equals(format)) {
                    vpData = JsonParser.parseString(vpToken).getAsJsonObject();
                } else if (OpenID4VPConstants.VCFormats.JWT_VP.equals(format) ||
                           OpenID4VPConstants.VCFormats.JWT_VP_JSON.equals(format)) {
                    String[] parts = vpToken.split("\\.");
                    if (parts.length >= 2) {
                        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
                        vpData = JsonParser.parseString(payload).getAsJsonObject();
                    }
                }
                
                if (vpData != null) {
                    username = extractUsernameFromVpData(vpData);
                }
            }

            if (StringUtils.isBlank(username)) {
                throw new AuthenticationFailedException("No user identifier found in verified credentials");
            }

            AuthenticatedUser authenticatedUser = AuthenticatedUser
                    .createFederateAuthenticatedUserFromSubjectIdentifier(username);
            authenticatedUser.setFederatedUser(true);
            if (context.getExternalIdP() != null) {
                authenticatedUser.setFederatedIdPName(context.getExternalIdP().getIdPName());
            }
            authenticatedUser.setTenantDomain(context.getTenantDomain());

            // Map Attributes
            ClaimMapping[] idpClaimMappings = new ClaimMapping[0];
            if (context.getExternalIdP() != null) {
                idpClaimMappings = context.getExternalIdP().getClaimMappings();
            }

            Map<ClaimMapping, String> userAttributes;
            if (!verifiedClaims.isEmpty()) {
                userAttributes = mapVerifiedClaimsToLocal(verifiedClaims, idpClaimMappings);
            } else {
                userAttributes = extractClaimsFromVP(vpToken, idpClaimMappings);
            }

            authenticatedUser.setUserAttributes(userAttributes);
            context.setSubject(authenticatedUser);

        } catch (VPException | RuntimeException e) {
            throw new AuthenticationFailedException("Authentication failed: " + e.getMessage(), e);
        }
    }

    /**
     * Helper to extract username from generic VP Data (JSON-LD/JWT Payload).
     */
    private String extractUsernameFromVpData(JsonObject vpData) {
        // Wrapper for the existing logic to keep the main method clean
        // ... (Logic from original method) ...
        try {
            JsonObject vp = vpData.has("vp") ? vpData.getAsJsonObject("vp") : vpData;
            if (!vp.has("verifiableCredential")) {
                return null;
            }

            JsonElement vcElement = vp.get("verifiableCredential");
            String vcToken = null;

            if (vcElement.isJsonArray() && vcElement.getAsJsonArray().size() > 0) {
               JsonElement first = vcElement.getAsJsonArray().get(0);
               if (first.isJsonPrimitive()) {
                   vcToken = first.getAsString();
               } else if (first.isJsonObject()) {
                   return extractSubjectFromJsonObject(first.getAsJsonObject());
               }
            } else if (vcElement.isJsonPrimitive()) {
                vcToken = vcElement.getAsString();
            } else if (vcElement.isJsonObject()) {
                return extractSubjectFromJsonObject(vcElement.getAsJsonObject());
            }

            if (vcToken != null) {
                 return extractSubjectFromJwt(vcToken);
            }
        } catch (RuntimeException e) {
            // Ignore extraction errors
        }
        return null;
    }

    private String extractSubjectFromJsonObject(JsonObject vcObj) {
        if (vcObj.has("credentialSubject")) {
            JsonObject cs = vcObj.getAsJsonObject("credentialSubject");
            if (cs.has("email")) {
                return cs.get("email").getAsString();
            }
            if (cs.has("username")) {
                return cs.get("username").getAsString();
            }
            if (cs.has("id")) {
                return cs.get("id").getAsString();
            }
        }
        return null;
    }

    private String extractSubjectFromJwt(String jwt) {
         try {
             String part = jwt.contains("~") ? jwt.split("~")[0] : jwt;
             String[] parts = part.split("\\.");
             if (parts.length < 2) {
                 return null;
             }
             String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
             JsonObject json = JsonParser.parseString(payload).getAsJsonObject();
             // Handle standard JWT payload or nested vc
             if (json.has("vc")) {
                 return extractSubjectFromJsonObject(json.getAsJsonObject("vc"));
             } else {
                 return extractSubjectFromJsonObject(json);
             }
         } catch (RuntimeException e) { 
             return null; 
         }
    }
    
    /**
     * Map Verified Claims map to WSO2 Claim Mappings.
     */
    private Map<ClaimMapping, String> mapVerifiedClaimsToLocal(Map<String, Object> verifiedClaims, 
                                                              ClaimMapping[] idpClaimMappings) {
        Map<ClaimMapping, String> mappedClaims = new HashMap<>();
        if (idpClaimMappings == null || idpClaimMappings.length == 0) {
             // If no mappings, return all as local claims (backward compatibility)
             for (Map.Entry<String, Object> entry : verifiedClaims.entrySet()) {
                 mappedClaims.put(ClaimMapping.build(entry.getKey(), entry.getKey(), null, false), 
                                  entry.getValue().toString());
             }
             return mappedClaims;
        }

        for (ClaimMapping mapping : idpClaimMappings) {
            String remoteClaim = mapping.getRemoteClaim().getClaimUri();
            // Try direct match first
            if (verifiedClaims.containsKey(remoteClaim)) {
                mappedClaims.put(mapping, verifiedClaims.get(remoteClaim).toString());
            } else {
                // Try to find in credentialSubject if not found at top level
                if (verifiedClaims.containsKey("credentialSubject")) {
                    Object cs = verifiedClaims.get("credentialSubject");
                    if (cs instanceof Map) {
                        Map<?, ?> csMap = (Map<?, ?>) cs;
                        if (csMap.containsKey(remoteClaim)) {
                            mappedClaims.put(mapping, csMap.get(remoteClaim).toString());
                            continue;
                        }
                    }
                }
                
                // Try to find in vc.credentialSubject (nested VC)
                if (verifiedClaims.containsKey("vc")) {
                    Object vc = verifiedClaims.get("vc");
                    if (vc instanceof Map) {
                        Map<?, ?> vcMap = (Map<?, ?>) vc;
                        if (vcMap.containsKey("credentialSubject")) {
                            Object cs = vcMap.get("credentialSubject");
                            if (cs instanceof Map) {
                                Map<?, ?> csMap = (Map<?, ?>) cs;
                                if (csMap.containsKey(remoteClaim)) {
                                    mappedClaims.put(mapping, csMap.get(remoteClaim).toString());
                                }
                            }
                        }
                    }
                }
            }
        }
        return mappedClaims;
    }

    // --- SD-JWT Verification Methods ---



    @Override
    @SuppressFBWarnings("SERVLET_PARAMETER")
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

                sendPollResponse(response, status.getValue().toLowerCase(Locale.ENGLISH), null);

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
    @SuppressFBWarnings("XSS_SERVLET")
    private void sendPollResponse(HttpServletResponse response, String status, String error) {
        try {
            response.setContentType("application/json;charset=UTF-8");

            JsonObject json = new JsonObject();
            json.addProperty("status", status);
            if (error != null) {
                // Sanitize error message to prevent XSS (though JSON encoding usually handles
                // it)
                json.addProperty("error", org.apache.commons.lang.StringEscapeUtils.escapeHtml(error));
            }

            response.getWriter().print(json.toString());
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

        // Set Signing Algorithm (Default to EdDSA)
        String signingAlgorithm = authenticatorProperties.get(OpenID4VPConstants.ConfigKeys.SIGNING_ALGORITHM);
        if (StringUtils.isBlank(signingAlgorithm)) {
            signingAlgorithm = OpenID4VPConstants.Verification.ALG_EDDSA;
        }
        createDTO.setSigningAlgorithm(signingAlgorithm);

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

    /**
     * Resolve the presentation definition ID for the application.
     * 
     * The presentation definition ID is stored directly in the authenticator configuration.
     * The listener handles creating the definition and updating the configuration with the ID.
     * 
     * @param context Authentication context
     * @return Presentation definition ID or null
     * @throws VPException If error occurs during resolution
     */
    @SuppressFBWarnings({ "DE_MIGHT_IGNORE", "REC_CATCH_EXCEPTION" })
    private String resolvePresentationDefinitionId(AuthenticationContext context) throws VPException {

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String configId = authenticatorProperties.get(PROP_PRESENTATION_DEFINITION_ID);

            if (StringUtils.isNotBlank(configId)) {
                // If the value looks like a JSON object (starts with {), it means the listener hasn't
                // processed it yet or failed to update it. We should handle this gracefully.
                if (configId.trim().startsWith("{")) {
                    // Fallback: try to resolve by resource ID as before, or log warning
                    // Ideally the listener ensures this is a UUID.
                    // For now, let's try to assume it might be a raw JSON and we can't use it as ID.
                    // But wait — if it IS raw JSON, we can't use it as an ID for the request.
                    // So we must rely on the listener having done its job.
                    // However, for safety, let's try to fetch by Resource ID if the property is not a valid UUID.
                    return resolveByResourceId(context);
                }
                return configId;
            }

        } catch (Exception e) {
            // Ignored: Config might not be available
        }

        // Fallback or default
        return null;
    }

    /**
     * Fallback resolution by Resource ID if simpler property lookup fails.
     */
    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
    private String resolveByResourceId(AuthenticationContext context) {
        try {
            String applicationId = context.getServiceProviderName();
            int tenantId = getTenantId(context);
            
            ApplicationManagementService applicationMgtService = VPServiceDataHolder.getInstance()
                    .getApplicationManagementService();
            if (applicationMgtService != null) {
                ServiceProvider serviceProvider = applicationMgtService.getServiceProvider(applicationId,
                        context.getTenantDomain());
                if (serviceProvider != null) {
                    String appResourceId = serviceProvider.getApplicationResourceId();
                    if (StringUtils.isNotBlank(appResourceId)) {
                         PresentationDefinition pd = VPServiceDataHolder.getInstance()
                                 .getPresentationDefinitionService()
                                .getPresentationDefinitionByResourceId(appResourceId, tenantId);
                        if (pd != null) {
                            return pd.getDefinitionId();
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
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
                // Ignored: Failed to resolve tenant ID, using default
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
     * Extract claims from VP token for federated user attributes.
     * When IDP claim mappings are configured, only extracts the mapped claims
     * and validates that all required claims are present in the VC.
     * When no mappings are configured, extracts all credentialSubject fields
     * (backward compatible).
     *
     * @param vpToken Raw VP token (JWT or JSON-LD)
     * @param idpClaimMappings Claim mappings configured on the IDP
     * @return Map of claim mappings to values
     */
    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
    private Map<ClaimMapping, String> extractClaimsFromVP(
            final String vpToken, final ClaimMapping[] idpClaimMappings) {
        Map<ClaimMapping, String> claims = new HashMap<>();

        try {
            JsonObject vpData = null;
            String trimmedToken = vpToken.trim();

            // Minimal parsing logic to find credentialSubject
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

                if (idpClaimMappings != null && idpClaimMappings.length > 0) {
                    // IDP claim mappings configured: validate and extract only mapped claims
                    List<String> missingClaims = new ArrayList<>();

                    for (ClaimMapping mapping : idpClaimMappings) {
                        String remoteClaim = mapping.getRemoteClaim().getClaimUri();
                        if (!hasNestedValue(subject, remoteClaim)) {
                            missingClaims.add(remoteClaim);
                        } else {
                            String value = getNestedValue(subject, remoteClaim);
                            if (value != null) {
                                claims.put(mapping, value);
                            }
                        }
                    }

                    if (!missingClaims.isEmpty()) {
                        throw new VPException(
                                "VC missing required claims: "
                                        + String.join(", ", missingClaims));
                    }
                } else {
                    // No IDP claim mappings: extract all (backward compatible)
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
            }
        } catch (VPException vpEx) {
            throw new RuntimeException(vpEx.getMessage(), vpEx);
        } catch (Exception e) {
            // ignore parsing errors for backward compatibility
        }

        return claims;
    }

    /**
     * Check if a nested value exists in a JsonObject using a dotted path.
     * Supports paths like "email", "degree.type", "address.street.name".
     *
     * @param obj  The JsonObject to search
     * @param path Dotted path (e.g. "degree.type")
     * @return true if the value exists and is not null
     */
    private boolean hasNestedValue(final JsonObject obj, final String path) {
        String[] parts = path.split("\\.");
        JsonObject current = obj;
        for (int i = 0; i < parts.length - 1; i++) {
            if (!current.has(parts[i]) || !current.get(parts[i]).isJsonObject()) {
                return false;
            }
            current = current.getAsJsonObject(parts[i]);
        }
        String lastKey = parts[parts.length - 1];
        return current.has(lastKey) && !current.get(lastKey).isJsonNull();
    }

    /**
     * Extract a value from a JsonObject using a dotted path.
     * Returns the string value of the leaf element, or null if not found.
     *
     * @param obj  The JsonObject to search
     * @param path Dotted path (e.g. "degree.type")
     * @return The string value, or null
     */
    private String getNestedValue(final JsonObject obj, final String path) {
        String[] parts = path.split("\\.");
        JsonObject current = obj;
        for (int i = 0; i < parts.length - 1; i++) {
            if (!current.has(parts[i]) || !current.get(parts[i]).isJsonObject()) {
                return null;
            }
            current = current.getAsJsonObject(parts[i]);
        }
        String lastKey = parts[parts.length - 1];
        JsonElement val = current.get(lastKey);
        if (val == null || val.isJsonNull()) {
            return null;
        }
        return val.isJsonPrimitive() ? val.getAsString() : val.toString();
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
    @SuppressFBWarnings("SERVLET_PARAMETER")
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
    @SuppressFBWarnings("SERVLET_PARAMETER")
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
