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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.openid4vc.presentation.cache.WalletDataCache;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Custom authenticator for Wallet-based authentication using Verifiable Presentations.
 */
public class WalletAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(WalletAuthenticator.class);

    private static final String AUTHENTICATOR_NAME = "WalletAuthenticator";
    private static final String AUTHENTICATOR_FRIENDLY_NAME = "Wallet Login";
    private static final String PARAM_STATE = "state";
    private static final String PARAM_WALLET_STATE = "walletState";
    private static final String SESSION_DATA_KEY = "sessionDataKey";
    private static final String WALLET_PAGE_URL = "/authenticationendpoint/wallet/login.jsp";
    private static final String WAIT_PAGE_URL = "/authenticationendpoint/wallet/wait.jsp";
    private static final String RETRY_PAGE_URL = "/authenticationendpoint/wallet/retry.jsp";
    private static final String PROCEED_AUTH = "proceedAuth";
    private static final String VP_TOKEN_NOT_FOUND = "vpTokenNotFound";
    private static final String VP_TOKEN_NOT_FOUND_MESSAGE = "VP token not received from wallet";
    private static final String AUTH_DENIED = "authDenied";
    private static final String AUTH_DENIED_MESSAGE = "Authentication denied by user";
    private static final String INVALID_VP_TOKEN = "invalidVpToken";
    private static final String INVALID_VP_TOKEN_MESSAGE = "Invalid VP token received";
    private static final String CONTEXT_WALLET_STATE = "walletState";
    private static final String CONTEXT_USER_EMAIL = "userEmail";

    @Override
    public boolean canHandle(HttpServletRequest request) {
        // Handle when proceedAuth is present (polling redirect back to complete auth)
        String proceedAuth = request.getParameter(PROCEED_AUTH);
        String walletState = request.getParameter(PARAM_WALLET_STATE);
        String sessionDataKey = request.getParameter(SESSION_DATA_KEY);

        boolean canHandle = (proceedAuth != null && "true".equalsIgnoreCase(proceedAuth.trim()));

        log.info("=== WalletAuthenticator.canHandle called ===");
        log.info("    proceedAuth=" + proceedAuth);
        log.info("    walletState=" + walletState);
        log.info("    sessionDataKey=" + sessionDataKey);
        log.info("    canHandle result=" + canHandle);

        if (log.isDebugEnabled()) {
            log.debug("WalletAuthenticator canHandle: " + canHandle +
                     " | proceedAuth=" + proceedAuth +
                     " | walletState=" + walletState);
        }

        return canHandle;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
            HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        log.info("=== WalletAuthenticator.initiateAuthenticationRequest CALLED ===");

        try {
            // Generate unique state parameter
            String state = UUID.randomUUID().toString();

            // Get sessionDataKey from request or context
            String sessionDataKey = request.getParameter(SESSION_DATA_KEY);
            if (sessionDataKey == null || sessionDataKey.trim().isEmpty()) {
                sessionDataKey = context.getContextIdentifier();
            }

            log.info("Generated state: " + state + ", sessionDataKey: " + sessionDataKey);

            // Store state in authentication context
            context.setProperty(CONTEXT_WALLET_STATE, state);

            if (log.isDebugEnabled()) {
                log.debug("Initiating wallet authentication with state: " + state +
                         " for sessionDataKey: " + sessionDataKey);
            }

            // Store context in cache
            WalletDataCache.getInstance().storeContext(sessionDataKey, context);

            // Build the wallet login page URL (QR code page)
            String authEndpoint = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
            if (log.isDebugEnabled()) {
                log.debug("Auth endpoint URL: " + authEndpoint);
            }

            String walletLoginPageUrl = authEndpoint.replace("login.do", "wallet/login.jsp");

            // Build query string with framework context
            String queryParams = null;
            try {
                queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                        context.getQueryParams(),
                        context.getCallerSessionKey(),
                        context.getContextIdentifier()
                );
            } catch (Exception e) {
                log.warn("Error building query string with FrameworkUtils, using manual construction", e);
            }

            // Build redirect URL
            StringBuilder redirectUrl = new StringBuilder(walletLoginPageUrl);
            redirectUrl.append("?");

            // Add walletState parameter (unique to this auth attempt)
            redirectUrl.append("walletState=").append(state);

            // Add framework query params if available
            if (queryParams != null && !queryParams.trim().isEmpty()) {
                redirectUrl.append("&").append(queryParams);
            } else {
                // If no query params from framework, manually add required params
                redirectUrl.append("&sessionDataKey=").append(sessionDataKey);
                if (context.getServiceProviderName() != null) {
                    redirectUrl.append("&spId=").append(context.getServiceProviderName());
                }
            }

            String finalRedirectUrl = redirectUrl.toString();

            log.info("=== REDIRECTING TO QR CODE PAGE: " + finalRedirectUrl + " ===");

            if (log.isDebugEnabled()) {
                log.debug("Redirecting to wallet login page (QR code): " + finalRedirectUrl);
            }

            response.sendRedirect(finalRedirectUrl);

            log.info("=== REDIRECT SENT SUCCESSFULLY ===");

        } catch (IOException e) {
            log.error("IO Error during wallet authentication initiation", e);
            throw new AuthenticationFailedException("Error initiating wallet authentication", e);
        } catch (Exception e) {
            log.error("Unexpected error during wallet authentication initiation", e);
            throw new AuthenticationFailedException("Error initiating wallet authentication", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
            HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        log.info("=== WalletAuthenticator.processAuthenticationResponse CALLED ===");

        try {
            // Step 1: Retrieve sessionDataKey from request
            String sessionDataKey = request.getParameter(SESSION_DATA_KEY);
            log.info("    sessionDataKey from request: " + sessionDataKey);

            if (sessionDataKey == null || sessionDataKey.trim().isEmpty()) {
                sessionDataKey = context.getContextIdentifier();
                log.info("    sessionDataKey from context: " + sessionDataKey);
            }

            if (sessionDataKey == null || sessionDataKey.trim().isEmpty()) {
                log.error("Session data key is missing from both request and context");
                throw new AuthenticationFailedException("Session data key is missing");
            }

            // Step 2: Retrieve walletState from request first (passed from JSP redirect)
            String state = request.getParameter(PARAM_WALLET_STATE);
            log.info("    walletState from request: " + state);

            // If not in request, try from context
            if (state == null || state.trim().isEmpty()) {
                state = (String) context.getProperty(CONTEXT_WALLET_STATE);
                log.info("    walletState from context property: " + state);
            }

            // If state not in current context, try to retrieve from cache
            if (state == null || state.trim().isEmpty()) {
                AuthenticationContext storedContext = WalletDataCache.getInstance().getContext(sessionDataKey);
                if (storedContext != null) {
                    state = (String) storedContext.getProperty(CONTEXT_WALLET_STATE);
                    log.info("    walletState from cached context: " + state);
                    // Copy state to current context
                    if (state != null) {
                        context.setProperty(CONTEXT_WALLET_STATE, state);
                    }
                }
            }

            if (state == null || state.trim().isEmpty()) {
                log.error("State not found in request, context, or cache");
                throw new AuthenticationFailedException("State not found in authentication context");
            }

            log.info("    Using state for token lookup: " + state);

            if (log.isDebugEnabled()) {
                log.debug("Processing authentication response for state: " + state);
            }

            // Step 3: Check if VP token exists (without removing it yet)
            boolean hasToken = WalletDataCache.getInstance().hasToken(state);
            log.info("    Token exists in cache: " + hasToken);

            if (!hasToken) {
                // Token not yet received - redirect to wait page which will auto-refresh
                log.info("    VP token not yet received, redirecting to wait page");
                if (log.isDebugEnabled()) {
                    log.debug("VP token not yet received for state: " + state + ", showing wait page");
                }
                redirectToWaitPage(response, sessionDataKey, state);
                return; // Don't proceed with authentication yet
            }

            // Step 4: Fetch VP token from cache (now remove it)
            String vpToken = WalletDataCache.getInstance().retrieveToken(state);
            if (vpToken == null || vpToken.trim().isEmpty()) {
                log.error("VP token not found in cache for state: " + state);
                throw new AuthenticationFailedException("VP token not found in cache for state: "
                    + state);
            }

            if (log.isDebugEnabled()) {
                log.debug("VP token received for state: " + state + ", processing authentication");
            }

            // Step 5: Decode and parse JWT to extract email
            log.info("    Extracting email from VP token...");
            String email = extractEmailFromJWT(vpToken);
            log.info("    Extracted email: " + email);

            if (log.isDebugEnabled()) {
                log.debug("Extracted email from VP token: " + email);
            }

            // Step 6: Validate user exists in user store
            log.info("    Validating user exists in user store...");
            if (!validateUserExists(email)) {
                log.error("User not found in user store: " + email);
                throw new AuthenticationFailedException("User not found: " + email);
            }
            log.info("    User validation: PASSED");

            // Step 7: Complete authentication - set authenticated user
            log.info("    Creating authenticated user...");
            AuthenticatedUser authenticatedUser = createAuthenticatedUser(email, context);
            context.setSubject(authenticatedUser);
            log.info("    Authentication context subject set to: " + email);

            // Clear context from cache
            WalletDataCache.getInstance().clearContext(sessionDataKey);
            log.info("    Cleared context from cache");

            log.info("=== AUTHENTICATION SUCCESSFUL for user: " + email + " ===");

            if (log.isDebugEnabled()) {
                log.debug("Authentication successful for user: " + email);
            }

        } catch (AuthenticationFailedException e) {
            log.error("Authentication failed: " + e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Error processing authentication response", e);
            throw new AuthenticationFailedException("Authentication processing failed", e);
        }
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(SESSION_DATA_KEY);
    }

    @Override
    public String getName() {
        return AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Extract email claim from JWT VP token.
     */
    private String extractEmailFromJWT(String vpToken) throws AuthenticationFailedException {
        try {
            // TODO: Implement full JWT signature verification

            // Split JWT into parts
            String[] jwtParts = vpToken.split("\\.");
            if (jwtParts.length != 3) {
                throw new AuthenticationFailedException("Invalid JWT format");
            }

            // Decode payload (second part)
            String payload = new String(Base64.getUrlDecoder().decode(jwtParts[1]),
                StandardCharsets.UTF_8);

            // Parse JSON payload
            JsonObject payloadJson = JsonParser.parseString(payload).getAsJsonObject();

            // Extract email from vc.credentialSubject or vp structure
            String email = null;
            if (payloadJson.has("vp")) {
                JsonObject vp = payloadJson.getAsJsonObject("vp");
                if (vp.has("verifiableCredential")) {
                    // Handle array of VCs
                    JsonObject vc = vp.getAsJsonArray("verifiableCredential")
                        .get(0).getAsJsonObject();
                    if (vc.has("credentialSubject")) {
                        JsonObject credentialSubject = vc.getAsJsonObject("credentialSubject");
                        if (credentialSubject.has("email")) {
                            email = credentialSubject.get("email").getAsString();
                        }
                    }
                }
            } else if (payloadJson.has("email")) {
                // Direct email claim
                email = payloadJson.get("email").getAsString();
            }

            if (email == null || email.trim().isEmpty()) {
                throw new AuthenticationFailedException("Email claim not found in VP token");
            }

            if (log.isDebugEnabled()) {
                log.debug("Extracted email from VP token: " + email);
            }

            return email;

        } catch (Exception e) {
            log.error("Error parsing JWT VP token", e);
            throw new AuthenticationFailedException("Failed to extract email from VP token", e);
        }
    }

    /**
     * Validate that user exists in user store.
     */
    private boolean validateUserExists(String email) {
        try {
            UserRealm userRealm = CarbonContext.getThreadLocalCarbonContext().getUserRealm();
            if (userRealm == null) {
                log.warn("User realm not found");
                return false;
            }

            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (!userStoreManager.isExistingUser(email)) {
                log.warn("User not found in user store: " + email);
                return false;
            }

            if (log.isDebugEnabled()) {
                log.debug("User exists in user store: " + email);
            }

            return true;

        } catch (UserStoreException e) {
            log.error("Error validating user existence", e);
            return false;
        }
    }

    /**
     * Create authenticated user object.
     */
    private AuthenticatedUser createAuthenticatedUser(String email, AuthenticationContext context) {
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(email);
        authenticatedUser.setUserName(email);

        // Set tenant domain
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        authenticatedUser.setTenantDomain(tenantDomain);

        // Set user store domain (default)
        authenticatedUser.setUserStoreDomain("PRIMARY");

        log.info("    Created AuthenticatedUser: username=" + email + ", tenant=" + tenantDomain);

        return authenticatedUser;
    }

    /**
     * Redirect to wallet presentation page.
     */
    private void redirectToWalletPage(HttpServletResponse response, String sessionDataKey,
            String state) throws IOException {
        StringBuilder redirectUrl = new StringBuilder();
        redirectUrl.append(WALLET_PAGE_URL)
                   .append("?").append(PARAM_STATE).append("=").append(state);

        if (sessionDataKey != null) {
            redirectUrl.append("&").append(SESSION_DATA_KEY).append("=").append(sessionDataKey);
        }

        if (log.isDebugEnabled()) {
            log.debug("Redirecting to wallet page: " + redirectUrl);
        }

        response.sendRedirect(redirectUrl.toString());
    }

    /**
     * Redirect to wait page - this page will auto-submit to check authentication status.
     */
    private void redirectToWaitPage(HttpServletResponse response, String sessionDataKey,
            String state) throws IOException {
        StringBuilder redirectUrl = new StringBuilder();
        redirectUrl.append(WAIT_PAGE_URL)
                   .append("?").append(PARAM_STATE).append("=").append(state);

        if (sessionDataKey != null) {
            redirectUrl.append("&").append(SESSION_DATA_KEY).append("=").append(sessionDataKey);
        }

        if (log.isDebugEnabled()) {
            log.debug("Redirecting to wait page for polling: " + redirectUrl);
        }

        response.sendRedirect(redirectUrl.toString());
    }

    /**
     * Redirect to retry page with error information.
     */
    private void redirectToRetryPage(HttpServletResponse response, String sessionDataKey,
            String errorCode) throws AuthenticationFailedException {
        try {
            StringBuilder redirectUrl = new StringBuilder();
            redirectUrl.append(RETRY_PAGE_URL)
                       .append("?").append(SESSION_DATA_KEY).append("=").append(sessionDataKey)
                       .append("&errorCode=").append(errorCode);

            if (log.isDebugEnabled()) {
                log.debug("Redirecting to retry page with error: " + errorCode);
            }

            response.sendRedirect(redirectUrl.toString());
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error redirecting to retry page", e);
        }
    }
}

