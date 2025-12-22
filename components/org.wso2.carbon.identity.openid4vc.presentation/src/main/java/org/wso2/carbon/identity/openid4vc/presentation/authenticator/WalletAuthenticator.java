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
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.openid4vc.presentation.cache.WalletDataCache;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
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
    private static final String SESSION_DATA_KEY = "sessionDataKey";
    private static final String WALLET_PAGE_URL = "/wallet/login.jsp";

    @Override
    public boolean canHandle(HttpServletRequest request) {
        // Check if request contains wallet-specific parameters
        String state = request.getParameter(PARAM_STATE);
        return state != null && !state.trim().isEmpty();
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
            HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            // Generate unique state parameter
            String state = UUID.randomUUID().toString();

            // Store state in authentication context
            context.setProperty(PARAM_STATE, state);

            if (log.isDebugEnabled()) {
                log.debug("Initiating wallet authentication with state: " + state);
            }

            // Build redirect URL to wallet presentation page
            String redirectUrl = buildRedirectUrl(request, state, context);

            response.sendRedirect(redirectUrl);

        } catch (IOException e) {
            throw new AuthenticationFailedException("Error initiating wallet authentication", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
            HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            // Step 1: Retrieve state from request
            String receivedState = request.getParameter(PARAM_STATE);
            if (receivedState == null || receivedState.trim().isEmpty()) {
                throw new AuthenticationFailedException("State parameter is missing");
            }

            // Step 2: Validate state
            String expectedState = (String) context.getProperty(PARAM_STATE);
            if (!receivedState.equals(expectedState)) {
                log.error("State mismatch. Expected: " + expectedState + ", Received: " + receivedState);
                throw new AuthenticationFailedException("Invalid state parameter");
            }

            if (log.isDebugEnabled()) {
                log.debug("State validation successful for: " + receivedState);
            }

            // Step 3: Fetch VP token from cache
            String vpToken = WalletDataCache.getInstance().retrieveToken(receivedState);
            if (vpToken == null || vpToken.trim().isEmpty()) {
                throw new AuthenticationFailedException("VP token not found in cache for state: "
                    + receivedState);
            }

            // Step 4: Decode and parse JWT
            String email = extractEmailFromJWT(vpToken);

            // Step 5: Validate user exists
            validateUserExists(email);

            // Step 6: Complete authentication
            AuthenticatedUser authenticatedUser = createAuthenticatedUser(email, context);
            context.setSubject(authenticatedUser);

            if (log.isDebugEnabled()) {
                log.debug("Authentication successful for user: " + email);
            }

        } catch (AuthenticationFailedException e) {
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
    private void validateUserExists(String email) throws AuthenticationFailedException {
        try {
            UserRealm userRealm = CarbonContext.getThreadLocalCarbonContext().getUserRealm();
            if (userRealm == null) {
                throw new AuthenticationFailedException("User realm not found");
            }

            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (!userStoreManager.isExistingUser(email)) {
                log.warn("User not found in user store: " + email);
                throw new AuthenticationFailedException("User not found: " + email);
            }

            if (log.isDebugEnabled()) {
                log.debug("User exists in user store: " + email);
            }

        } catch (UserStoreException e) {
            log.error("Error validating user existence", e);
            throw new AuthenticationFailedException("User validation failed", e);
        }
    }

    /**
     * Create authenticated user object.
     */
    private AuthenticatedUser createAuthenticatedUser(String email, AuthenticationContext context) {
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(email);
        authenticatedUser.setUserName(email);

        // Set user attributes
        Map<ClaimMapping, String> attributes = new HashMap<>();
        attributes.put(ClaimMapping.build("http://wso2.org/claims/emailaddress",
            "email", null, false), email);
        authenticatedUser.setUserAttributes(attributes);

        // Set tenant domain
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        authenticatedUser.setTenantDomain(tenantDomain);

        return authenticatedUser;
    }

    /**
     * Build redirect URL to wallet presentation page.
     */
    private String buildRedirectUrl(HttpServletRequest request, String state,
            AuthenticationContext context) {
        String sessionDataKey = request.getParameter(SESSION_DATA_KEY);

        StringBuilder redirectUrl = new StringBuilder();
        redirectUrl.append(request.getContextPath())
                   .append(WALLET_PAGE_URL)
                   .append("?").append(PARAM_STATE).append("=").append(state);

        if (sessionDataKey != null) {
            redirectUrl.append("&").append(SESSION_DATA_KEY).append("=").append(sessionDataKey);
        }

        return redirectUrl.toString();
    }
}

