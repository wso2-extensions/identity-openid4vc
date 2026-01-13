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

package org.wso2.carbon.identity.openid4vc.presentation.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.constant.OpenID4VPConstants;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

/**
 * Utility class for OpenID4VP operations.
 */
public class OpenID4VPUtil {

    private static final Log log = LogFactory.getLog(OpenID4VPUtil.class);
    private static final SecureRandom secureRandom = new SecureRandom();

    private OpenID4VPUtil() {
        // Prevent instantiation
    }

    /**
     * Generate a unique request ID.
     *
     * @return A unique request ID
     */
    public static String generateRequestId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate a unique transaction ID.
     *
     * @return A unique transaction ID
     */
    public static String generateTransactionId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate a unique submission ID.
     *
     * @return A unique submission ID
     */
    public static String generateSubmissionId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate a cryptographically secure nonce.
     *
     * @return A secure nonce string
     */
    public static String generateNonce() {
        byte[] nonce = new byte[32];
        secureRandom.nextBytes(nonce);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
    }

    /**
     * Generate a state parameter.
     *
     * @return A secure state string
     */
    public static String generateState() {
        byte[] state = new byte[16];
        secureRandom.nextBytes(state);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(state);
    }

    /**
     * Get the VP request expiry time in seconds.
     *
     * @return Expiry time in seconds
     */
    public static int getVPRequestExpirySeconds() {
        String configValue = IdentityUtil.getProperty(OpenID4VPConstants.ConfigKeys.VP_REQUEST_EXPIRY_SECONDS);
        if (StringUtils.isNotBlank(configValue)) {
            try {
                return Integer.parseInt(configValue);
            } catch (NumberFormatException e) {
                log.warn("Invalid VP request expiry configuration: " + configValue +
                        ". Using default value.");
            }
        }
        return OpenID4VPConstants.Defaults.VP_REQUEST_EXPIRY_SECONDS;
    }

    /**
     * Calculate the expiry timestamp for a VP request.
     *
     * @param createdAt The creation timestamp
     * @return The expiry timestamp
     */
    public static long calculateExpiryTime(long createdAt) {
        return createdAt + (getVPRequestExpirySeconds() * 1000L);
    }

    /**
     * Check if a timestamp is expired.
     *
     * @param expiresAt The expiry timestamp
     * @return true if the timestamp is in the past
     */
    public static boolean isExpired(long expiresAt) {
        return System.currentTimeMillis() > expiresAt;
    }

    /**
     * Get the default presentation definition ID from configuration.
     *
     * @return The default presentation definition ID or null
     */
    public static String getDefaultPresentationDefinitionId() {
        return IdentityUtil.getProperty(OpenID4VPConstants.ConfigKeys.DEFAULT_PRESENTATION_DEFINITION_ID);
    }

    /**
     * Check if the request_uri mode is enabled.
     *
     * @return true if request_uri mode is enabled
     */
    public static boolean isRequestUriEnabled() {
        String configValue = IdentityUtil.getProperty(OpenID4VPConstants.ConfigKeys.ENABLE_REQUEST_URI);
        return StringUtils.isBlank(configValue) || Boolean.parseBoolean(configValue);
    }

    /**
     * Check if request JWT signing is enabled.
     *
     * @return true if request JWT signing is enabled
     */
    public static boolean isRequestJwtEnabled() {
        String configValue = IdentityUtil.getProperty(OpenID4VPConstants.ConfigKeys.ENABLE_REQUEST_JWT);
        return Boolean.parseBoolean(configValue);
    }

    /**
     * Get the configured signing algorithm.
     *
     * @return The signing algorithm
     */
    public static String getSigningAlgorithm() {
        String configValue = IdentityUtil.getProperty(OpenID4VPConstants.ConfigKeys.SIGNING_ALGORITHM);
        return StringUtils.isNotBlank(configValue) ? configValue : OpenID4VPConstants.Defaults.SIGNING_ALGORITHM;
    }

    /**
     * Check if credential verification is enabled.
     *
     * @return true if verification is enabled
     */
    public static boolean isVerificationEnabled() {
        String configValue = IdentityUtil.getProperty(OpenID4VPConstants.ConfigKeys.VERIFICATION_ENABLED);
        return StringUtils.isBlank(configValue) || Boolean.parseBoolean(configValue);
    }

    /**
     * Check if revocation checking is enabled.
     *
     * @return true if revocation checking is enabled
     */
    public static boolean isRevocationCheckEnabled() {
        String configValue = IdentityUtil.getProperty(OpenID4VPConstants.ConfigKeys.REVOCATION_CHECK_ENABLED);
        return Boolean.parseBoolean(configValue);
    }

    /**
     * Build the authorization request URL for a VP request.
     *
     * @param baseUrl   The base URL of the authorization server
     * @param requestId The request ID
     * @return The full authorization request URL
     */
    public static String buildAuthorizationRequestUrl(String baseUrl, String requestId) {
        StringBuilder url = new StringBuilder(baseUrl);
        if (!baseUrl.endsWith("/")) {
            url.append("/");
        }
        url.append("oauth2/authorize?");
        url.append(OpenID4VPConstants.RequestParams.REQUEST_URI).append("=");
        url.append(buildRequestUri(baseUrl, requestId));
        return url.toString();
    }

    /**
     * Build the request URI for a VP request.
     *
     * @param baseUrl   The base URL of the authorization server
     * @param requestId The request ID
     * @return The request URI
     */
    public static String buildRequestUri(String baseUrl, String requestId) {
        StringBuilder uri = new StringBuilder(baseUrl);
        if (!baseUrl.endsWith("/")) {
            uri.append("/");
        }
        uri.append("api/openid4vp/v1");
        uri.append(OpenID4VPConstants.Endpoints.REQUEST_URI);
        uri.append("/").append(requestId);
        return uri.toString();
    }

    /**
     * Build the response URI for a VP request.
     *
     * @param baseUrl The base URL of the authorization server
     * @return The response URI
     */
    public static String buildResponseUri(String baseUrl) {
        StringBuilder uri = new StringBuilder(baseUrl);
        if (!baseUrl.endsWith("/")) {
            uri.append("/");
        }
        uri.append("api/openid4vp/v1");
        uri.append(OpenID4VPConstants.Endpoints.VP_RESPONSE);
        return uri.toString();
    }

    /**
     * Build an OpenID4VP deep link URL.
     *
     * @param requestUri The request URI to include
     * @return The OpenID4VP deep link URL
     */
    public static String buildOpenID4VPDeepLink(String requestUri) {
        return OpenID4VPConstants.Protocol.OPENID4VP_SCHEME +
                "?" + OpenID4VPConstants.RequestParams.REQUEST_URI + "=" + requestUri;
    }

    /**
     * Validate a client ID.
     *
     * @param clientId The client ID to validate
     * @return true if the client ID is valid
     */
    public static boolean isValidClientId(String clientId) {
        return StringUtils.isNotBlank(clientId);
    }

    /**
     * Validate a nonce.
     *
     * @param nonce The nonce to validate
     * @return true if the nonce is valid
     */
    public static boolean isValidNonce(String nonce) {
        return StringUtils.isNotBlank(nonce) && nonce.length() >= 16;
    }

    /**
     * Sanitize a string for safe logging (remove potential injection attacks).
     *
     * @param input The input string
     * @return The sanitized string
     */
    public static String sanitizeForLogging(String input) {
        if (input == null) {
            return "null";
        }
        // Remove newlines and carriage returns to prevent log injection
        return input.replace("\n", "").replace("\r", "").replace("\t", "");
    }

    /**
     * Mask sensitive data for logging purposes.
     *
     * @param data      The data to mask
     * @param showChars Number of characters to show at the end
     * @return Masked string
     */
    public static String maskSensitiveData(String data, int showChars) {
        if (StringUtils.isBlank(data)) {
            return "***";
        }
        if (data.length() <= showChars) {
            return "***";
        }
        return "***" + data.substring(data.length() - showChars);
    }
}
