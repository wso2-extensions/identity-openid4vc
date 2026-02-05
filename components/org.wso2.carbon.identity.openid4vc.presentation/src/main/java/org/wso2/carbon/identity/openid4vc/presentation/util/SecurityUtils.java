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

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Security utility class for OpenID4VP operations.
 * Provides methods for secure random generation, input validation, and
 * sanitization.
 */
public final class SecurityUtils {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // Patterns for validation
    private static final Pattern DID_PATTERN = Pattern.compile("^did:[a-z]+:[a-zA-Z0-9._%-]+.*$");
    // URL_PATTERN removed to avoid ReDOS. Using URI validation instead.
    private static final Pattern NONCE_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");
    private static final Pattern STATE_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    // Maximum lengths for various fields
    private static final int MAX_NONCE_LENGTH = 256;
    private static final int MAX_STATE_LENGTH = 256;
    private static final int MAX_URL_LENGTH = 2048;
    private static final int MAX_DID_LENGTH = 1024;
    private static final int MAX_VP_TOKEN_LENGTH = 1024 * 1024; // 1 MB

    private SecurityUtils() {
        // Private constructor to prevent instantiation
    }

    /**
     * Generate a cryptographically secure random nonce.
     *
     * @return Base64URL encoded random nonce (32 bytes)
     */
    public static String generateNonce() {
        return generateNonce(32);
    }

    /**
     * Generate a cryptographically secure random nonce of specified length.
     *
     * @param byteLength the number of random bytes
     * @return Base64URL encoded random nonce
     */
    public static String generateNonce(int byteLength) {
        byte[] bytes = new byte[byteLength];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Generate a cryptographically secure state parameter.
     *
     * @return Base64URL encoded random state (24 bytes)
     */
    public static String generateState() {
        return generateNonce(24);
    }

    /**
     * Validate a DID string.
     *
     * @param did the DID to validate
     * @return true if valid
     */
    public static boolean isValidDID(String did) {
        if (StringUtils.isBlank(did)) {
            return false;
        }
        if (did.length() > MAX_DID_LENGTH) {
            return false;
        }
        return DID_PATTERN.matcher(did).matches();
    }

    /**
     * Validate a URL.
     *
     * @param url the URL to validate
     * @return true if valid
     */
    public static boolean isValidUrl(String url) {
        if (StringUtils.isBlank(url)) {
            return false;
        }
        if (url.length() > MAX_URL_LENGTH) {
            return false;
        }
        try {
            java.net.URI uri = new java.net.URI(url);
            return "http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme());
        } catch (java.net.URISyntaxException e) {
            return false;
        }
    }

    /**
     * Validate a nonce value.
     *
     * @param nonce the nonce to validate
     * @return true if valid
     */
    public static boolean isValidNonce(String nonce) {
        if (StringUtils.isBlank(nonce)) {
            return false;
        }
        if (nonce.length() > MAX_NONCE_LENGTH) {
            return false;
        }
        return NONCE_PATTERN.matcher(nonce).matches();
    }

    /**
     * Validate a state parameter.
     *
     * @param state the state to validate
     * @return true if valid
     */
    public static boolean isValidState(String state) {
        if (StringUtils.isBlank(state)) {
            return false;
        }
        if (state.length() > MAX_STATE_LENGTH) {
            return false;
        }
        return STATE_PATTERN.matcher(state).matches();
    }

    /**
     * Validate a UUID string.
     *
     * @param uuid the UUID to validate
     * @return true if valid
     */
    public static boolean isValidUUID(String uuid) {
        if (StringUtils.isBlank(uuid)) {
            return false;
        }
        return UUID_PATTERN.matcher(uuid).matches();
    }

    /**
     * Validate VP token size.
     *
     * @param vpToken the VP token to validate
     * @return true if valid size
     */
    public static boolean isValidVPTokenSize(String vpToken) {
        if (StringUtils.isBlank(vpToken)) {
            return false;
        }
        return vpToken.length() <= MAX_VP_TOKEN_LENGTH;
    }

    /**
     * Sanitize a string for logging (mask sensitive parts).
     *
     * @param value        the value to sanitize
     * @param visibleChars number of characters to show at start and end
     * @return sanitized string
     */
    public static String sanitizeForLogging(String value, int visibleChars) {
        if (StringUtils.isBlank(value)) {
            return "[empty]";
        }
        if (value.length() <= visibleChars * 2) {
            return "[masked]";
        }
        return value.substring(0, visibleChars) + "..." +
                value.substring(value.length() - visibleChars);
    }

    /**
     * Sanitize a DID for logging.
     *
     * @param did the DID to sanitize
     * @return sanitized DID
     */
    public static String sanitizeDIDForLogging(String did) {
        if (StringUtils.isBlank(did)) {
            return "[empty]";
        }
        // Show DID method and first/last few chars of specific-id
        String[] parts = did.split(":");
        if (parts.length < 3) {
            return sanitizeForLogging(did, 10);
        }
        String method = parts[1];
        String specificId = did.substring(("did:" + method + ":").length());
        return "did:" + method + ":" + sanitizeForLogging(specificId, 4);
    }

    /**
     * Check if a redirect URI is safe (HTTPS only, no fragments).
     *
     * @param redirectUri the redirect URI to check
     * @return true if safe
     */
    public static boolean isSafeRedirectUri(String redirectUri) {
        if (StringUtils.isBlank(redirectUri)) {
            return false;
        }

        // Must be HTTPS (except for localhost in development)
        String lowerUri = redirectUri.toLowerCase(Locale.ENGLISH);
        boolean isHttps = lowerUri.startsWith("https://");
        boolean isLocalhost = lowerUri.startsWith("http://localhost") ||
                lowerUri.startsWith("http://127.0.0.1");

        if (redirectUri.startsWith("/")) {
            // Relative URL is considered safe for redirection within the app
            return true;
        }

        if (!isHttps && !isLocalhost) {
            return false;
        }

        // Must not contain fragments
        if (redirectUri.contains("#")) {
            return false;
        }

        // Must be valid URL
        return isValidUrl(redirectUri);
    }

    /**
     * Constant-time string comparison to prevent timing attacks.
     *
     * @param a first string
     * @param b second string
     * @return true if equal
     */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return a == null && b == null;
        }
        if (a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    /**
     * Extract the DID method from a DID string.
     *
     * @param did the DID
     * @return the method (e.g., "web", "key", "jwk")
     */
    public static String extractDIDMethod(String did) {
        if (StringUtils.isBlank(did) || !did.startsWith("did:")) {
            return null;
        }
        String[] parts = did.split(":");
        if (parts.length < 3) {
            return null;
        }
        return parts[1];
    }

    /**
     * Check if a JWT is well-formed (basic structure check).
     *
     * @param jwt the JWT string
     * @return true if well-formed
     */
    public static boolean isWellFormedJWT(String jwt) {
        if (StringUtils.isBlank(jwt)) {
            return false;
        }
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            return false;
        }
        // Each part should be Base64URL encoded
        try {
            for (String part : parts) {
                if (part.isEmpty()) {
                    return false;
                }
                // Basic Base64URL character check
                if (!part.matches("^[A-Za-z0-9_-]+$")) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Calculate SHA-256 hash of a string.
     *
     * @param input the input string
     * @return hex-encoded hash
     */
    public static String sha256(String input) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Generate a challenge for PKCE-like flows.
     *
     * @return challenge string
     */
    public static String generateChallenge() {
        String verifier = generateNonce(32);
        return sha256(verifier).substring(0, 43); // S256 challenge
    }
}
