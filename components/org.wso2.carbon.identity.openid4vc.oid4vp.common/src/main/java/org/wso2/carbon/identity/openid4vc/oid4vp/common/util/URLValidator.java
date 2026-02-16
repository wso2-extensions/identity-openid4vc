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

package org.wso2.carbon.identity.openid4vc.oid4vp.common.util;

import org.apache.commons.lang.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Utility class for validating URLs to prevent unvalidated redirect
 * vulnerabilities.
 * 
 * Provides methods to validate redirect URIs against allowed schemes and
 * patterns.
 */
public final class URLValidator {

    private static final Set<String> ALLOWED_SCHEMES = new HashSet<>(
            Arrays.asList("http", "https", "openid4vp"));

    private URLValidator() {
        // Private constructor to prevent instantiation
    }

    /**
     * Validate a URL for basic security requirements.
     * 
     * @param url the URL to validate
     * @return true if the URL is valid and safe, false otherwise
     */
    public static boolean isValidURL(String url) {
        if (StringUtils.isBlank(url)) {
            return false;
        }

        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();

            // Check if scheme is allowed
            if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase(Locale.ENGLISH))) {
                return false;
            }

            // Additional validation for http/https schemes
            if ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) {
                String host = uri.getHost();
                if (StringUtils.isBlank(host)) {
                    return false;
                }

                // Prevent localhost redirects in production (can be configured)
                // For now, we allow all hosts but this can be restricted
            }

            return true;
        } catch (URISyntaxException e) {
            return false;
        }
    }

    /**
     * Validate a redirect URI against a whitelist of allowed URIs.
     * 
     * @param redirectUri the redirect URI to validate
     * @param allowedUris set of allowed redirect URIs
     * @return true if the redirect URI is in the whitelist, false otherwise
     */
    public static boolean isValidRedirectUri(String redirectUri, Set<String> allowedUris) {
        if (!isValidURL(redirectUri)) {
            return false;
        }

        if (allowedUris == null || allowedUris.isEmpty()) {
            // If no whitelist is provided, accept any valid URL
            return true;
        }

        return allowedUris.contains(redirectUri);
    }

    /**
     * Validate if a URL matches a base URL (for subdomain/path matching).
     * 
     * @param url     the URL to validate
     * @param baseUrl the base URL to match against
     * @return true if the URL is under the base URL, false otherwise
     */
    public static boolean matchesBaseUrl(String url, String baseUrl) {
        if (!isValidURL(url) || !isValidURL(baseUrl)) {
            return false;
        }

        try {
            URI uri = new URI(url);
            URI base = new URI(baseUrl);

            // Scheme must match
            if (!uri.getScheme().equalsIgnoreCase(base.getScheme())) {
                return false;
            }

            // Host must match or be a subdomain
            String host = uri.getHost();
            String baseHost = base.getHost();

            if (host == null || baseHost == null) {
                return false;
            }

            return host.equalsIgnoreCase(baseHost) || host.endsWith("." + baseHost);
        } catch (URISyntaxException e) {
            return false;
        }
    }
}
