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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Utility class for handling CORS (Cross-Origin Resource Sharing) headers.
 */
public final class CORSUtil {

    private static final String HEADER_ORIGIN = "Origin";
    private static final String HEADER_ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
    private static final String HEADER_ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods";
    private static final String HEADER_ACCESS_CONTROL_ALLOW_HEADERS = "Access-Control-Allow-Headers";
    private static final String HEADER_ACCESS_CONTROL_MAX_AGE = "Access-Control-Max-Age";
    private static final String HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";
    private static final String HEADER_ACCESS_CONTROL_EXPOSE_HEADERS = "Access-Control-Expose-Headers";

    private static final String DEFAULT_ALLOWED_METHODS = "GET, POST, PUT, DELETE, OPTIONS";
    private static final String DEFAULT_ALLOWED_HEADERS = "Content-Type, Authorization, X-Requested-With, Accept, Origin, X-Tenant-Id, X-CSRF-Token";
    private static final String DEFAULT_EXPOSED_HEADERS = "Content-Type, X-Request-Id, X-Transaction-Id";
    private static final String DEFAULT_MAX_AGE = "86400"; // 24 hours

    private CORSUtil() {
        // Private constructor to prevent instantiation
    }

    /**
     * Add CORS headers to the response.
     *
     * @param request  The HTTP request
     * @param response The HTTP response
     */
    public static void addCORSHeaders(HttpServletRequest request, HttpServletResponse response) {
        String origin = request.getHeader(HEADER_ORIGIN);

        if (origin != null && !origin.isEmpty()) {
            // Allow the requesting origin
            response.setHeader(HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, origin);
            response.setHeader(HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        } else {
            // Allow all origins for simple requests without credentials
            response.setHeader(HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        }

        response.setHeader(HEADER_ACCESS_CONTROL_ALLOW_METHODS, DEFAULT_ALLOWED_METHODS);
        response.setHeader(HEADER_ACCESS_CONTROL_ALLOW_HEADERS, DEFAULT_ALLOWED_HEADERS);
        response.setHeader(HEADER_ACCESS_CONTROL_MAX_AGE, DEFAULT_MAX_AGE);
        response.setHeader(HEADER_ACCESS_CONTROL_EXPOSE_HEADERS, DEFAULT_EXPOSED_HEADERS);
    }

    /**
     * Add CORS headers with custom allowed methods.
     *
     * @param request        The HTTP request
     * @param response       The HTTP response
     * @param allowedMethods Comma-separated list of allowed HTTP methods
     */
    public static void addCORSHeaders(HttpServletRequest request, HttpServletResponse response,
            String allowedMethods) {
        addCORSHeaders(request, response);
        response.setHeader(HEADER_ACCESS_CONTROL_ALLOW_METHODS, allowedMethods);
    }

    /**
     * Add CORS headers for preflight requests.
     *
     * @param request  The HTTP request
     * @param response The HTTP response
     */
    public static void handlePreflight(HttpServletRequest request, HttpServletResponse response) {
        addCORSHeaders(request, response);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    /**
     * Check if this is a CORS preflight request.
     *
     * @param request The HTTP request
     * @return true if this is a preflight request
     */
    public static boolean isPreflightRequest(HttpServletRequest request) {
        return "OPTIONS".equalsIgnoreCase(request.getMethod())
                && request.getHeader("Access-Control-Request-Method") != null;
    }

    /**
     * Check if this is a CORS request (has Origin header).
     *
     * @param request The HTTP request
     * @return true if this is a CORS request
     */
    public static boolean isCORSRequest(HttpServletRequest request) {
        return request.getHeader(HEADER_ORIGIN) != null;
    }

    /**
     * Validate if the origin is allowed.
     *
     * @param request        The HTTP request
     * @param allowedOrigins Array of allowed origins (null or empty allows all)
     * @return true if the origin is allowed
     */
    public static boolean isOriginAllowed(HttpServletRequest request, String[] allowedOrigins) {
        if (allowedOrigins == null || allowedOrigins.length == 0) {
            return true; // Allow all
        }

        String origin = request.getHeader(HEADER_ORIGIN);
        if (origin == null || origin.isEmpty()) {
            return true; // Not a CORS request
        }

        for (String allowed : allowedOrigins) {
            if ("*".equals(allowed) || origin.equals(allowed)) {
                return true;
            }
        }

        return false;
    }
}
