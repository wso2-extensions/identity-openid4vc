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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.util;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * Utility class for Servlets to handle common HTTP request parameters.
 */
public class ServletUtil {

    private static final String PARAM_LONG_POLL = "long_poll";
    private static final String PARAM_TIMEOUT = "timeout";
    private static final long MAX_TIMEOUT_SECONDS = 120L;
    private static final long DEFAULT_TIMEOUT_SECONDS = 5L;
    private static final int DEFAULT_TENANT_ID = -1234;

    private ServletUtil() {
    }

    /**
     * Check if long polling is enabled for this request.
     *
     * @param request HTTP request
     * @return true if long polling is enabled
     */
    @SuppressFBWarnings("SERVLET_PARAMETER")
    public static boolean isLongPollingEnabled(final HttpServletRequest request) {

        @SuppressFBWarnings("SERVLET_PARAMETER")
        String longPollParam = request.getParameter(PARAM_LONG_POLL);
        if (longPollParam != null) {
            return "true".equalsIgnoreCase(longPollParam)
                    || "1".equals(longPollParam);
        }

        // If timeout parameter is provided, assume long polling
        @SuppressFBWarnings("SERVLET_PARAMETER")
        String timeoutParam = request.getParameter(PARAM_TIMEOUT);
        return StringUtils.isNotBlank(timeoutParam);
    }

    /**
     * Get timeout seconds from request.
     *
     * @param request HTTP request
     * @return timeout seconds
     */
    @SuppressFBWarnings("SERVLET_PARAMETER")
    public static long getTimeoutSeconds(final HttpServletRequest request) {

        @SuppressFBWarnings("SERVLET_PARAMETER")
        String timeoutParam = request.getParameter(PARAM_TIMEOUT);
        if (StringUtils.isNotBlank(timeoutParam)) {
            try {
                long timeout = Long.parseLong(timeoutParam);
                if (timeout > 0 && timeout <= MAX_TIMEOUT_SECONDS) {
                    return timeout;
                }
                if (timeout > MAX_TIMEOUT_SECONDS) {
                    return MAX_TIMEOUT_SECONDS;
                }
            } catch (NumberFormatException e) {
            }
        }
        return DEFAULT_TIMEOUT_SECONDS;
    }

    /**
     * Get tenant ID from request.
     *
     * @param request HTTP request
     * @return tenant ID
     */
    @SuppressFBWarnings("SERVLET_HEADER")
    public static int getTenantId(final HttpServletRequest request) {

        String tenantHeader = request.getHeader("X-Tenant-Id");
        if (StringUtils.isNotBlank(tenantHeader)) {
            try {
                return Integer.parseInt(tenantHeader);
            } catch (NumberFormatException e) {
            }
        }
        return DEFAULT_TENANT_ID;
    }
}
