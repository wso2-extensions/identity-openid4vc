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

package org.wso2.carbon.identity.openid4vc.oid4vp.presentation.util;

/**
 * Utility class for sanitizing log messages to prevent CRLF injection attacks.
 * 
 * This class provides methods to remove or replace dangerous characters from
 * log messages that could be exploited for log forging or CRLF injection.
 */
public final class LogSanitizer {

    private LogSanitizer() {
        // Private constructor to prevent instantiation
    }

    /**
     * Sanitize a log message by removing carriage return and line feed characters.
     * 
     * @param message the message to sanitize
     * @return sanitized message with CRLF characters removed, or null if input is
     *         null
     */
    public static String sanitize(String message) {
        if (message == null) {
            return null;
        }

        // Remove carriage return and line feed characters to prevent CRLF injection
        return message.replace('\n', '_').replace('\r', '_');
    }

    /**
     * Sanitize a log message by removing CRLF and limiting length.
     * 
     * @param message   the message to sanitize
     * @param maxLength maximum length of the sanitized message
     * @return sanitized and truncated message, or null if input is null
     */
    public static String sanitize(String message, int maxLength) {
        String sanitized = sanitize(message);
        if (sanitized == null) {
            return null;
        }

        if (sanitized.length() > maxLength) {
            return sanitized.substring(0, maxLength) + "...";
        }

        return sanitized;
    }
}
