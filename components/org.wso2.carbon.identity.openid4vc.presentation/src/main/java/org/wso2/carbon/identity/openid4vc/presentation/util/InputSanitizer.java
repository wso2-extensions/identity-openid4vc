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

import org.apache.commons.lang.StringEscapeUtils;

/**
 * Utility class for sanitizing user inputs to prevent XSS attacks.
 * 
 * Provides methods to encode and sanitize strings that will be included
 * in HTML, JSON, or other output formats.
 */
public final class InputSanitizer {

    private InputSanitizer() {
        // Private constructor to prevent instantiation
    }

    /**
     * Sanitize input for safe inclusion in HTML.
     * 
     * @param input the input to sanitize
     * @return HTML-encoded string, or null if input is null
     */
    public static String sanitizeForHTML(String input) {
        if (input == null) {
            return null;
        }

        return StringEscapeUtils.escapeHtml(input);
    }

    /**
     * Sanitize input for safe inclusion in JSON.
     * 
     * @param input the input to sanitize
     * @return JSON-safe string, or null if input is null
     */
    public static String sanitizeForJSON(String input) {
        if (input == null) {
            return null;
        }

        return StringEscapeUtils.escapeJava(input);
    }

    /**
     * Sanitize input by removing potentially dangerous characters.
     * 
     * @param input the input to sanitize
     * @return sanitized string with dangerous characters removed
     */
    public static String sanitize(String input) {
        if (input == null) {
            return null;
        }

        // Remove script tags and other dangerous HTML elements
        String sanitized = input.replaceAll("<script[^>]*>.*?</script>", "");
        sanitized = sanitized.replaceAll("<iframe[^>]*>.*?</iframe>", "");
        sanitized = sanitized.replaceAll("javascript:", "");
        sanitized = sanitized.replaceAll("on\\w+\\s*=", "");

        return sanitized;
    }
}
