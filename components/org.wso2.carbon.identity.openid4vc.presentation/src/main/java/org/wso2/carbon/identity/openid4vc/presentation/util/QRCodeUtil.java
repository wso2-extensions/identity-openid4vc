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
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.dto.AuthorizationDetailsDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Utility class for generating QR codes for OpenID4VP authorization requests.
 * 
 * QR codes can encode:
 * 1. A full authorization request URL (by-value)
 * 2. A request_uri reference (by-reference)
 * 3. An OpenID4VP deep link for mobile wallets
 */
public class QRCodeUtil {

    // Default QR code settings
    private static final int DEFAULT_QR_SIZE = 300;
    private static final String DEFAULT_ERROR_CORRECTION = "M";

    private QRCodeUtil() {
        // Prevent instantiation
    }

    /**
     * Generate QR code content for a VP request using request_uri flow.
     * 
     * @param requestUri The URI where the full request can be fetched
     * @param clientId   The client ID to include in the authorization request
     * @return QR code content string (OpenID4VP deep link)
     */
    public static String generateRequestUriQRContent(String requestUri, String clientId) {
        if (StringUtils.isBlank(requestUri)) {
            throw new IllegalArgumentException("Request URI cannot be blank");
        }

        // OpenID4VP scheme with request_uri
        StringBuilder content = new StringBuilder();
        content.append(OpenID4VPConstants.Protocol.OPENID4VP_SCHEME);
        content.append("authorize"); // Add authorize path as requested
        content.append("?");

        // Add client_id if present (as requested by user)
        if (StringUtils.isNotBlank(clientId)) {
            content.append(OpenID4VPConstants.RequestParams.CLIENT_ID);
            content.append("=");
            content.append(urlEncode(clientId));
            content.append("&");
        }

        content.append(OpenID4VPConstants.RequestParams.REQUEST_URI);
        content.append("=");
        content.append(urlEncode(requestUri));

        return content.toString();
    }

    /**
     * Generate QR code content for a VP request using by-value flow.
     * 
     * @param authorizationDetails The full authorization details
     * @return QR code content string (OpenID4VP deep link with full request)
     */
    public static String generateByValueQRContent(AuthorizationDetailsDTO authorizationDetails) {
        if (authorizationDetails == null) {
            throw new IllegalArgumentException("Authorization details cannot be null");
        }

        StringBuilder content = new StringBuilder();
        content.append(OpenID4VPConstants.Protocol.OPENID4VP_SCHEME);
        content.append("?");

        // Client ID
        content.append(OpenID4VPConstants.RequestParams.CLIENT_ID);
        content.append("=");
        content.append(urlEncode(authorizationDetails.getClientId()));

        // Response type
        content.append("&");
        content.append(OpenID4VPConstants.RequestParams.RESPONSE_TYPE);
        content.append("=");
        content.append(OpenID4VPConstants.Protocol.RESPONSE_TYPE_VP_TOKEN);

        // Response mode
        content.append("&");
        content.append(OpenID4VPConstants.RequestParams.RESPONSE_MODE);
        content.append("=");
        content.append(urlEncode(authorizationDetails.getResponseMode()));

        // Response URI
        content.append("&");
        content.append(OpenID4VPConstants.RequestParams.RESPONSE_URI);
        content.append("=");
        content.append(urlEncode(authorizationDetails.getResponseUri()));

        // Nonce
        content.append("&");
        content.append(OpenID4VPConstants.RequestParams.NONCE);
        content.append("=");
        content.append(urlEncode(authorizationDetails.getNonce()));

        // State (request ID)
        if (StringUtils.isNotBlank(authorizationDetails.getState())) {
            content.append("&");
            content.append(OpenID4VPConstants.RequestParams.STATE);
            content.append("=");
            content.append(urlEncode(authorizationDetails.getState()));
        }

        // Presentation definition
        if (authorizationDetails.getPresentationDefinition() != null) {
            content.append("&");
            content.append(OpenID4VPConstants.Protocol.PRESENTATION_DEFINITION);
            content.append("=");
            content.append(urlEncode(authorizationDetails.getPresentationDefinition().toString()));
        }

        return content.toString();
    }

    /**
     * Generate QR code data URL (base64 encoded image) for display in HTML.
     * 
     * Note: This method returns a placeholder. In production, use a QR code library
     * like ZXing (Zebra Crossing) or QRCode.js to generate actual QR images.
     * 
     * @param content The content to encode in the QR code
     * @param size    The size of the QR code in pixels
     * @return Data URL string (data:image/png;base64,...)
     * @throws VPException If QR generation fails
     */
    public static String generateQRCodeDataUrl(String content, int size) throws VPException {
        if (StringUtils.isBlank(content)) {
            throw new VPException("QR code content cannot be blank");
        }

        if (size <= 0) {
            size = getConfiguredQRSize();
        }

        // In production, use a library like ZXing:
        //
        // QRCodeWriter qrCodeWriter = new QRCodeWriter();
        // BitMatrix bitMatrix = qrCodeWriter.encode(content, BarcodeFormat.QR_CODE,
        // size, size);
        // ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
        // MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);
        // byte[] pngData = pngOutputStream.toByteArray();
        // return "data:image/png;base64," +
        // Base64.getEncoder().encodeToString(pngData);

        // For now, return a placeholder that indicates QR generation is needed
        // The actual QR can be generated on the client side using JavaScript libraries

        // Return a JSON object that the frontend can use to generate the QR code
        return createQRCodePlaceholder(content, size);
    }

    /**
     * Create a placeholder response for QR code generation.
     * Frontend JavaScript can use this to render the actual QR code.
     */
    private static String createQRCodePlaceholder(String content, int size) {
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"type\":\"qrcode\",");
        json.append("\"content\":\"").append(escapeJson(content)).append("\",");
        json.append("\"size\":").append(size).append(",");
        json.append("\"errorCorrection\":\"").append(getConfiguredErrorCorrection()).append("\"");
        json.append("}");
        return json.toString();
    }

    /**
     * Generate an HTML snippet for QR code display.
     * 
     * @param content   The content to encode
     * @param requestId The request ID for identification
     * @return HTML string with QR code container
     */
    public static String generateQRCodeHtml(String content, String requestId) {
        int size = getConfiguredQRSize();

        StringBuilder html = new StringBuilder();
        html.append("<div id=\"qr-container-").append(escapeHtml(requestId)).append("\" ");
        html.append("class=\"openid4vp-qr-container\" ");
        html.append("data-content=\"").append(escapeHtml(content)).append("\" ");
        html.append("data-size=\"").append(size).append("\" ");
        html.append("data-request-id=\"").append(escapeHtml(requestId)).append("\">");
        html.append("<canvas id=\"qr-canvas-").append(escapeHtml(requestId)).append("\"></canvas>");
        html.append("</div>");

        return html.toString();
    }

    /**
     * Generate JavaScript code for rendering QR code.
     * Assumes QRCode.js library is available.
     * 
     * @param containerId The container element ID
     * @param content     The content to encode
     * @param size        The size in pixels
     * @return JavaScript code string
     */
    public static String generateQRCodeScript(String containerId, String content, int size) {
        StringBuilder script = new StringBuilder();
        script.append("new QRCode(document.getElementById('").append(escapeJs(containerId))
                .append("'), {");
        script.append("text: '").append(escapeJs(content)).append("',");
        script.append("width: ").append(size).append(",");
        script.append("height: ").append(size).append(",");
        script.append("colorDark: '#000000',");
        script.append("colorLight: '#ffffff',");
        script.append("correctLevel: QRCode.CorrectLevel.").append(getConfiguredErrorCorrection());
        script.append("});");

        return script.toString();
    }

    /**
     * Get configured QR code size.
     */
    public static int getConfiguredQRSize() {
        String configValue = IdentityUtil.getProperty("OpenID4VP.QRCode.Size");
        if (StringUtils.isNotBlank(configValue)) {
            try {
                return Integer.parseInt(configValue);
            } catch (NumberFormatException e) {
                // Use default
            }
        }
        return DEFAULT_QR_SIZE;
    }

    /**
     * Get configured error correction level.
     */
    public static String getConfiguredErrorCorrection() {
        String configValue = IdentityUtil.getProperty("OpenID4VP.QRCode.ErrorCorrectionLevel");
        if (StringUtils.isNotBlank(configValue) &&
                (configValue.equals("L") || configValue.equals("M") ||
                        configValue.equals("Q") || configValue.equals("H"))) {
            return configValue;
        }
        return DEFAULT_ERROR_CORRECTION;
    }

    /**
     * URL encode a string.
     */
    private static String urlEncode(String value) {
        if (value == null) {
            return "";
        }
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            // UTF-8 is always supported
            return value;
        }
    }

    /**
     * Escape string for JSON.
     */
    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * Escape string for HTML attribute.
     */
    private static String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    /**
     * Escape string for JavaScript.
     */
    private static String escapeJs(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("\\", "\\\\")
                .replace("'", "\\'")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}
