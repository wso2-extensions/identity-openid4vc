<%--
  ~ Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
  ~
  ~ WSO2 LLC. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>

<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.util.UUID" %>
<%
    // Get wallet authentication state (unique for this wallet auth attempt)
    String walletState = request.getParameter("walletState");
    String sessionDataKey = request.getParameter("sessionDataKey");

    // Get context path
    String contextPath = request.getContextPath();
    if (contextPath == null) {
        contextPath = "";
    }

    // Check for missing parameters (we'll show error in UI instead of redirecting)
    boolean hasError = false;
    String errorMessage = "";

    if (walletState == null || walletState.trim().isEmpty()) {
        hasError = true;
        errorMessage = "Missing wallet state parameter. Please try again.";
        walletState = ""; // Set to empty to avoid null errors
    }

    if (sessionDataKey == null || sessionDataKey.trim().isEmpty()) {
        hasError = true;
        errorMessage = "Missing session data key. Please try again.";
        sessionDataKey = ""; // Set to empty to avoid null errors
    }
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Wallet Authentication - WSO2 Identity Server</title>

    <!-- QR Code Library -->
    <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>

    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Gilroy', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #000000;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }

        .container {
            background: #FFFFFF;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(255, 115, 0, 0.15);
            max-width: 500px;
            width: 100%;
            padding: 40px;
            animation: slideIn 0.5s ease-out;
            border: 1px solid rgba(255, 115, 0, 0.1);
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #ff7300;
        }

        .logo {
            width: 80px;
            height: 80px;
            margin: 0 auto 20px;
            background: #ff7300;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            box-shadow: 0 4px 12px rgba(255, 115, 0, 0.3);
        }

        h1 {
            color: #000000;
            font-size: 28px;
            margin-bottom: 10px;
            font-weight: 600;
        }

        .subtitle {
            color: #666666;
            font-size: 14px;
        }

        .info-box {
            background: #fff5ed;
            border-left: 4px solid #ff7300;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 25px;
        }

        .info-box strong {
            color: #ff7300;
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
        }

        .info-box ol {
            margin-left: 20px;
            color: #000000;
        }

        .info-box li {
            margin-bottom: 5px;
            line-height: 1.6;
        }

        .qr-section {
            background: #f8f8f8;
            padding: 25px;
            border-radius: 4px;
            margin-bottom: 25px;
            text-align: center;
            border: 1px solid #e0e0e0;
        }

        .qr-title {
            font-size: 16px;
            font-weight: 600;
            color: #000000;
            margin-bottom: 15px;
        }

        .qr-placeholder {
            width: 256px;
            height: 256px;
            margin: 0 auto 15px;
            background: #FFFFFF;
            border: 2px solid #ff7300;
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 10px;
        }

        .qr-placeholder canvas {
            max-width: 100%;
            max-height: 100%;
        }

        .qr-placeholder img {
            max-width: 100%;
            max-height: 100%;
        }

        .state-info {
            font-size: 11px;
            color: #666666;
            word-break: break-all;
            margin-top: 10px;
            padding: 8px;
            background: #FFFFFF;
            border-radius: 4px;
            border: 1px solid #e0e0e0;
        }

        .state-info code {
            color: #ff7300;
            font-family: 'Courier New', monospace;
            font-weight: 600;
        }

        .button {
            width: 100%;
            padding: 14px 24px;
            background: #ff7300;
            color: #FFFFFF;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s, box-shadow 0.3s;
            margin-bottom: 15px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .button:hover {
            background: #e66700;
            box-shadow: 0 4px 12px rgba(255, 115, 0, 0.4);
        }

        .button:active {
            background: #cc5c00;
        }

        .button:disabled {
            background: #cccccc;
            cursor: not-allowed;
            box-shadow: none;
        }

        .button-secondary {
            background: #FFFFFF;
            color: #000000;
            border: 2px solid #000000;
        }

        .button-secondary:hover {
            background: #f8f8f8;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }

        .status {
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 15px;
            display: none;
            animation: fadeIn 0.3s;
            font-weight: 500;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .status.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
            display: block;
        }

        .status.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
            display: block;
        }

        .status.info {
            background: #fff5ed;
            color: #ff7300;
            border: 1px solid #ffd9b3;
            display: block;
        }

        .spinner {
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: #FFFFFF;
            animation: spin 0.8s linear infinite;
            margin-right: 8px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .footer {
            text-align: center;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            color: #666666;
            font-size: 12px;
        }

        .footer strong {
            color: #ff7300;
        }

        .polling-status {
            font-size: 13px;
            color: #666666;
            text-align: center;
            margin-top: 15px;
        }

        .polling-dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            background: #ff7300;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 1.5s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 0.3; }
            50% { opacity: 1; }
        }
    </style>
</head>
<body>
    <% if (hasError) { %>
    <div class="container">
        <div class="header">
            <div class="logo">⚠️</div>
            <h1>Authentication Error</h1>
        </div>
        <div style="background: #f8d7da; color: #721c24; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <strong>Error:</strong> <%= errorMessage %>
        </div>
        <button class="button button-secondary" onclick="window.history.back()">
            ← Go Back
        </button>
        <div class="footer">
            Powered by <strong>WSO2 Identity Server</strong>
        </div>
    </div>
    </body>
    </html>
    <%
        return; // Stop processing
    }
    %>

    <div class="container">
        <div class="header">
            <div class="logo">🔐</div>
            <h1>Wallet Authentication</h1>
            <p class="subtitle">Secure login with your digital wallet</p>
        </div>

        <div class="info-box">
            <strong>📱 How to authenticate:</strong>
            <ol>
                <li>Open your digital wallet app</li>
                <li>Scan the QR code below</li>
                <li>Approve the presentation request</li>
                <li>You'll be automatically logged in</li>
            </ol>
        </div>

        <div class="qr-section">
            <div class="qr-title">Scan with your wallet app</div>
            <div id="qrcode" class="qr-placeholder"></div>
            <p id="qrStatus" style="color: #666; font-size: 13px; margin-top: 10px;">Generating QR code...</p>
            <div class="state-info">
                Session ID: <code><%= sessionDataKey != null && !sessionDataKey.isEmpty() ? sessionDataKey.substring(0, Math.min(16, sessionDataKey.length())) + "..." : "N/A" %></code>
            </div>
        </div>

        <div id="status" class="status"></div>

        <button class="button button-secondary" onclick="window.history.back()">
            ← Back to Login
        </button>

        <div id="pollingStatus" class="polling-status" style="display: none;">
            <span class="polling-dot"></span>
            Waiting for wallet response...
        </div>

        <div class="footer">
            Powered by <strong>WSO2 Identity Server</strong><br>
            OpenID4VP Wallet Authentication
        </div>
    </div>

    <script>
        // Configuration - with defensive null checks
        const WALLET_STATE = '<%= walletState != null ? walletState : "" %>';
        const SESSION_DATA_KEY = '<%= sessionDataKey != null ? sessionDataKey : "" %>';
        const CONTEXT_PATH = '<%= contextPath != null ? contextPath : "" %>';
        const CALLBACK_URL = '/wallet-callback';
        const COMMONAUTH_URL = '/commonauth';
        const POLL_INTERVAL = 2000; // 2 seconds

        let pollingInterval = null;

        // Validate we have required parameters
        if (!WALLET_STATE || !SESSION_DATA_KEY) {
            console.error('Missing required parameters');
            if (typeof showStatus === 'function') {
                showStatus('Configuration error: Missing required parameters', 'error');
            }
        }

        /**
         * Show status message
         */
        function showStatus(message, type) {
            const statusDiv = document.getElementById('status');
            statusDiv.textContent = message;
            statusDiv.className = 'status ' + type;

            // Auto-hide success messages after 3 seconds
            if (type === 'success') {
                setTimeout(() => {
                    statusDiv.style.display = 'none';
                }, 3000);
            }
        }

        /**
         * Poll for authentication completion
         */
        function startPolling() {
            // Validate parameters before polling
            if (!WALLET_STATE) {
                console.error('Cannot start polling: missing wallet state');
                return;
            }

            console.log('=== Starting polling for wallet state:', WALLET_STATE);

            // Show polling status
            const pollingStatus = document.getElementById('pollingStatus');
            if (pollingStatus) {
                pollingStatus.style.display = 'block';
            }

            let pollCount = 0;
            const maxPolls = 150; // 150 * 2 seconds = 5 minutes

            pollingInterval = setInterval(() => {
                pollCount++;

                if (pollCount > maxPolls) {
                    clearInterval(pollingInterval);
                    showStatus('⏱️ Polling timeout. Please refresh and try again.', 'error');
                    console.log('Polling stopped: max attempts reached');
                    return;
                }

                console.log(`[Poll ${pollCount}] Checking /wallet-callback/status?state=${WALLET_STATE.substring(0, 8)}...`);

                fetch('/wallet-callback/status?state=' + encodeURIComponent(WALLET_STATE))
                    .then(response => {
                        console.log(`[Poll ${pollCount}] Response status: ${response.status}`);
                        if (!response.ok) {
                            throw new Error('HTTP ' + response.status);
                        }
                        return response.json();
                    })
                    .then(data => {
                        console.log(`[Poll ${pollCount}] Response data:`, data);

                        if (data.status === 'received' || data.tokenReceived || data.authenticated) {
                            clearInterval(pollingInterval);
                            console.log('✓ VP token received! Redirecting to authentication...');
                            showStatus('✅ Wallet response received! Verifying...', 'success');

                            // Redirect to commonauth with proceedAuth to trigger authentication
                            setTimeout(() => {
                                const redirectUrl = CONTEXT_PATH + '/commonauth' +
                                    '?sessionDataKey=' + encodeURIComponent(SESSION_DATA_KEY) +
                                    '&walletState=' + encodeURIComponent(WALLET_STATE) +
                                    '&proceedAuth=true';

                                console.log('Redirecting to:', redirectUrl);
                                window.location.href = redirectUrl;
                            }, 500);
                        } else {
                            console.debug(`[Poll ${pollCount}] Token not yet received`);
                        }
                    })
                    .catch(error => {
                        // Log polling errors for debugging
                        console.debug(`[Poll ${pollCount}] Error:`, error.message);
                    });
            }, POLL_INTERVAL);

            console.log('=== Polling started successfully, interval:', POLL_INTERVAL, 'ms');
        }

        /**
         * Generate OpenID4VP QR code
         */
        function generateQRCode() {
            try {
                // Validate required parameters
                if (!WALLET_STATE) {
                    showStatus('Cannot generate QR code: missing wallet state', 'error');
                    return;
                }

                // Generate nonce (unique per request)
                const nonce = generateNonce();

                // Get current window location for building URLs
                const protocol = window.location.protocol;
                const host = window.location.host;

                // Build the callback URL (response_uri)
                const responseUri = protocol + '//' + host + CALLBACK_URL;

                // Build OpenID4VP authorization request URL
                const authRequest = 'openid4vp://authorize' +
                    '?response_type=vp_token' +
                    '&client_id=wso2-identity-server' +
                    '&response_mode=direct_post' +
                    '&response_uri=' + encodeURIComponent(responseUri) +
                    '&state=' + encodeURIComponent(WALLET_STATE) +
                    '&nonce=' + encodeURIComponent(nonce);

                if (typeof console !== 'undefined' && console.log) {
                    console.log('OpenID4VP Request:', authRequest);
                    console.log('Wallet State:', WALLET_STATE);
                    console.log('Nonce:', nonce);
                    console.log('Response URI:', responseUri);
                }

                // Generate QR code
                const qrCodeContainer = document.getElementById('qrcode');
                if (!qrCodeContainer) {
                    console.error('QR code container not found');
                    return;
                }

                qrCodeContainer.innerHTML = ''; // Clear any existing content

                // Check if QRCode library is loaded
                if (typeof QRCode === 'undefined') {
                    console.error('QRCode library not loaded');
                    showFallbackQRCode(authRequest, qrCodeContainer);
                    return;
                }

                // Generate QR code with library
                new QRCode(qrCodeContainer, {
                    text: authRequest,
                    width: 236,
                    height: 236,
                    colorDark: '#000000',
                    colorLight: '#FFFFFF',
                    correctLevel: QRCode.CorrectLevel.M
                });

                // Update status
                const statusEl = document.getElementById('qrStatus');
                if (statusEl) {
                    statusEl.textContent = 'Scan QR code with your wallet app';
                    statusEl.style.color = '#ff7300';
                }

                if (typeof console !== 'undefined' && console.log) {
                    console.log('QR Code generated successfully');
                }

            } catch (error) {
                console.error('Error generating QR code:', error);
                const statusEl = document.getElementById('qrStatus');
                if (statusEl) {
                    statusEl.textContent = 'Error generating QR code';
                    statusEl.style.color = '#721c24';
                }

                // Show error and provide manual URL
                const qrCodeContainer = document.getElementById('qrcode');
                if (qrCodeContainer) {
                    showFallbackQRCode('Error loading QR code', qrCodeContainer);
                }
            }
        }

        /**
         * Show fallback when QR code library fails
         */
        function showFallbackQRCode(authRequest, container) {
            // Escape single quotes for safe insertion into onclick attribute
            const escapedUrl = authRequest.replace(/'/g, "\\'");
            
            container.innerHTML = `
                <div style="padding: 20px; background: #fff3cd; border: 2px dashed #ff7300; border-radius: 8px;">
                    <div style="font-size: 48px; margin-bottom: 10px;">📱</div>
                    <p style="margin: 10px 0; font-size: 14px; color: #856404;">
                        <strong>QR Code library not available</strong><br>
                        Copy this URL to your wallet app:
                    </p>
                    <div style="background: white; padding: 10px; border-radius: 4px; word-break: break-all; font-size: 11px; font-family: monospace; max-height: 150px; overflow-y: auto;">
                        ` + authRequest + `
                    </div>
                    <button onclick="copyToClipboard('` + escapedUrl + `'); return false;"
                            style="margin-top: 10px; padding: 8px 16px; background: #ff7300; color: white; border: none; border-radius: 4px; cursor: pointer;">
                        📋 Copy URL
                    </button>
                </div>
            `;

            const statusEl = document.getElementById('qrStatus');
            if (statusEl) {
                statusEl.textContent = 'Use the URL above with your wallet app';
                statusEl.style.color = '#856404';
            }
        }

        /**
         * Copy text to clipboard
         */
        function copyToClipboard(text) {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(() => {
                    showStatus('✓ URL copied to clipboard!', 'success');
                }).catch(err => {
                    console.error('Failed to copy:', err);
                    showStatus('Failed to copy. Please copy manually.', 'error');
                });
            } else {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                textArea.style.position = 'fixed';
                textArea.style.left = '-999999px';
                document.body.appendChild(textArea);
                textArea.select();
                try {
                    document.execCommand('copy');
                    showStatus('✓ URL copied to clipboard!', 'success');
                } catch (err) {
                    console.error('Failed to copy:', err);
                    showStatus('Failed to copy. Please copy manually.', 'error');
                }
                document.body.removeChild(textArea);
            }
        }

        /**
         * Generate a unique nonce for this request
         */
        function generateNonce() {
            // Generate a cryptographically secure random nonce
            const array = new Uint8Array(16);
            if (window.crypto && window.crypto.getRandomValues) {
                window.crypto.getRandomValues(array);
            } else {
                // Fallback for older browsers
                for (let i = 0; i < array.length; i++) {
                    array[i] = Math.floor(Math.random() * 256);
                }
            }

            // Convert to hex string
            return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
        }

        /**
         * Initialize page
         */
        window.addEventListener('DOMContentLoaded', () => {
            // Validate we have required parameters
            if (!WALLET_STATE || !SESSION_DATA_KEY) {
                showStatus('Configuration error: Missing required parameters', 'error');
                console.error('Missing required parameters:', {
                    walletState: WALLET_STATE,
                    sessionDataKey: SESSION_DATA_KEY
                });
                return;
            }

            // Generate QR code
            generateQRCode();

            // Start polling for wallet response
            startPolling();

            // Log state for debugging
            if (typeof console !== 'undefined' && console.log) {
                console.log('Wallet authentication initialized:', {
                    walletState: WALLET_STATE,
                    sessionDataKey: SESSION_DATA_KEY,
                    callbackUrl: CALLBACK_URL
                });
            }
        });

        /**
         * Cleanup on page unload
         */
        window.addEventListener('beforeunload', () => {
            if (pollingInterval) {
                clearInterval(pollingInterval);
            }
        });
    </script>
</body>
</html>

