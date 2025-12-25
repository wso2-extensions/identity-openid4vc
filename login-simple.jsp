<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.util.UUID" %>
<%
    String walletState = request.getParameter("walletState");
    String sessionDataKey = request.getParameter("sessionDataKey");
    String contextPath = request.getContextPath();

    if (contextPath == null) contextPath = "";
    if (walletState == null) walletState = "";
    if (sessionDataKey == null) sessionDataKey = "";
%>
<!DOCTYPE html>
<html>
<head>
    <title>Wallet Authentication</title>
    <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
    <style>
        body { font-family: Arial; text-align: center; padding: 50px; background: #f5f5f5; }
        .container { background: white; max-width: 500px; margin: 0 auto; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        #qrcode { margin: 20px auto; }
        .status { padding: 10px; margin: 10px 0; border-radius: 4px; }
        .error { background: #f8d7da; color: #721c24; }
        .success { background: #d4edda; color: #155724; }
        .polling { font-size: 12px; color: #666; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Wallet Authentication</h1>
        <p>Scan the QR code with your digital wallet</p>

        <div id="qrcode"></div>
        <div id="status"></div>
        <div class="polling">Waiting for wallet response...</div>

        <p style="font-size: 11px; color: #999; margin-top: 20px;">
            Session: <%= sessionDataKey.length() > 16 ? sessionDataKey.substring(0, 16) + "..." : sessionDataKey %>
        </p>
    </div>

    <script>
        const WALLET_STATE = '<%= walletState %>';
        const SESSION_DATA_KEY = '<%= sessionDataKey %>';
        const CONTEXT_PATH = '<%= contextPath %>';

        console.log('Wallet State:', WALLET_STATE);
        console.log('Session Key:', SESSION_DATA_KEY);

        // Generate QR Code
        function generateQR() {
            const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
            const url = 'openid4vp://authorize' +
                '?response_type=vp_token' +
                '&client_id=wso2-identity-server' +
                '&response_mode=direct_post' +
                '&response_uri=' + encodeURIComponent(window.location.protocol + '//' + window.location.host + '/wallet-callback') +
                '&state=' + encodeURIComponent(WALLET_STATE) +
                '&nonce=' + encodeURIComponent(nonce);

            console.log('QR URL:', url);

            if (typeof QRCode !== 'undefined') {
                new QRCode(document.getElementById('qrcode'), {
                    text: url,
                    width: 256,
                    height: 256
                });
                console.log('✓ QR Code generated');
            } else {
                document.getElementById('status').innerHTML = '<div class="error">QR library not loaded. Please refresh.</div>';
            }
        }

        // Polling
        let pollingInterval = null;
        function startPolling() {
            let count = 0;
            console.log('=== Starting polling for state: ' + WALLET_STATE + ' ===');

            pollingInterval = setInterval(() => {
                count++;
                console.log('[Poll ' + count + '] Checking status for state: ' + WALLET_STATE);

                fetch('/wallet-callback/status?state=' + encodeURIComponent(WALLET_STATE), {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json'
                    }
                })
                    .then(r => {
                        console.log('[Poll ' + count + '] Response status: ' + r.status);
                        return r.json();
                    })
                    .then(data => {
                        console.log('[Poll ' + count + '] Response data:', JSON.stringify(data));
                        if (data.tokenReceived === true) {
                            console.log('✓ TOKEN RECEIVED! Stopping polling and redirecting...');
                            // Stop polling immediately
                            if (pollingInterval) {
                                clearInterval(pollingInterval);
                                pollingInterval = null;
                            }
                            document.getElementById('status').innerHTML = '<div class="success">✓ Wallet verified! Completing authentication...</div>';
                            document.querySelector('.polling').textContent = 'Redirecting...';

                            // Build redirect URL - use commonauth endpoint
                            const redirectUrl = '/commonauth?sessionDataKey=' +
                                encodeURIComponent(SESSION_DATA_KEY) +
                                '&walletState=' + encodeURIComponent(WALLET_STATE) +
                                '&proceedAuth=true';

                            console.log('=== REDIRECTING TO: ' + redirectUrl + ' ===');

                            setTimeout(() => {
                                window.location.href = redirectUrl;
                            }, 300);
                        } else {
                            console.log('[Poll ' + count + '] Token not yet received, continuing...');
                        }
                    })
                    .catch(e => {
                        console.error('[Poll ' + count + '] Error:', e.message);
                    });
            }, 2000);
        }

        // Initialize
        window.addEventListener('DOMContentLoaded', () => {
            if (!WALLET_STATE || !SESSION_DATA_KEY) {
                document.getElementById('status').innerHTML = '<div class="error">Missing parameters</div>';
                return;
            }
            generateQR();
            startPolling();
        });
    </script>
</body>
</html>
