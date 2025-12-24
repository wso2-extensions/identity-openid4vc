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
<%
    String state = request.getParameter("state");
    String sessionDataKey = request.getParameter("sessionDataKey");

    // Validation
    if (state == null || state.trim().isEmpty() || sessionDataKey == null || sessionDataKey.trim().isEmpty()) {
        response.sendRedirect("../error.jsp?error=Invalid request parameters");
        return;
    }
%>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Waiting for Authentication - WSO2 Identity Server</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .wait-container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            padding: 40px;
            max-width: 500px;
            width: 100%;
            text-align: center;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 60px;
            height: 60px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        h2 {
            color: #333;
            margin-bottom: 10px;
        }
        p {
            color: #666;
            margin: 10px 0;
        }
        .status {
            font-size: 14px;
            color: #999;
            margin-top: 20px;
        }
        .cancel-btn {
            margin-top: 30px;
            padding: 10px 20px;
            background-color: #dc3545;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
        }
        .cancel-btn:hover {
            background-color: #c82333;
        }
    </style>
</head>
<body>
    <div class="wait-container">
        <h2>Waiting for Authentication</h2>
        <div class="spinner"></div>
        <p>Please complete the authentication on your wallet app.</p>
        <p class="status" id="status">Checking authentication status...</p>

        <!-- Auto-submit form to check authentication -->
        <form id="checkAuthForm" method="POST" action="<%= request.getContextPath() %>/commonauth">
            <input type="hidden" name="sessionDataKey" value="<%= sessionDataKey %>"/>
            <input type="hidden" name="state" value="<%= state %>"/>
            <input type="hidden" name="proceedAuth" value="true"/>
        </form>

        <button class="cancel-btn" onclick="cancelAuth()">Cancel</button>
    </div>

    <script>
        var checkInterval = 2000; // Check every 2 seconds
        var maxAttempts = 150; // 150 attempts * 2 seconds = 5 minutes
        var attempts = 0;

        function checkAuth() {
            attempts++;

            if (attempts > maxAttempts) {
                document.getElementById('status').textContent = 'Authentication timeout. Please try again.';
                clearInterval(pollingTimer);
                return;
            }

            // Update status
            var dots = '.'.repeat((attempts % 3) + 1);
            document.getElementById('status').textContent = 'Checking authentication status' + dots;

            // Submit the form to check if authentication is complete
            // The authenticator will either:
            // 1. Redirect back here if token not ready
            // 2. Complete authentication if token is ready
            document.getElementById('checkAuthForm').submit();
        }

        function cancelAuth() {
            if (confirm('Are you sure you want to cancel authentication?')) {
                window.location.href = '<%= request.getContextPath() %>/authenticationendpoint/login.do?sessionDataKey=<%= sessionDataKey %>&authFailure=true&authFailureMsg=Authentication cancelled';
            }
        }

        // Start polling after a short delay
        var pollingTimer = setInterval(checkAuth, checkInterval);
        setTimeout(checkAuth, 1000); // First check after 1 second
    </script>
</body>
</html>

