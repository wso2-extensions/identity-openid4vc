/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator;

import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.PresentationAuthenticatorDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.PresentationRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationCoreService;

import java.util.Collections;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link PresentationAuthenticator}.
 * Tests canHandle, getContextIdentifier, getName, getFriendlyName, and the wallet login page redirect.
 */
@WithCarbonHome
public class PresentationAuthenticatorTest {

    private static final String WALLET_LOGIN_PAGE = "/authenticationendpoint/wallet_login.jsp";
    private static final String TENANT_WALLET_LOGIN_PAGE_URL =
            "https://localhost:9443/t/tenant.com/authenticationendpoint/wallet_login.jsp";

    private PresentationAuthenticator authenticator;
    private MockedStatic<ServiceURLBuilder> serviceURLBuilderMock;
    private MockedStatic<LoggerUtils> loggerUtilsMock;

    @BeforeMethod
    public void setUp() {

        authenticator = new PresentationAuthenticator();
    }

    @AfterMethod
    public void tearDown() {

        if (serviceURLBuilderMock != null) {
            serviceURLBuilderMock.close();
            serviceURLBuilderMock = null;
        }
        if (loggerUtilsMock != null) {
            loggerUtilsMock.close();
            loggerUtilsMock = null;
        }
        PresentationAuthenticatorDataHolder.getInstance().setPresentationSessionService(null);
    }

    @Test(priority = 1, description = "Test canHandle returns true when all required parameters are present")
    public void testCanHandleWithAllRequiredParams() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn("key-123");
        when(request.getParameter("vp_request_id")).thenReturn("req-456");
        when(request.getParameter("status")).thenReturn("success");

        Assert.assertTrue(authenticator.canHandle(request),
                "canHandle should return true when all required params are present");
    }

    @Test(priority = 2, description = "Test canHandle returns false when status parameter is missing")
    public void testCanHandleWithMissingStatus() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn("key-123");
        when(request.getParameter("vp_request_id")).thenReturn("req-456");
        when(request.getParameter("status")).thenReturn(null);

        Assert.assertFalse(authenticator.canHandle(request),
                "canHandle should return false when status is missing");
    }

    @Test(priority = 3, description = "Test canHandle returns false when sessionDataKey parameter is missing")
    public void testCanHandleWithMissingSessionDataKey() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn(null);
        when(request.getParameter("vp_request_id")).thenReturn("req-456");
        when(request.getParameter("status")).thenReturn("success");

        Assert.assertFalse(authenticator.canHandle(request),
                "canHandle should return false when sessionDataKey is missing");
    }

    @Test(priority = 4, description = "Test canHandle returns false when vp_request_id parameter is missing")
    public void testCanHandleWithMissingVpRequestId() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn("key-123");
        when(request.getParameter("vp_request_id")).thenReturn(null);
        when(request.getParameter("status")).thenReturn("success");

        Assert.assertFalse(authenticator.canHandle(request),
                "canHandle should return false when vp_request_id is missing");
    }

    @Test(priority = 5, description = "Test canHandle returns false when all parameters are blank")
    public void testCanHandleWithAllBlankParams() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn("   ");
        when(request.getParameter("vp_request_id")).thenReturn("   ");
        when(request.getParameter("status")).thenReturn("   ");

        Assert.assertFalse(authenticator.canHandle(request),
                "canHandle should return false when all params are blank");
    }

    @Test(priority = 6, description = "Test getContextIdentifier returns trimmed sessionDataKey value")
    public void testGetContextIdentifierWithSessionDataKey() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn("  ctx-789  ");

        String result = authenticator.getContextIdentifier(request);

        Assert.assertEquals(result, "ctx-789",
                "getContextIdentifier should return the trimmed session data key");
    }

    @Test(priority = 7, description = "Test getContextIdentifier returns null when sessionDataKey is null")
    public void testGetContextIdentifierWithNullKey() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn(null);

        Assert.assertNull(authenticator.getContextIdentifier(request),
                "getContextIdentifier should return null when sessionDataKey is null");
    }

    @Test(priority = 8, description = "Test getName returns the authenticator name")
    public void testGetName() {

        Assert.assertEquals(authenticator.getName(), "PresentationAuthenticator",
                "getName should return PresentationAuthenticator");
    }

    @Test(priority = 9, description = "Test getFriendlyName returns the authenticator friendly name")
    public void testGetFriendlyName() {

        Assert.assertEquals(authenticator.getFriendlyName(), "Wallet (OpenID4VP)",
                "getFriendlyName should return Wallet (OpenID4VP)");
    }

    @Test(priority = 10, description = "Test the wallet login page URL is built with ServiceURLBuilder so it is "
            + "tenant qualified")
    public void testInitiateAuthenticationRequestRedirectsToTenantQualifiedWalletPage() throws Exception {

        ServiceURLBuilder builder = mockServiceURLBuilder();
        ServiceURL serviceURL = mock(ServiceURL.class);
        when(builder.build()).thenReturn(serviceURL);
        when(serviceURL.getAbsolutePublicURL()).thenReturn(TENANT_WALLET_LOGIN_PAGE_URL);
        HttpServletResponse response = mock(HttpServletResponse.class);

        authenticator.initiateAuthenticationRequest(mock(HttpServletRequest.class), response,
                mockAuthenticationContext());

        verify(builder).addPath(WALLET_LOGIN_PAGE);
        ArgumentCaptor<String> redirectCaptor = ArgumentCaptor.forClass(String.class);
        verify(response).sendRedirect(redirectCaptor.capture());
        String redirectUrl = redirectCaptor.getValue();
        Assert.assertTrue(redirectUrl.startsWith(TENANT_WALLET_LOGIN_PAGE_URL + "?"),
                "Redirect should target the tenant qualified wallet login page: " + redirectUrl);
        Assert.assertTrue(redirectUrl.contains("sessionDataKey=session-key"),
                "Redirect should carry the session data key: " + redirectUrl);
        Assert.assertTrue(redirectUrl.contains("tenantDomain=tenant.com"),
                "Redirect should carry the tenant domain: " + redirectUrl);
    }

    @Test(priority = 11, description = "Test a wallet login page URL build failure fails the authentication")
    public void testInitiateAuthenticationRequestUrlBuildFailure() throws Exception {

        ServiceURLBuilder builder = mockServiceURLBuilder();
        when(builder.build()).thenThrow(new URLBuilderException("Error building URL"));
        HttpServletResponse response = mock(HttpServletResponse.class);

        try {
            authenticator.initiateAuthenticationRequest(mock(HttpServletRequest.class), response,
                    mockAuthenticationContext());
            Assert.fail("Expected AuthenticationFailedException");
        } catch (AuthenticationFailedException e) {
            Assert.assertTrue(e.getCause() instanceof URLBuilderException,
                    "Cause should be the URLBuilderException");
        }
        verify(response, never()).sendRedirect(anyString());
    }

    private ServiceURLBuilder mockServiceURLBuilder() throws Exception {

        loggerUtilsMock = mockStatic(LoggerUtils.class);
        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);

        PresentationCoreService presentationCoreService = mock(PresentationCoreService.class);
        when(presentationCoreService.startPresentationSession("definition-id", "tenant.com"))
                .thenReturn(new PresentationRequestResponseDTO("request-id", "openid4vp://?client_id=x",
                        "https://localhost:9443/t/tenant.com/oid4vp/requests/request-id", "x",
                        System.currentTimeMillis() + 120000));
        PresentationAuthenticatorDataHolder.getInstance().setPresentationSessionService(presentationCoreService);

        ServiceURLBuilder builder = mock(ServiceURLBuilder.class, RETURNS_SELF);
        serviceURLBuilderMock = mockStatic(ServiceURLBuilder.class);
        serviceURLBuilderMock.when(ServiceURLBuilder::create).thenReturn(builder);
        return builder;
    }

    private AuthenticationContext mockAuthenticationContext() {

        AuthenticationContext context = mock(AuthenticationContext.class);
        when(context.getTenantDomain()).thenReturn("tenant.com");
        when(context.getContextIdentifier()).thenReturn("session-key");
        when(context.getAuthenticatorProperties())
                .thenReturn(Collections.singletonMap("presentationDefinitionId", "definition-id"));
        return context;
    }
}
