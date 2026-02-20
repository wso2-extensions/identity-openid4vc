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

package org.wso2.carbon.identity.openid4vc.oid4vp.presentation.servlet;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.oid4vp.presentation.polling.LongPollingManager;
import org.wso2.carbon.identity.openid4vc.oid4vp.presentation.polling.PollingResult;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertTrue;

public class VPStatusPollingServletTest {

    private VPStatusPollingServlet vpStatusPollingServlet;
    
    @Mock
    private HttpServletRequest request;
    
    @Mock
    private HttpServletResponse response;
    
    @Mock
    private LongPollingManager pollingManager;

    private StringWriter responseWriter;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        vpStatusPollingServlet = new VPStatusPollingServlet();
        
        // Inject mock polling manager via reflection
        Field managerField = VPStatusPollingServlet.class.getDeclaredField("pollingManager");
        managerField.setAccessible(true);
        managerField.set(vpStatusPollingServlet, pollingManager);

        responseWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));
    }

    @Test
    public void testDoGetImmediateStatus() throws Exception {
        when(request.getPathInfo()).thenReturn("/test-request-id/status");
        
        PollingResult result = PollingResult.submitted("test-request-id", "VP_SUBMITTED");
        when(pollingManager.checkCurrentStatus("test-request-id", -1234)).thenReturn(result);

        vpStatusPollingServlet.doGet(request, response);

        String output = responseWriter.toString();
        assertTrue(output.contains("VP_SUBMITTED"));
    }

    @Test
    public void testDoGetLongPoll() throws Exception {
        when(request.getPathInfo()).thenReturn("/test-request-id/status");
        when(request.getParameter("long_poll")).thenReturn("true");
        when(request.getParameter("timeout")).thenReturn("10");

        PollingResult result = PollingResult.submitted("test-request-id", "VP_SUBMITTED");
        when(pollingManager.waitForStatusChange(eq("test-request-id"), eq(10000L), eq(-1234))).thenReturn(result);

        vpStatusPollingServlet.doGet(request, response);

        String output = responseWriter.toString();
        assertTrue(output.contains("VP_SUBMITTED"));
    }

    @Test
    public void testDoGetMissingId() throws Exception {
        when(request.getPathInfo()).thenReturn("/");

        vpStatusPollingServlet.doGet(request, response);

        String output = responseWriter.toString();
        assertTrue(output.contains("Missing request ID"));
    }
}
