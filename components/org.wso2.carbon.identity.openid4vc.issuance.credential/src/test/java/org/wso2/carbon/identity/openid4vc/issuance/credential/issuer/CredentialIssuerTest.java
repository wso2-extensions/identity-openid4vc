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

package org.wso2.carbon.identity.openid4vc.issuance.credential.issuer;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceServerException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.internal.CredentialIssuanceDataHolder;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.handlers.CredentialFormatHandler;
import org.wso2.carbon.identity.openid4vc.template.management.model.VCTemplate;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test class for CredentialIssuer.
 * Tests credential issuance with format handlers.
 */
public class CredentialIssuerTest {

    private static final String TEST_FORMAT = "jwt_vc_json";
    private static final String TEST_VC_SD_JWT_FORMAT = "vc+sd-jwt";
    private static final String TEST_TEMPLATE_ID = "test-config-123";
    private static final String TEST_TENANT_DOMAIN = "carbon.super";
    private static final String TEST_CREDENTIAL =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
    private static final String TEST_SD_JWT_CREDENTIAL =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIn0.sig" +
                    "~WyJzYWx0IiwiZW1haWwiLCJ0ZXN0QGV4YW1wbGUuY29tIl0";

    private CredentialIssuer credentialIssuer;

    @BeforeMethod
    public void setUp() {
        credentialIssuer = new CredentialIssuer();

        // Clear format handlers before each test
        CredentialIssuanceDataHolder.getInstance().getCredentialFormatHandlers().clear();
    }

    @Test(priority = 1, description = "Test successful credential issuance with valid format handler")
    public void testIssueCredentialSuccess() throws CredentialIssuanceException {
        // Create template
        VCTemplate credentialConfig = createVCTemplate(TEST_FORMAT);

        // Create issuer context
        CredentialIssuerContext context = createIssuerContext(credentialConfig);

        // Mock format handler
        CredentialFormatHandler mockHandler = mock(CredentialFormatHandler.class);
        when(mockHandler.getFormat()).thenReturn(TEST_FORMAT);
        when(mockHandler.issueCredential(any(CredentialIssuerContext.class)))
                .thenReturn(TEST_CREDENTIAL);

        // Register the handler
        CredentialIssuanceDataHolder.getInstance().addCredentialFormatHandler(mockHandler);

        // Execute test
        String credential = credentialIssuer.issueCredential(context);

        // Verify
        Assert.assertNotNull(credential, "Credential should not be null");
        Assert.assertEquals(credential, TEST_CREDENTIAL, "Credential should match expected value");
    }

    @Test(priority = 2, description = "Test successful credential issuance with vc+sd-jwt format")
    public void testIssueCredentialWithVcSdJwtFormat() throws CredentialIssuanceException {
        // Create template with vc+sd-jwt format
        VCTemplate credentialConfig = createVCTemplate(TEST_VC_SD_JWT_FORMAT);

        // Create issuer context
        CredentialIssuerContext context = createIssuerContext(credentialConfig);

        // Mock format handler for vc+sd-jwt
        CredentialFormatHandler mockHandler = mock(CredentialFormatHandler.class);
        when(mockHandler.getFormat()).thenReturn(TEST_VC_SD_JWT_FORMAT);
        when(mockHandler.issueCredential(any(CredentialIssuerContext.class)))
                .thenReturn(TEST_SD_JWT_CREDENTIAL);

        // Register the handler
        CredentialIssuanceDataHolder.getInstance().addCredentialFormatHandler(mockHandler);

        // Execute test
        String credential = credentialIssuer.issueCredential(context);

        // Verify
        Assert.assertNotNull(credential, "Credential should not be null");
        Assert.assertEquals(credential, TEST_SD_JWT_CREDENTIAL, "Credential should match expected SD-JWT value");
        Assert.assertTrue(credential.contains("~"), "SD-JWT credential should contain disclosure separator");
    }

    @Test(priority = 3, description = "Test credential issuance when handler not found",
            expectedExceptions = CredentialIssuanceServerException.class)
    public void testIssueCredentialWithHandlerNotFound() throws CredentialIssuanceException {

        VCTemplate credentialConfig = createVCTemplate("unsupported_format");
        CredentialIssuerContext context = createIssuerContext(credentialConfig);
        CredentialFormatHandler mockHandler = mock(CredentialFormatHandler.class);
        when(mockHandler.getFormat()).thenReturn(TEST_FORMAT);
        CredentialIssuanceDataHolder.getInstance().addCredentialFormatHandler(mockHandler);
        credentialIssuer.issueCredential(context);
    }

    @Test(priority = 4, description = "Test credential issuance with null VCTemplate in context",
            expectedExceptions = NullPointerException.class)
    public void testIssueCredentialWithNullVCTemplate() throws CredentialIssuanceException {
        // Create context with null VCTemplate
        CredentialIssuerContext context = new CredentialIssuerContext();
        context.setVCTemplate(null);
        context.setConfigurationId(TEST_TEMPLATE_ID);
        context.setTenantDomain(TEST_TENANT_DOMAIN);

        // Execute test - should throw NPE when trying to get format from null template
        credentialIssuer.issueCredential(context);
    }

    @Test(priority = 5, description = "Test credential issuance when handler throws exception",
            expectedExceptions = CredentialIssuanceException.class)
    public void testIssueCredentialWhenHandlerThrowsException() throws CredentialIssuanceException {
        // Create template and context
        VCTemplate credentialConfig = createVCTemplate(TEST_FORMAT);
        CredentialIssuerContext context = createIssuerContext(credentialConfig);

        // Mock handler that throws exception
        CredentialFormatHandler mockHandler = mock(CredentialFormatHandler.class);
        when(mockHandler.getFormat()).thenReturn(TEST_FORMAT);
        when(mockHandler.issueCredential(any(CredentialIssuerContext.class)))
                .thenThrow(new CredentialIssuanceServerException("Credential signing failed"));

        // Register the handler
        CredentialIssuanceDataHolder.getInstance().addCredentialFormatHandler(mockHandler);

        // Execute test - should propagate exception from handler
        credentialIssuer.issueCredential(context);
    }

    @Test(priority = 6, description = "Test credential issuance with no handlers registered",
            expectedExceptions = CredentialIssuanceServerException.class)
    public void testIssueCredentialWithNoHandlersRegistered() throws CredentialIssuanceException {
        // Create template and context
        VCTemplate credentialConfig = createVCTemplate(TEST_FORMAT);
        CredentialIssuerContext context = createIssuerContext(credentialConfig);

        // Ensure no handlers are registered (already cleared in setUp)
        Assert.assertTrue(CredentialIssuanceDataHolder.getInstance().getCredentialFormatHandlers().isEmpty(),
                "Handler list should be empty");

        // Execute test - should throw exception as no handler is available
        credentialIssuer.issueCredential(context);
    }

    @Test(priority = 7, description = "Test credential issuance with empty format string",
            expectedExceptions = CredentialIssuanceServerException.class)
    public void testIssueCredentialWithEmptyFormat() throws CredentialIssuanceException {
        // Create template with empty format
        VCTemplate credentialConfig = createVCTemplate("");
        CredentialIssuerContext context = createIssuerContext(credentialConfig);

        // Register handler with valid format
        CredentialFormatHandler mockHandler = mock(CredentialFormatHandler.class);
        when(mockHandler.getFormat()).thenReturn(TEST_FORMAT);
        CredentialIssuanceDataHolder.getInstance().addCredentialFormatHandler(mockHandler);

        // Execute test - should throw exception as empty format won't match any handler
        credentialIssuer.issueCredential(context);
    }

    @Test(priority = 8, description = "Test credential issuance with multiple handlers")
    public void testIssueCredentialWithMultipleHandlers() throws CredentialIssuanceException {
        // Create template and context
        VCTemplate credentialConfig = createVCTemplate(TEST_FORMAT);
        CredentialIssuerContext context = createIssuerContext(credentialConfig);

        // Register multiple handlers with different formats
        CredentialFormatHandler mockHandler1 = mock(CredentialFormatHandler.class);
        when(mockHandler1.getFormat()).thenReturn(TEST_VC_SD_JWT_FORMAT);
        when(mockHandler1.issueCredential(any(CredentialIssuerContext.class)))
                .thenReturn(TEST_SD_JWT_CREDENTIAL);

        CredentialFormatHandler mockHandler2 = mock(CredentialFormatHandler.class);
        when(mockHandler2.getFormat()).thenReturn(TEST_FORMAT);
        when(mockHandler2.issueCredential(any(CredentialIssuerContext.class)))
                .thenReturn(TEST_CREDENTIAL);

        CredentialIssuanceDataHolder.getInstance().addCredentialFormatHandler(mockHandler1);
        CredentialIssuanceDataHolder.getInstance().addCredentialFormatHandler(mockHandler2);

        // Execute test - should use the correct handler based on format
        String credential = credentialIssuer.issueCredential(context);

        // Verify correct handler was used
        Assert.assertNotNull(credential, "Credential should not be null");
        Assert.assertEquals(credential, TEST_CREDENTIAL, "Should use jwt_vc_json handler");
    }

    /**
     * Helper method to create a VCTemplate.
     */
    private VCTemplate createVCTemplate(String format) {
        VCTemplate config = new VCTemplate();
        config.setId(TEST_TEMPLATE_ID);
        config.setIdentifier("test-identifier");
        config.setFormat(format);
        config.setExpiresIn(3600);
        config.setClaims(Arrays.asList("email", "name"));
        return config;
    }

    /**
     * Helper method to create a CredentialIssuerContext.
     */
    private CredentialIssuerContext createIssuerContext(VCTemplate credentialConfig) {
        CredentialIssuerContext context = new CredentialIssuerContext();
        context.setVCTemplate(credentialConfig);
        context.setConfigurationId(TEST_TEMPLATE_ID);
        context.setTenantDomain(TEST_TENANT_DOMAIN);

        Map<String, String> claims = new HashMap<>();
        claims.put("email", "test@example.com");
        claims.put("name", "Test User");
        context.setClaims(claims);

        return context;
    }
}
