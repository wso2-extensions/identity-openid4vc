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
    private static final String TEST_TEMPLATE_ID = "test-config-123";
    private static final String TEST_TENANT_DOMAIN = "carbon.super";
    private static final String TEST_CREDENTIAL =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";

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

    @Test(priority = 3, description = "Test credential issuance when handler not found",
            expectedExceptions = CredentialIssuanceServerException.class,
            expectedExceptionsMessageRegExp = ".*Unsupported credential format.*")
    public void testIssueCredentialWithHandlerNotFound() throws CredentialIssuanceException {

        VCTemplate credentialConfig = createVCTemplate("unsupported_format");
        CredentialIssuerContext context = createIssuerContext(credentialConfig);
        CredentialFormatHandler mockHandler = mock(CredentialFormatHandler.class);
        when(mockHandler.getFormat()).thenReturn(TEST_FORMAT);
        CredentialIssuanceDataHolder.getInstance().addCredentialFormatHandler(mockHandler);
        credentialIssuer.issueCredential(context);
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
