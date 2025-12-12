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
import org.wso2.carbon.identity.openid4vc.config.management.model.VCCredentialConfiguration;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.internal.CredentialIssuanceDataHolder;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.handlers.format.CredentialFormatHandler;

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
    private static final String TEST_CONFIG_ID = "test-config-123";
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
        // Create credential configuration
        VCCredentialConfiguration credentialConfig = createCredentialConfiguration(TEST_FORMAT);

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

    @Test(priority = 2, description = "Test credential issuance with null format",
            expectedExceptions = CredentialIssuanceException.class,
            expectedExceptionsMessageRegExp = ".*Credential format cannot be null.*")
    public void testIssueCredentialWithNullFormat() throws CredentialIssuanceException {
        // Create credential configuration with null format
        VCCredentialConfiguration credentialConfig = createCredentialConfiguration(null);

        // Create issuer context
        CredentialIssuerContext context = createIssuerContext(credentialConfig);

        // Execute test - should throw CredentialIssuanceException
        credentialIssuer.issueCredential(context);
    }

    @Test(priority = 3, description = "Test credential issuance when handler not found",
            expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = ".*Unsupported credential format.*")
    public void testIssueCredentialWithHandlerNotFound() throws CredentialIssuanceException {
        // Create credential configuration with a format that has no handler
        VCCredentialConfiguration credentialConfig = createCredentialConfiguration("unsupported_format");

        // Create issuer context
        CredentialIssuerContext context = createIssuerContext(credentialConfig);

        // Register a handler for a different format
        CredentialFormatHandler mockHandler = mock(CredentialFormatHandler.class);
        when(mockHandler.getFormat()).thenReturn(TEST_FORMAT);
        CredentialIssuanceDataHolder.getInstance().addCredentialFormatHandler(mockHandler);

        // Execute test - should throw IllegalArgumentException
        credentialIssuer.issueCredential(context);
    }

    /**
     * Helper method to create a VCCredentialConfiguration.
     */
    private VCCredentialConfiguration createCredentialConfiguration(String format) {
        VCCredentialConfiguration config = new VCCredentialConfiguration();
        config.setId(TEST_CONFIG_ID);
        config.setIdentifier("test-identifier");
        config.setFormat(format);
        config.setExpiresIn(3600);
        config.setClaims(Arrays.asList("email", "name"));
        return config;
    }

    /**
     * Helper method to create a CredentialIssuerContext.
     */
    private CredentialIssuerContext createIssuerContext(VCCredentialConfiguration credentialConfig) {
        CredentialIssuerContext context = new CredentialIssuerContext();
        context.setCredentialConfiguration(credentialConfig);
        context.setConfigurationId(TEST_CONFIG_ID);
        context.setTenantDomain(TEST_TENANT_DOMAIN);

        Map<String, String> claims = new HashMap<>();
        claims.put("email", "test@example.com");
        claims.put("name", "Test User");
        context.setClaims(claims);

        return context;
    }
}
