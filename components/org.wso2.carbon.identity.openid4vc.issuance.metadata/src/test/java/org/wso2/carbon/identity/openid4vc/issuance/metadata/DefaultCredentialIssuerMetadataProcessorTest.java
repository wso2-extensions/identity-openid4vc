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

package org.wso2.carbon.identity.openid4vc.issuance.metadata;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.openid4vc.issuance.common.util.CommonUtil;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.exception.CredentialIssuerMetadataException;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.internal.CredentialIssuerMetadataDataHolder;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.response.CredentialIssuerMetadataResponse;
import org.wso2.carbon.identity.openid4vc.template.management.VCTemplateManager;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtException;
import org.wso2.carbon.identity.openid4vc.template.management.model.VCTemplate;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Test class for DefaultCredentialIssuerMetadataProcessor.
 * Tests metadata response generation with minimal focused tests.
 */
public class DefaultCredentialIssuerMetadataProcessorTest {

    private static final String TEST_TENANT_DOMAIN = "carbon.super";
    private static final String TEST_ISSUER_URL = "https://localhost:9443/oid4vci";
    private static final String TEST_CREDENTIAL_ENDPOINT_URL = "https://localhost:9443/oid4vci/credential";
    private static final String TEST_TOKEN_URL = "https://localhost:9443/oauth2/token";

    private DefaultCredentialIssuerMetadataProcessor processor;
    private VCTemplateManager configManager;
    private MockedStatic<CommonUtil> commonUtilMockedStatic;

    @BeforeMethod
    public void setUp() {
        processor = DefaultCredentialIssuerMetadataProcessor.getInstance();
        configManager = mock(VCTemplateManager.class);
        CredentialIssuerMetadataDataHolder.getInstance().setVCTemplateManager(configManager);
    }

    @AfterMethod
    public void tearDown() {
        if (commonUtilMockedStatic != null) {
            commonUtilMockedStatic.close();
        }
    }

    @Test(priority = 1, description = "Test successful metadata response generation")
    public void testGetMetadataResponseSuccess() throws Exception {
        // Mock URL building
        commonUtilMockedStatic = mockCommonUtil();

        // Mock templates
        VCTemplate config = createTestConfiguration();
        when(configManager.list(TEST_TENANT_DOMAIN)).thenReturn(Collections.singletonList(config));
        when(configManager.get(config.getId(), TEST_TENANT_DOMAIN)).thenReturn(config);

        // Execute
        CredentialIssuerMetadataResponse response = processor.getMetadataResponse(TEST_TENANT_DOMAIN);

        // Verify
        Assert.assertNotNull(response, "Response should not be null");
        Map<String, Object> metadata = response.getMetadata();
        Assert.assertNotNull(metadata, "Metadata should not be null");

        // Verify required fields
        Assert.assertTrue(metadata.containsKey("credential_issuer"),
                "Should contain credential_issuer");
        Assert.assertTrue(metadata.containsKey("credential_endpoint"),
                "Should contain credential_endpoint");
        Assert.assertTrue(metadata.containsKey("authorization_servers"),
                "Should contain authorization_servers");
        Assert.assertTrue(metadata.containsKey("credential_configurations_supported"),
                "Should contain credential_configurations_supported");

        // Verify URLs
        Assert.assertEquals(metadata.get("credential_issuer"), TEST_ISSUER_URL);
        Assert.assertEquals(metadata.get("credential_endpoint"), TEST_CREDENTIAL_ENDPOINT_URL);
    }

    @Test(priority = 2, description = "Test tenant domain resolution with null/empty tenant")
    public void testGetMetadataResponseWithNullTenant() throws Exception {
        // Mock URL building
        commonUtilMockedStatic = mockCommonUtil();

        // Mock empty configurations
        when(configManager.list(anyString())).thenReturn(Collections.emptyList());

        // Test with null tenant - should default to carbon.super
        CredentialIssuerMetadataResponse response1 = processor.getMetadataResponse(null);
        Assert.assertNotNull(response1, "Response should not be null for null tenant");

        // Test with empty tenant - should default to carbon.super
        CredentialIssuerMetadataResponse response2 = processor.getMetadataResponse("");
        Assert.assertNotNull(response2, "Response should not be null for empty tenant");

        // Test with whitespace tenant - should default to carbon.super
        CredentialIssuerMetadataResponse response3 = processor.getMetadataResponse("  ");
        Assert.assertNotNull(response3, "Response should not be null for whitespace tenant");
    }

    @Test(priority = 3, description = "Test error handling when config retrieval fails",
            expectedExceptions = CredentialIssuerMetadataException.class,
            expectedExceptionsMessageRegExp = ".*Error while retrieving VC templates.*")
    public void testGetMetadataResponseWithConfigRetrievalError() throws Exception {
        // Mock URL building
        commonUtilMockedStatic = mockCommonUtil();

        // Mock config manager to throw exception
        when(configManager.list(TEST_TENANT_DOMAIN))
                .thenThrow(new VCTemplateMgtException("Database error", "Error retrieving templates", "error"));

        // Execute - should throw CredentialIssuerMetadataException
        processor.getMetadataResponse(TEST_TENANT_DOMAIN);
    }

    /**
     * Helper method to mock CommonUtil URL building.
     */
    private MockedStatic<CommonUtil> mockCommonUtil() throws Exception {
        MockedStatic<CommonUtil> mockedStatic = mockStatic(CommonUtil.class);

        ServiceURL issuerUrl = mock(ServiceURL.class);
        when(issuerUrl.getAbsolutePublicURL()).thenReturn(TEST_ISSUER_URL);

        ServiceURL credentialUrl = mock(ServiceURL.class);
        when(credentialUrl.getAbsolutePublicURL()).thenReturn(TEST_CREDENTIAL_ENDPOINT_URL);

        ServiceURL tokenUrl = mock(ServiceURL.class);
        when(tokenUrl.getAbsolutePublicURL()).thenReturn(TEST_TOKEN_URL);

        mockedStatic.when(() -> CommonUtil.buildServiceUrl(anyString(), any()))
                .thenReturn(issuerUrl);
        mockedStatic.when(() -> CommonUtil.buildServiceUrl(anyString(), any(), any()))
                .thenAnswer(invocation -> {
                    String segment = invocation.getArgument(1);
                    if ("oid4vci".equals(segment)) {
                        return credentialUrl;
                    }
                    return tokenUrl;
                });

        return mockedStatic;
    }

    /**
     * Helper method to create a test VC template.
     */
    private VCTemplate createTestConfiguration() {
        VCTemplate config = new VCTemplate();
        config.setId("config-123");
        config.setIdentifier("employee_badge");
        config.setFormat("jwt_vc_json");
        config.setSigningAlgorithm("RS256");
        config.setClaims(Arrays.asList("email", "name", "employee_id"));
        config.setDisplayName("Employee Badge Credential");

        return config;
    }
}
