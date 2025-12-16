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

package org.wso2.carbon.identity.openid4vc.issuance.offer;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.openid4vc.issuance.common.util.CommonUtil;
import org.wso2.carbon.identity.openid4vc.issuance.offer.exception.CredentialOfferException;
import org.wso2.carbon.identity.openid4vc.issuance.offer.internal.CredentialOfferDataHolder;
import org.wso2.carbon.identity.openid4vc.issuance.offer.response.CredentialOfferResponse;
import org.wso2.carbon.identity.openid4vc.template.management.VCTemplateManager;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtException;
import org.wso2.carbon.identity.openid4vc.template.management.model.VCTemplate;

import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Test class for DefaultCredentialOfferProcessor.
 * Tests credential offer generation with minimal focused tests.
 */
public class DefaultCredentialOfferProcessorTest {

    private static final String TEST_OFFER_ID = "offer-123";
    private static final String TEST_TENANT_DOMAIN = "carbon.super";
    private static final String TEST_ISSUER_URL = "https://localhost:9443/oid4vci";
    private static final String TEST_TOKEN_URL = "https://localhost:9443/oauth2/token";
    private static final String TEST_TEMPLATE_ID = "config-123";
    private static final String TEST_IDENTIFIER = "employee_badge";

    private DefaultCredentialOfferProcessor processor;
    private VCTemplateManager configManager;
    private MockedStatic<CommonUtil> commonUtilMockedStatic;

    @BeforeMethod
    public void setUp() {
        processor = DefaultCredentialOfferProcessor.getInstance();
        configManager = mock(VCTemplateManager.class);

        CredentialOfferDataHolder.getInstance().setVCTemplateManager(configManager);
    }

    @AfterMethod
    public void tearDown() {
        if (commonUtilMockedStatic != null) {
            commonUtilMockedStatic.close();
        }
    }

    @Test(priority = 1, description = "Test successful credential offer generation")
    public void testGenerateOfferSuccess() throws Exception {
        // Mock URL building
        commonUtilMockedStatic = mockCommonUtil();

        // Mock VCCredentialConfigurations
        VCTemplate config = createTestConfiguration();
        when(configManager.getByOfferId(TEST_OFFER_ID, TEST_TENANT_DOMAIN)).thenReturn(config);

        // Execute
        CredentialOfferResponse response = processor.generateOffer(TEST_OFFER_ID, TEST_TENANT_DOMAIN);

        // Verify
        Assert.assertNotNull(response, "Response should not be null");
        Map<String, Object> offer = response.getOffer();
        Assert.assertNotNull(offer, "Offer should not be null");

        // Verify required fields
        Assert.assertTrue(offer.containsKey("credential_issuer"),
                "Should contain credential_issuer");
        Assert.assertTrue(offer.containsKey("credential_configuration_ids"),
                "Should contain credential_configuration_ids");
        Assert.assertTrue(offer.containsKey("grants"),
                "Should contain grants");

        // Verify credential_issuer URL
        Assert.assertEquals(offer.get("credential_issuer"), TEST_ISSUER_URL);

        // Verify credential_configuration_ids
        @SuppressWarnings("unchecked")
        List<String> configIds = (List<String>) offer.get("credential_configuration_ids");
        Assert.assertNotNull(configIds, "Configuration IDs should not be null");
        Assert.assertEquals(configIds.size(), 1, "Should have 1 configuration IDs");
        Assert.assertTrue(configIds.contains(TEST_IDENTIFIER), "Should contain employee_badge");

        // Verify grants structure
        @SuppressWarnings("unchecked")
        Map<String, Object> grants = (Map<String, Object>) offer.get("grants");
        Assert.assertNotNull(grants, "Grants should not be null");
        Assert.assertTrue(grants.containsKey("authorization_code"),
                "Grants should contain authorization_code");

        @SuppressWarnings("unchecked")
        Map<String, Object> authCodeGrant = (Map<String, Object>) grants.get("authorization_code");
        Assert.assertNotNull(authCodeGrant, "Authorization code grant should not be null");
        Assert.assertEquals(authCodeGrant.get("authorization_server"), TEST_TOKEN_URL);
    }

    @Test(priority = 3, description = "Test error handling when config retrieval fails",
            expectedExceptions = CredentialOfferException.class)
    public void testGenerateOfferWithConfigRetrievalError() throws Exception {
        // Mock URL building
        commonUtilMockedStatic = mockCommonUtil();

        // Mock configManager to throw exception
        when(configManager.getByOfferId(TEST_OFFER_ID, TEST_TENANT_DOMAIN))
                .thenThrow(new VCTemplateMgtException("Config not found", "Error retrieving config", "error-code"));

        // Execute - should throw CredentialOfferException
        try {
            processor.generateOffer(TEST_OFFER_ID, TEST_TENANT_DOMAIN);
            Assert.fail("Expected CredentialOfferException to be thrown");
        } catch (CredentialOfferException e) {
            Assert.assertTrue(e.getDescription().contains("Error while retrieving") ||
                    e.getDescription().contains("offer ID"),
                    "Exception description should indicate retrieval error. Actual: " + e.getDescription());
            throw e;
        }
    }

    /**
     * Helper method to mock CommonUtil URL building.
     */
    private MockedStatic<CommonUtil> mockCommonUtil() throws Exception {
        MockedStatic<CommonUtil> mockedStatic = mockStatic(CommonUtil.class);

        ServiceURL issuerUrl = mock(ServiceURL.class);
        when(issuerUrl.getAbsolutePublicURL()).thenReturn(TEST_ISSUER_URL);

        ServiceURL tokenUrl = mock(ServiceURL.class);
        when(tokenUrl.getAbsolutePublicURL()).thenReturn(TEST_TOKEN_URL);

        mockedStatic.when(() -> CommonUtil.buildServiceUrl(anyString(), any()))
                .thenReturn(issuerUrl);
        mockedStatic.when(() -> CommonUtil.buildServiceUrl(anyString(), any(), any()))
                .thenReturn(tokenUrl);

        return mockedStatic;
    }

    /**
     * Helper method to create a test VC template.
     */
    private VCTemplate createTestConfiguration() {
        VCTemplate config = new VCTemplate();
        config.setId(DefaultCredentialOfferProcessorTest.TEST_TEMPLATE_ID);
        config.setIdentifier(DefaultCredentialOfferProcessorTest.TEST_IDENTIFIER);
        config.setDisplayName("Test Config " + DefaultCredentialOfferProcessorTest.TEST_TEMPLATE_ID);
        config.setFormat("jwt_vc_json");
        config.setOfferId(DefaultCredentialOfferProcessorTest.TEST_OFFER_ID);
        return config;
    }
}
