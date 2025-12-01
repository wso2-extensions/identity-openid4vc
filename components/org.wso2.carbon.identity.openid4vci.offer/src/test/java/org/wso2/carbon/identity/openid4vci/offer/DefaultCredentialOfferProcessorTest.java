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

package org.wso2.carbon.identity.openid4vci.offer;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.openid4vci.common.util.CommonUtil;
import org.wso2.carbon.identity.openid4vci.offer.exception.CredentialOfferException;
import org.wso2.carbon.identity.openid4vci.offer.internal.CredentialOfferDataHolder;
import org.wso2.carbon.identity.openid4vci.offer.response.CredentialOfferResponse;
import org.wso2.carbon.identity.vc.config.management.VCCredentialConfigManager;
import org.wso2.carbon.identity.vc.config.management.VCOfferManager;
import org.wso2.carbon.identity.vc.config.management.exception.VCConfigMgtException;
import org.wso2.carbon.identity.vc.config.management.model.VCCredentialConfiguration;
import org.wso2.carbon.identity.vc.config.management.model.VCOffer;

import java.util.Arrays;
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
    private static final String TEST_CONFIG_ID_1 = "config-123";
    private static final String TEST_CONFIG_ID_2 = "config-456";
    private static final String TEST_IDENTIFIER_1 = "employee_badge";
    private static final String TEST_IDENTIFIER_2 = "student_id";

    private DefaultCredentialOfferProcessor processor;
    private VCOfferManager offerManager;
    private VCCredentialConfigManager configManager;
    private MockedStatic<CommonUtil> commonUtilMockedStatic;

    @BeforeMethod
    public void setUp() {
        processor = DefaultCredentialOfferProcessor.getInstance();
        offerManager = mock(VCOfferManager.class);
        configManager = mock(VCCredentialConfigManager.class);

        CredentialOfferDataHolder.getInstance().setVCOfferManager(offerManager);
        CredentialOfferDataHolder.getInstance().setVcCredentialConfigManager(configManager);
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

        // Mock VCOffer
        VCOffer vcOffer = createTestVCOffer();
        when(offerManager.get(TEST_OFFER_ID, TEST_TENANT_DOMAIN)).thenReturn(vcOffer);

        // Mock VCCredentialConfigurations
        VCCredentialConfiguration config1 = createTestConfiguration(TEST_CONFIG_ID_1, TEST_IDENTIFIER_1);
        VCCredentialConfiguration config2 = createTestConfiguration(TEST_CONFIG_ID_2, TEST_IDENTIFIER_2);
        when(configManager.get(TEST_CONFIG_ID_1, TEST_TENANT_DOMAIN)).thenReturn(config1);
        when(configManager.get(TEST_CONFIG_ID_2, TEST_TENANT_DOMAIN)).thenReturn(config2);

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
        Assert.assertEquals(configIds.size(), 2, "Should have 2 configuration IDs");
        Assert.assertTrue(configIds.contains(TEST_IDENTIFIER_1), "Should contain employee_badge");
        Assert.assertTrue(configIds.contains(TEST_IDENTIFIER_2), "Should contain student_id");

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

    @Test(priority = 2, description = "Test error handling when offer retrieval fails",
            expectedExceptions = CredentialOfferException.class,
            expectedExceptionsMessageRegExp = ".*Error while retrieving VC offer.*")
    public void testGenerateOfferWithOfferRetrievalError() throws Exception {
        // Mock URL building
        commonUtilMockedStatic = mockCommonUtil();

        // Mock offerManager to throw exception
        when(offerManager.get(TEST_OFFER_ID, TEST_TENANT_DOMAIN))
                .thenThrow(new VCConfigMgtException("error-code", "Offer not found"));

        // Execute - should throw CredentialOfferException
        processor.generateOffer(TEST_OFFER_ID, TEST_TENANT_DOMAIN);
    }

    @Test(priority = 3, description = "Test error handling when config retrieval fails",
            expectedExceptions = CredentialOfferException.class,
            expectedExceptionsMessageRegExp = ".*Error while retrieving VC credential configuration.*")
    public void testGenerateOfferWithConfigRetrievalError() throws Exception {
        // Mock URL building
        commonUtilMockedStatic = mockCommonUtil();

        // Mock VCOffer
        VCOffer vcOffer = createTestVCOffer();
        when(offerManager.get(TEST_OFFER_ID, TEST_TENANT_DOMAIN)).thenReturn(vcOffer);

        // Mock configManager to throw exception
        when(configManager.get(TEST_CONFIG_ID_1, TEST_TENANT_DOMAIN))
                .thenThrow(new VCConfigMgtException("error-code", "Config not found"));

        // Execute - should throw CredentialOfferException
        processor.generateOffer(TEST_OFFER_ID, TEST_TENANT_DOMAIN);
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
     * Helper method to create a test VCOffer.
     */
    private VCOffer createTestVCOffer() {
        VCOffer offer = new VCOffer();
        offer.setOfferId(TEST_OFFER_ID);
        offer.setCredentialConfigurationIds(Arrays.asList(TEST_CONFIG_ID_1, TEST_CONFIG_ID_2));
        return offer;
    }

    /**
     * Helper method to create a test VC credential configuration.
     */
    private VCCredentialConfiguration createTestConfiguration(String id, String identifier) {
        VCCredentialConfiguration config = new VCCredentialConfiguration();
        config.setId(id);
        config.setIdentifier(identifier);
        config.setFormat("jwt_vc_json");
        config.setScope(identifier);
        return config;
    }
}
