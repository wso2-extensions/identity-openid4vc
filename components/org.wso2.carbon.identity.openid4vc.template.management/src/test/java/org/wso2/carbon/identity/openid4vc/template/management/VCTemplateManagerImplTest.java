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

package org.wso2.carbon.identity.openid4vc.template.management;

import org.apache.commons.lang.StringUtils;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.api.resource.mgt.APIResourceManager;
import org.wso2.carbon.identity.application.common.model.APIResource;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.internal.component.IdentityCoreServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtClientException;
import org.wso2.carbon.identity.openid4vc.template.management.exception.VCTemplateMgtException;
import org.wso2.carbon.identity.openid4vc.template.management.internal.VCTemplateManagementServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.template.management.model.VCTemplate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;


/**
 * Test class for VCCredentialConfigManagerImpl.
 * Tests service layer business logic for VC template management.
 */
@WithCarbonHome
@WithH2Database(files = {"dbscripts/h2.sql"})
@WithRealmService(injectToSingletons = {IdentityCoreServiceDataHolder.class})
public class VCTemplateManagerImplTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String TEST_IDENTIFIER = "EmployeeBadge-" + System.currentTimeMillis();
    private static final String TEST_DISPLAY_NAME = "Employee Badge Credential";
    private static final String TEST_FORMAT = "jwt_vc_json";
    private static final int TEST_EXPIRES_IN = 3600;

    private VCTemplateManager configManager;
    private VCTemplate sampleConfig;

    private MockedStatic<ClaimMetadataHandler> claimMetadataHandlerMock;

    @BeforeClass
    public void setUpClass() throws Exception {

        MockitoAnnotations.openMocks(this);

        configManager = VCTemplateManagerImpl.getInstance();

        APIResource testApiResource = new APIResource.APIResourceBuilder()
                .id("test_api")
                .name("Test API Resource")
                .type("VC")
                .identifier("test_api")
                .description("API Resource for testing")
                .requiresAuthorization(false).build();
        APIResourceManager apiResourceManager = mock(APIResourceManager.class);
        VCTemplateManagementServiceDataHolder.getInstance().setAPIResourceManager(apiResourceManager);
        when(apiResourceManager.addAPIResource(any(), any())).thenReturn(testApiResource);
        when(apiResourceManager.getAPIResourceByIdentifier(anyString(), anyString())).thenReturn(testApiResource);
        doNothing().when(apiResourceManager).deleteAPIResourceById(anyString(), anyString());

        ClaimMetadataHandler mockClaimMetadataHandler = mock(ClaimMetadataHandler.class);
        claimMetadataHandlerMock = mockStatic(ClaimMetadataHandler.class);
        claimMetadataHandlerMock.when(ClaimMetadataHandler::getInstance).thenReturn(mockClaimMetadataHandler);

        Set<ExternalClaim> vcClaims = new HashSet<>();
        vcClaims.add(new ExternalClaim("http://wso2.org/vc", "email", "http://wso2.org/claims/emailaddress"));
        vcClaims.add(new ExternalClaim("http://wso2.org/vc", "name", "http://wso2.org/claims/fullname"));
        vcClaims.add(new ExternalClaim("http://wso2.org/vc", "employee_id", "http://wso2.org/claims/employeeid"));
        vcClaims.add(new ExternalClaim("http://wso2.org/vc", "department", "http://wso2.org/claims/department"));
        vcClaims.add(new ExternalClaim("http://wso2.org/vc", "valid_claim", "http://wso2.org/claims/validclaim"));
        vcClaims.add(new ExternalClaim("http://wso2.org/vc", "another_claim", "http://wso2.org/claims/anotherclaim"));

        when(mockClaimMetadataHandler.getMappingsFromOtherDialectToCarbon(
                anyString(), isNull(), anyString())).thenReturn(vcClaims);
    }

    @AfterClass
    public void tearDownClass() {

        if (claimMetadataHandlerMock != null) {
            claimMetadataHandlerMock.close();
        }
    }

    @Test(priority = 1)
    public void testAddConfiguration() throws VCTemplateMgtException {

        VCTemplate creatingConfig = createSampleConfiguration(
                TEST_IDENTIFIER,
                TEST_DISPLAY_NAME,
                TEST_FORMAT,
                TEST_EXPIRES_IN,
                Arrays.asList("email", "name", "employee_id")
        );

        sampleConfig = configManager.add(creatingConfig, TENANT_DOMAIN);

        Assert.assertNotNull(sampleConfig.getId(), "Configuration ID should not be null.");
        Assert.assertEquals(sampleConfig.getIdentifier(), TEST_IDENTIFIER,
                "Identifier should match.");
        Assert.assertEquals(sampleConfig.getDisplayName(), TEST_DISPLAY_NAME,
                "Display name should match.");
        Assert.assertEquals(sampleConfig.getFormat(), TEST_FORMAT,
                "Format should match.");
        Assert.assertEquals(sampleConfig.getExpiresIn(), Integer.valueOf(TEST_EXPIRES_IN),
                "Expires in should match.");
        Assert.assertNotNull(sampleConfig.getClaims(),
                "Claims should not be null.");
        Assert.assertEquals(sampleConfig.getClaims().size(), 3,
                "Should have 3 claims.");
        Assert.assertEquals(sampleConfig.getSigningAlgorithm(), "RS256",
                "Default signing algorithm should be RS256.");
    }

    @Test(priority = 2, expectedExceptions = VCTemplateMgtClientException.class)
    public void testAddConfigurationWithEmptyIdentifier() throws VCTemplateMgtClientException {

        VCTemplate config = createSampleConfiguration(
                StringUtils.EMPTY,
                TEST_DISPLAY_NAME,
                TEST_FORMAT,
                TEST_EXPIRES_IN,
                Arrays.asList("email")
        );
        try {
            configManager.add(config, TENANT_DOMAIN);
            Assert.fail("Expected VCTemplateMgtClientException to be thrown");
        } catch (VCTemplateMgtClientException e) {
            Assert.assertTrue(e.getDescription().contains("Identifier")
                            && e.getDescription().contains("cannot be empty"),
                    "Exception description should contain 'Identifier cannot be empty'. Actual: "
                            + e.getDescription());
            throw e;
        } catch (VCTemplateMgtException e) {
            Assert.fail("Unexpected exception type: " + e.getClass().getName());
        }
    }

    @Test(priority = 3, expectedExceptions = VCTemplateMgtClientException.class)
    public void testAddConfigurationWithEmptyDisplayName() throws VCTemplateMgtClientException {

        VCTemplate config = createSampleConfiguration(
                "UniqueIdentifier1-" + System.currentTimeMillis(),
                StringUtils.EMPTY,
                TEST_FORMAT,
                TEST_EXPIRES_IN,
                Arrays.asList("email")
        );
        try {
            configManager.add(config, TENANT_DOMAIN);
            Assert.fail("Expected VCTemplateMgtClientException to be thrown");
        } catch (VCTemplateMgtClientException e) {
            Assert.assertTrue(e.getDescription().contains("Display name") &&
                            e.getDescription().contains("cannot be empty"),
                    "Exception description should contain 'Display name cannot be empty'. Actual: "
                            + e.getDescription());
            throw e;
        } catch (VCTemplateMgtException e) {
            Assert.fail("Unexpected exception type: " + e.getClass().getName());
        }
    }

    @Test(priority = 5, expectedExceptions = VCTemplateMgtClientException.class)
    public void testAddConfigurationWithInvalidExpiry() throws VCTemplateMgtClientException {

        VCTemplate config = createSampleConfiguration(
                "UniqueIdentifier3-" + System.currentTimeMillis(),
                TEST_DISPLAY_NAME,
                TEST_FORMAT,
                59,
                Arrays.asList("email")
        );
        try {
            configManager.add(config, TENANT_DOMAIN);
            Assert.fail("Expected VCTemplateMgtClientException to be thrown");
        } catch (VCTemplateMgtClientException e) {
            Assert.assertTrue(e.getDescription().contains("Expiry must be at least"),
                    "Exception description should contain 'Expiry must be at least'. Actual: " + e.getDescription());
            throw e;
        } catch (VCTemplateMgtException e) {
            Assert.fail("Unexpected exception type: " + e.getClass().getName());
        }
    }

    @Test(priority = 6, expectedExceptions = VCTemplateMgtClientException.class,
            expectedExceptionsMessageRegExp = ".*already exists.*")
    public void testAddConfigurationWithDuplicateIdentifier() throws VCTemplateMgtException {

        VCTemplate config = createSampleConfiguration(
                TEST_IDENTIFIER,
                "Different Display Name",
                TEST_FORMAT,
                TEST_EXPIRES_IN,
                Arrays.asList("email")
        );
        configManager.add(config, TENANT_DOMAIN);
    }

    @Test(priority = 7)
    public void testListConfigurations() throws VCTemplateMgtException {

        List<VCTemplate> configs = configManager.list(TENANT_DOMAIN);

        Assert.assertNotNull(configs, "Configuration list should not be null.");
        Assert.assertTrue(configs.size() >= 1, "Should have at least one configuration.");

        boolean found = false;
        for (VCTemplate config : configs) {
            if (sampleConfig.getId().equals(config.getId())) {
                found = true;
                Assert.assertEquals(config.getIdentifier(), TEST_IDENTIFIER);
                Assert.assertEquals(config.getDisplayName(), TEST_DISPLAY_NAME);
                break;
            }
        }
        Assert.assertTrue(found, "Sample configuration should be in the list.");
    }

    @Test(priority = 8)
    public void testGetConfigurationById() throws VCTemplateMgtException {

        VCTemplate retrieved = configManager.get(sampleConfig.getId(), TENANT_DOMAIN);

        Assert.assertNotNull(retrieved, "Retrieved configuration should not be null.");
        Assert.assertEquals(retrieved.getId(), sampleConfig.getId());
        Assert.assertEquals(retrieved.getIdentifier(), sampleConfig.getIdentifier());
        Assert.assertEquals(retrieved.getDisplayName(), sampleConfig.getDisplayName());
        Assert.assertEquals(retrieved.getFormat(), sampleConfig.getFormat());
        Assert.assertEquals(retrieved.getExpiresIn(), sampleConfig.getExpiresIn());
        Assert.assertEquals(retrieved.getClaims().size(), sampleConfig.getClaims().size());
    }

    @Test(priority = 9)
    public void testGetConfigurationByConfigId() throws VCTemplateMgtException {

        VCTemplate retrieved = configManager.getByIdentifier(
                sampleConfig.getIdentifier(), TENANT_DOMAIN);

        Assert.assertNotNull(retrieved, "Retrieved configuration should not be null.");
        Assert.assertEquals(retrieved.getId(), sampleConfig.getId());
        Assert.assertEquals(retrieved.getIdentifier(), sampleConfig.getIdentifier());
        Assert.assertEquals(retrieved.getDisplayName(), sampleConfig.getDisplayName());
    }

    @Test(priority = 10)
    public void testGetNonExistentConfiguration() throws VCTemplateMgtException {

        VCTemplate retrieved = configManager.get("non-existent-id", TENANT_DOMAIN);

        Assert.assertNull(retrieved, "Should return null for non-existent configuration.");
    }

    @Test(priority = 11)
    public void testUpdateConfiguration() throws VCTemplateMgtException {


        String updatedDisplayName = "Updated Employee Badge";
        List<String> updatedClaims = Arrays.asList("email", "name", "employee_id", "department");

        sampleConfig.setIdentifier(null);
        sampleConfig.setDisplayName(updatedDisplayName);
        sampleConfig.setClaims(updatedClaims);
        sampleConfig.setExpiresIn(7200);

        VCTemplate updated = configManager.update(
                sampleConfig.getId(), sampleConfig, TENANT_DOMAIN);

        Assert.assertNotNull(updated, "Updated configuration should not be null.");
        Assert.assertEquals(updated.getId(), sampleConfig.getId(),
                "ID should remain the same.");
        Assert.assertEquals(updated.getIdentifier(), sampleConfig.getIdentifier(),
                "Identifier should remain the same (preserved from existing).");
        Assert.assertEquals(updated.getDisplayName(), updatedDisplayName,
                "Display name should be updated.");
        Assert.assertEquals(updated.getExpiresIn(), Integer.valueOf(7200),
                "Expires in should be updated.");
        Assert.assertEquals(updated.getClaims().size(), 4,
                "Should have 4 claims after update.");
        sampleConfig = updated;
    }

    @Test(priority = 12, expectedExceptions = VCTemplateMgtClientException.class)
    public void testUpdateConfigurationWithNewIdentifier() throws VCTemplateMgtClientException {

        VCTemplate updatingConfig = new VCTemplate();
        updatingConfig.setIdentifier("NewIdentifier");
        updatingConfig.setDisplayName("Some Display Name");

        try {
            configManager.update(sampleConfig.getId(), updatingConfig, TENANT_DOMAIN);
            Assert.fail("Expected VCTemplateMgtClientException to be thrown");
        } catch (VCTemplateMgtClientException e) {
            Assert.assertTrue(e.getDescription().contains("Identifier cannot be updated"),
                    "Exception description should contain 'Identifier cannot be updated'. Actual: "
                            + e.getDescription());
            throw e;
        } catch (VCTemplateMgtException e) {
            Assert.fail("Unexpected exception type: " + e.getClass().getName());
        }
    }

    @Test(priority = 13, expectedExceptions = VCTemplateMgtClientException.class,
            expectedExceptionsMessageRegExp = ".*not found.*")
    public void testUpdateNonExistentConfiguration() throws VCTemplateMgtException {

        VCTemplate updatingConfig = new VCTemplate();
        updatingConfig.setDisplayName("Some Display Name");

        configManager.update("non-existent-id", updatingConfig, TENANT_DOMAIN);
    }

    @Test(priority = 14, expectedExceptions = VCTemplateMgtClientException.class,
            expectedExceptionsMessageRegExp = ".*mismatch.*")
    public void testUpdateConfigurationWithMismatchedId() throws VCTemplateMgtException {

        VCTemplate updatingConfig = new VCTemplate();
        updatingConfig.setId("different-id");
        updatingConfig.setDisplayName("Some Display Name");

        configManager.update(sampleConfig.getId(), updatingConfig, TENANT_DOMAIN);
    }

    @Test(priority = 15)
    public void testDeleteConfiguration() throws VCTemplateMgtException {

        VCTemplate configToDelete = createSampleConfiguration(
                "DeletableConfig-" + System.currentTimeMillis(),
                "Deletable Configuration",
                TEST_FORMAT,
                TEST_EXPIRES_IN,
                Arrays.asList("email")
        );
        VCTemplate created = configManager.add(configToDelete, TENANT_DOMAIN);
        String idToDelete = created.getId();

        VCTemplate beforeDelete = configManager.get(idToDelete, TENANT_DOMAIN);
        Assert.assertNotNull(beforeDelete, "Configuration should exist before deletion.");

        configManager.delete(idToDelete, TENANT_DOMAIN);

        VCTemplate afterDelete = configManager.get(idToDelete, TENANT_DOMAIN);
        Assert.assertNull(afterDelete, "Configuration should not exist after deletion.");
    }

    @Test(priority = 16)
    public void testAddConfigurationWithDefaultFormat() throws VCTemplateMgtException {

        VCTemplate config = createSampleConfiguration(
                "DefaultFormatConfig-" + System.currentTimeMillis(),
                "Default Format Configuration",
                null,
                TEST_EXPIRES_IN,
                Arrays.asList("email")
        );

        VCTemplate created = configManager.add(config, TENANT_DOMAIN);

        Assert.assertNotNull(created.getFormat(),
                "Format should be set to default.");
        Assert.assertEquals(created.getFormat(), "jwt_vc_json",
                "Default format should be jwt_vc_json.");
    }

    @Test(priority = 17, expectedExceptions = VCTemplateMgtClientException.class,
            expectedExceptionsMessageRegExp = ".*Unsupported.*")
    public void testAddConfigurationWithUnsupportedFormat() throws VCTemplateMgtException {

        VCTemplate config = createSampleConfiguration(
                "UnsupportedFormatConfig-" + System.currentTimeMillis(),
                "Unsupported Format Configuration",
                "ldp_vc",
                TEST_EXPIRES_IN,
                Arrays.asList("email")
        );

        configManager.add(config, TENANT_DOMAIN);
    }

    @Test(priority = 18, expectedExceptions = VCTemplateMgtClientException.class)
    public void testAddConfigurationWithInvalidClaims() throws VCTemplateMgtClientException {

        List<String> invalidClaims = new ArrayList<>();
        invalidClaims.add("valid_claim");
        invalidClaims.add("");
        invalidClaims.add("another_claim");

        VCTemplate config = createSampleConfiguration(
                "InvalidClaimsConfig-" + System.currentTimeMillis(),
                "Invalid Claims Configuration",
                TEST_FORMAT,
                TEST_EXPIRES_IN,
                invalidClaims
        );

        try {
            configManager.add(config, TENANT_DOMAIN);
            Assert.fail("Expected VCTemplateMgtClientException to be thrown");
        } catch (VCTemplateMgtClientException e) {
            Assert.assertTrue(e.getDescription().contains("Invalid claim"),
                    "Exception description should contain 'Invalid claim'. Actual: " + e.getDescription());
            throw e;
        } catch (VCTemplateMgtException e) {
            Assert.fail("Unexpected exception type: " + e.getClass().getName());
        }
    }

    /**
     * Helper method to create a sample VC template.
     *
     * @param identifier Identifier.
     * @param displayName Display name.
     * @param format Format.
     * @param expiresIn Expiry in seconds.
     * @param claims Claims list.
     * @return VCCredentialConfiguration.
     */
    private VCTemplate createSampleConfiguration(String identifier, String displayName, String format,
                                                 int expiresIn, List<String> claims) {

        VCTemplate config = new VCTemplate();
        config.setIdentifier(identifier);
        config.setDisplayName(displayName);
        config.setFormat(format);
        config.setExpiresIn(expiresIn);
        config.setClaims(claims);
        return config;
    }
}
