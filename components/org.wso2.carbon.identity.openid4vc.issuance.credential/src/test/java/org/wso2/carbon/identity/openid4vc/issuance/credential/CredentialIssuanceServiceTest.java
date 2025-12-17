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

package org.wso2.carbon.identity.openid4vc.issuance.credential;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenProvider;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.dto.CredentialIssuanceReqDTO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.dto.CredentialIssuanceRespDTO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.internal.CredentialIssuanceDataHolder;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.CredentialIssuerContext;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.handlers.CredentialFormatHandler;
import org.wso2.carbon.identity.openid4vc.template.management.VCTemplateManager;
import org.wso2.carbon.identity.openid4vc.template.management.model.VCTemplate;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Test class for CredentialIssuanceService.
 * Tests service layer business logic for credential issuance.
 */
public class CredentialIssuanceServiceTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String TEST_TEMPLATE_ID = "test-template-123";
    private static final String TEST_TOKEN = "test-access-token";
    private static final String TEST_USER_ID = "user-123";
    private static final String TEST_USERNAME = "testuser@carbon.super";

    private CredentialIssuanceService credentialIssuanceService;
    MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    MockedStatic<ServiceURLBuilder> serviceUrlBuilderMockedStatic;
    private static final RealmService realmService = mock(RealmService.class);
    private static final TenantManager tenantManager = mock(TenantManager.class);
    private static final UserRealm userRealm = mock(UserRealm.class);
    private static final AbstractUserStoreManager userStoreManager = mock(AbstractUserStoreManager.class);
    private static final VCTemplateManager vcTemplateManager = mock(VCTemplateManager.class);

    @BeforeClass
    public void setUpClass() {

        // Initialize the service
        credentialIssuanceService = new CredentialIssuanceService();
    }

    @BeforeMethod
    public void setUp() {

        // Close any existing static mocks before each test
        if (identityTenantUtilMockedStatic != null) {
            identityTenantUtilMockedStatic.close();
            identityTenantUtilMockedStatic = null;
        }
        if (serviceUrlBuilderMockedStatic != null) {
            serviceUrlBuilderMockedStatic.close();
            serviceUrlBuilderMockedStatic = null;
        }

        // Clear DataHolder state to prevent test pollution
        CredentialIssuanceDataHolder.getInstance().setVCTemplateManager(null);
        CredentialIssuanceDataHolder.getInstance().setTokenProvider(null);
        CredentialIssuanceDataHolder.getInstance().setRealmService(null);

        // Clear format handlers
        CredentialIssuanceDataHolder.getInstance().getCredentialFormatHandlers().clear();
    }

    @AfterMethod
    public void tearDown() {

        if (identityTenantUtilMockedStatic != null) {
            identityTenantUtilMockedStatic.close();
            identityTenantUtilMockedStatic = null;
        }
        if (serviceUrlBuilderMockedStatic != null) {
            serviceUrlBuilderMockedStatic.close();
            serviceUrlBuilderMockedStatic = null;
        }
    }

    @Test(priority = 1, description = "Test successful credential issuance")
    public void testIssueCredentialSuccess() throws Exception {
        // Setup static mocks
        serviceUrlBuilderMockedStatic = mockServiceUrlBuilder();
        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);

        // Prepare test data
        CredentialIssuanceReqDTO reqDTO = createTestRequest();
        VCTemplate vcTemplate = createTestVCTemplate();
        Map<String, String> userClaims = createTestUserClaims();

        // Mock template manager
        CredentialIssuanceDataHolder.getInstance().setVCTemplateManager(vcTemplateManager);
        when(vcTemplateManager.getByIdentifier(TEST_TEMPLATE_ID, TENANT_DOMAIN))
                .thenReturn(vcTemplate);

        // Mock credential format handler
        CredentialFormatHandler mockFormatHandler = mock(CredentialFormatHandler.class);
        when(mockFormatHandler.getFormat()).thenReturn("jwt_vc_json");
        when(mockFormatHandler.issueCredential(any(CredentialIssuerContext.class)))
                .thenReturn("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature");
        CredentialIssuanceDataHolder.getInstance().addCredentialFormatHandler(mockFormatHandler);

        // Mock token provider with valid token
        TokenProvider tokenProvider = mock(TokenProvider.class);
        CredentialIssuanceDataHolder.getInstance().setTokenProvider(tokenProvider);
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setScope(new String[]{TEST_TEMPLATE_ID, "openid"});
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(TEST_USERNAME);
        authenticatedUser.setUserId(TEST_USER_ID);
        accessTokenDO.setAuthzUser(authenticatedUser);
        when(tokenProvider.getVerifiedAccessToken(TEST_TOKEN, false)).thenReturn(accessTokenDO);

        // Mock realm service for user claims
        CredentialIssuanceDataHolder.getInstance().setRealmService(realmService);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(tenantManager.getTenantId(TENANT_DOMAIN)).thenReturn(-1234);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValuesWithID(TEST_USER_ID,
                vcTemplate.getClaims().toArray(new String[0]), null))
                .thenReturn(userClaims);

        // Mock IdentityTenantUtil
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(-1234);

        // Execute the test
        CredentialIssuanceRespDTO response = credentialIssuanceService.issueCredential(reqDTO);

        // Verify the response
        Assert.assertNotNull(response, "Response should not be null");
        Assert.assertNotNull(response.getCredential(), "Credential should not be null");
        Assert.assertTrue(response.getCredential().startsWith("eyJ"),
                "Credential should be a JWT token");
    }

    @Test(priority = 2, description = "Test with null request DTO",
            expectedExceptions = CredentialIssuanceException.class)
    public void testIssueCredentialWithNullDTO() throws CredentialIssuanceException {
        // Test with null request DTO
        try {
            credentialIssuanceService.issueCredential(null);
            Assert.fail("Expected CredentialIssuanceException to be thrown");
        } catch (CredentialIssuanceException e) {
            Assert.assertTrue(e.getDescription().contains("invalid") || e.getDescription().contains("malformed"),
                    "Exception description should indicate invalid request. Actual: " + e.getDescription());
            throw e;
        }
    }

    @Test(priority = 3, description = "Test with invalid access token",
            expectedExceptions = CredentialIssuanceException.class)
    public void testIssueCredentialWithInvalidAccessToken() throws Exception {
        // Mock template manager
        CredentialIssuanceDataHolder.getInstance().setVCTemplateManager(vcTemplateManager);

        // Mock token provider to throw exception for invalid token
        TokenProvider tokenProvider = mock(TokenProvider.class);
        CredentialIssuanceDataHolder.getInstance().setTokenProvider(tokenProvider);
        when(tokenProvider.getVerifiedAccessToken(TEST_TOKEN, false))
                .thenThrow(new IdentityOAuth2Exception("Invalid access token"));

        // Execute test with invalid token
        CredentialIssuanceReqDTO reqDTO = createTestRequest();
        try {
            credentialIssuanceService.issueCredential(reqDTO);
            Assert.fail("Expected CredentialIssuanceException to be thrown");
        } catch (CredentialIssuanceException e) {
            Assert.assertTrue(e.getDescription().contains("invalid") || e.getDescription().contains("expired")
                    || e.getDescription().contains("revoked"),
                    "Exception description should indicate invalid token. Actual: " + e.getDescription());
            throw e;
        }
    }

    @Test(priority = 4, description = "Test with invalid template ID",
            expectedExceptions = CredentialIssuanceException.class)
    public void testIssueCredentialWithInvalidCredentialConfigurationId() throws Exception {
        // Mock template manager to return null for invalid config ID
        CredentialIssuanceDataHolder.getInstance().setVCTemplateManager(vcTemplateManager);
        when(vcTemplateManager.getByIdentifier("invalid-template-id", TENANT_DOMAIN))
                .thenReturn(null);

        // Mock token provider with valid token
        TokenProvider tokenProvider = mock(TokenProvider.class);
        CredentialIssuanceDataHolder.getInstance().setTokenProvider(tokenProvider);
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setScope(new String[]{"invalid-template-id"});
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(TEST_USERNAME);
        accessTokenDO.setAuthzUser(authenticatedUser);
        when(tokenProvider.getVerifiedAccessToken(TEST_TOKEN, false)).thenReturn(accessTokenDO);

        // Execute test with invalid template ID
        CredentialIssuanceReqDTO reqDTO = createTestRequest();
        reqDTO.setCredentialConfigurationId("invalid-template-id");
        try {
            credentialIssuanceService.issueCredential(reqDTO);
            Assert.fail("Expected CredentialIssuanceException to be thrown");
        } catch (CredentialIssuanceException e) {
            Assert.assertTrue(e.getDescription().contains("not supported") || e.getDescription().contains("unknown")
                    || e.getDescription().contains("does not exist"),
                    "Exception description should indicate unknown configuration. Actual: " + e.getDescription());
            throw e;
        }
    }

    @Test(priority = 5, description = "Test with failed scope validation",
            expectedExceptions = CredentialIssuanceException.class)
    public void testIssueCredentialWithFailedScopeValidation() throws Exception {
        // Mock template with required scope
        VCTemplate credentialvcTemplate = createTestVCTemplate();
        CredentialIssuanceDataHolder.getInstance().setVCTemplateManager(vcTemplateManager);
        when(vcTemplateManager.getByIdentifier(TEST_TEMPLATE_ID, TENANT_DOMAIN))
                .thenReturn(credentialvcTemplate);

        // Mock token provider with token that has WRONG scopes (missing required scope)
        TokenProvider tokenProvider = mock(TokenProvider.class);
        CredentialIssuanceDataHolder.getInstance().setTokenProvider(tokenProvider);
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setScope(new String[]{"openid", "profile", "email"}); // Missing TEST_SCOPE
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(TEST_USERNAME);
        accessTokenDO.setAuthzUser(authenticatedUser);
        when(tokenProvider.getVerifiedAccessToken(TEST_TOKEN, false)).thenReturn(accessTokenDO);

        // Execute test - should fail at scope validation
        CredentialIssuanceReqDTO reqDTO = createTestRequest();
        try {
            credentialIssuanceService.issueCredential(reqDTO);
            Assert.fail("Expected CredentialIssuanceException to be thrown");
        } catch (CredentialIssuanceException e) {
            Assert.assertTrue(e.getDescription().contains("scope") || e.getDescription().contains("required"),
                    "Exception description should indicate insufficient scope. Actual: " + e.getDescription());
            throw e;
        }
    }

    private MockedStatic<ServiceURLBuilder> mockServiceUrlBuilder() throws Exception {

        ServiceURL serviceURL = mock(ServiceURL.class);
        when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443/openid4vci");

        MockedStatic<ServiceURLBuilder> mockedServiceURLBuilder = mockStatic(ServiceURLBuilder.class);
        ServiceURLBuilder mockBuilder = mock(ServiceURLBuilder.class);

        mockedServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockBuilder);
        when(mockBuilder.addPath(any(String[].class))).thenReturn(mockBuilder);
        when(mockBuilder.setTenant(anyString())).thenReturn(mockBuilder);
        when(mockBuilder.addParameter(any(), any())).thenReturn(mockBuilder);
        when(mockBuilder.build()).thenReturn(serviceURL);

        return mockedServiceURLBuilder;
    }

    /**
     * Helper method to create a test credential issuance request.
     *
     * @return CredentialIssuanceReqDTO.
     */
    private CredentialIssuanceReqDTO createTestRequest() {
        CredentialIssuanceReqDTO reqDTO = new CredentialIssuanceReqDTO();
        reqDTO.setTenantDomain(TENANT_DOMAIN);
        reqDTO.setCredentialConfigurationId(TEST_TEMPLATE_ID);
        reqDTO.setToken(TEST_TOKEN);
        return reqDTO;
    }

    /**
     * Helper method to create a test template.
     *
     * @return VCTemplate.
     */
    private VCTemplate createTestVCTemplate() {
        VCTemplate template = new VCTemplate();
        template.setId("template-id-123");
        template.setIdentifier(TEST_TEMPLATE_ID);
        template.setDisplayName("Test Template");
        template.setFormat("jwt_vc_json");
        template.setExpiresIn(3600);
        template.setSigningAlgorithm("RS256");

        List<String> claims = Arrays.asList(
                "http://wso2.org/claims/emailaddress",
                "http://wso2.org/claims/fullname",
                "http://wso2.org/claims/employeeid"
        );
        template.setClaims(claims);

        return template;
    }

    /**
     * Helper method to create test user claims.
     *
     * @return Map of user claims.
     */
    private Map<String, String> createTestUserClaims() {
        Map<String, String> claims = new HashMap<>();
        claims.put("email", "testuser@example.com");
        claims.put("given_name", "Test User");
        return claims;
    }
}
