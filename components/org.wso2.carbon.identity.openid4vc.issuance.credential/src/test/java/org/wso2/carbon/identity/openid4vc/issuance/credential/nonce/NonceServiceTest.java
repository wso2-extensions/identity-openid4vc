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

package org.wso2.carbon.identity.openid4vc.issuance.credential.nonce;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.nonce.dao.NonceDAO;

import java.lang.reflect.Field;
import java.sql.Timestamp;
import java.util.Base64;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for NonceService.
 */
public class NonceServiceTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final int TENANT_ID = -1234;

    private NonceService nonceService;
    private NonceDAO mockNonceDAO;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;

    @BeforeMethod
    public void setUp() throws Exception {

        nonceService = new NonceService();
        mockNonceDAO = mock(NonceDAO.class);

        // Inject mock NonceDAO using reflection
        Field nonceDAOField = NonceService.class.getDeclaredField("nonceDAO");
        nonceDAOField.setAccessible(true);
        nonceDAOField.set(nonceService, mockNonceDAO);

        // Mock IdentityTenantUtil
        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);
    }

    @AfterMethod
    public void tearDown() {

        if (identityTenantUtilMockedStatic != null) {
            identityTenantUtilMockedStatic.close();
        }
    }

    @Test(description = "Test successful nonce generation")
    public void testGenerateNonceSuccess() throws Exception {

        doNothing().when(mockNonceDAO).storeNonce(anyString(), eq(TENANT_ID), any(Timestamp.class));

        String nonce = nonceService.generateNonce(TENANT_DOMAIN);

        Assert.assertNotNull(nonce, "Generated nonce should not be null");
        Assert.assertFalse(nonce.isEmpty(), "Generated nonce should not be empty");

        // Verify nonce is Base64 URL encoded (43 chars for 32 bytes without padding)
        Assert.assertEquals(nonce.length(), 43, "Nonce should be 43 characters (32 bytes Base64url without padding)");

        // Verify it can be decoded as Base64 URL
        byte[] decoded = Base64.getUrlDecoder().decode(nonce);
        Assert.assertEquals(decoded.length, 32, "Decoded nonce should be 32 bytes");

        // Verify DAO was called
        verify(mockNonceDAO).storeNonce(eq(nonce), eq(TENANT_ID), any(Timestamp.class));
    }

    @Test(description = "Test nonce generation failure due to database error",
            expectedExceptions = CredentialIssuanceException.class)
    public void testGenerateNonceDbFailure() throws Exception {

        doThrow(new CredentialIssuanceException("Database error"))
                .when(mockNonceDAO).storeNonce(anyString(), anyInt(), any(Timestamp.class));

        nonceService.generateNonce(TENANT_DOMAIN);
    }

    @Test(description = "Test successful nonce validation and consumption")
    public void testValidateAndConsumeNonceSuccess() throws Exception {

        String validNonce = "testNonce123";
        when(mockNonceDAO.validateAndConsumeNonce(validNonce, TENANT_ID)).thenReturn(true);

        boolean result = nonceService.validateAndConsumeNonce(validNonce, TENANT_DOMAIN);

        Assert.assertTrue(result, "Valid nonce should return true");
        verify(mockNonceDAO).validateAndConsumeNonce(validNonce, TENANT_ID);
    }

    @Test(description = "Test nonce validation with invalid/expired nonce")
    public void testValidateAndConsumeNonceInvalid() throws Exception {

        String invalidNonce = "invalidNonce";
        when(mockNonceDAO.validateAndConsumeNonce(invalidNonce, TENANT_ID)).thenReturn(false);

        boolean result = nonceService.validateAndConsumeNonce(invalidNonce, TENANT_DOMAIN);

        Assert.assertFalse(result, "Invalid nonce should return false");
        verify(mockNonceDAO).validateAndConsumeNonce(invalidNonce, TENANT_ID);
    }

    @Test(description = "Test nonce validation failure due to database error",
            expectedExceptions = CredentialIssuanceException.class)
    public void testValidateAndConsumeNonceDbFailure() throws Exception {

        String nonce = "testNonce";
        when(mockNonceDAO.validateAndConsumeNonce(nonce, TENANT_ID))
                .thenThrow(new CredentialIssuanceException("Database error"));

        nonceService.validateAndConsumeNonce(nonce, TENANT_DOMAIN);
    }
}
