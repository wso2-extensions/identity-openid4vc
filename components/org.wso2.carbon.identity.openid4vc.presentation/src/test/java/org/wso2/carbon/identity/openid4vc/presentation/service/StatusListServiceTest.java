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

package org.wso2.carbon.identity.openid4vc.presentation.service;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.exception.RevocationCheckException;
import org.wso2.carbon.identity.openid4vc.presentation.model.RevocationCheckResult;
import org.wso2.carbon.identity.openid4vc.presentation.model.VerifiableCredential;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.StatusListServiceImpl;

/**
 * Unit tests for StatusListService.
 */
public class StatusListServiceTest {

    private StatusListService statusListService;

    @BeforeMethod
    public void setUp() {
        statusListService = new StatusListServiceImpl();
    }

    @Test
    public void testCheckRevocationStatusWithNoCredentialStatus() throws RevocationCheckException {
        // Arrange - credential status is null
        VerifiableCredential.CredentialStatus credentialStatus = null;

        // Act
        RevocationCheckResult result = statusListService.checkRevocationStatus(credentialStatus);

        // Assert
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getStatus(), RevocationCheckResult.Status.SKIPPED);
    }

    @Test
    public void testCheckRevocationStatusWithUnknownType() throws RevocationCheckException {
        // Arrange
        VerifiableCredential.CredentialStatus credentialStatus = new VerifiableCredential.CredentialStatus();
        credentialStatus.setType("UnknownStatusType");
        credentialStatus.setStatusListCredential("https://example.com/status/1");
        credentialStatus.setStatusListIndex("42");

        // Act
        RevocationCheckResult result = statusListService.checkRevocationStatus(credentialStatus);

        // Assert
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getStatus(), RevocationCheckResult.Status.UNKNOWN);
    }

    @Test
    public void testCheckRevocationStatusWithMissingUrl() throws RevocationCheckException {
        // Arrange
        VerifiableCredential.CredentialStatus credentialStatus = new VerifiableCredential.CredentialStatus();
        credentialStatus.setType("StatusList2021Entry");
        credentialStatus.setStatusListCredential(null);
        credentialStatus.setStatusListIndex("42");

        // Act
        RevocationCheckResult result = statusListService.checkRevocationStatus(credentialStatus);

        // Assert
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getStatus(), RevocationCheckResult.Status.UNKNOWN);
    }

    @Test
    public void testCheckRevocationStatusWithMissingIndex() throws RevocationCheckException {
        // Arrange
        VerifiableCredential.CredentialStatus credentialStatus = new VerifiableCredential.CredentialStatus();
        credentialStatus.setType("StatusList2021Entry");
        credentialStatus.setStatusListCredential("https://example.com/status/1");
        credentialStatus.setStatusListIndex(null);

        // Act
        RevocationCheckResult result = statusListService.checkRevocationStatus(credentialStatus);

        // Assert
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getStatus(), RevocationCheckResult.Status.UNKNOWN);
    }

    @Test
    public void testIsBitSetAtIndex0() {
        // Arrange - First byte = 0x80 (10000000 in binary), meaning bit 0 is set
        byte[] bitstring = new byte[] { (byte) 0x80, 0x00, 0x00 };

        // Act & Assert
        Assert.assertTrue(statusListService.isBitSet(bitstring, 0));
        Assert.assertFalse(statusListService.isBitSet(bitstring, 1));
        Assert.assertFalse(statusListService.isBitSet(bitstring, 7));
    }

    @Test
    public void testIsBitSetAtIndex7() {
        // Arrange - First byte = 0x01 (00000001 in binary), meaning bit 7 is set
        byte[] bitstring = new byte[] { 0x01, 0x00, 0x00 };

        // Act & Assert
        Assert.assertFalse(statusListService.isBitSet(bitstring, 0));
        Assert.assertFalse(statusListService.isBitSet(bitstring, 6));
        Assert.assertTrue(statusListService.isBitSet(bitstring, 7));
    }

    @Test
    public void testIsBitSetAtIndex8() {
        // Arrange - Second byte = 0x80 (10000000 in binary), meaning bit 8 is set
        byte[] bitstring = new byte[] { 0x00, (byte) 0x80, 0x00 };

        // Act & Assert
        Assert.assertFalse(statusListService.isBitSet(bitstring, 7));
        Assert.assertTrue(statusListService.isBitSet(bitstring, 8));
        Assert.assertFalse(statusListService.isBitSet(bitstring, 9));
    }

    @Test
    public void testIsBitSetOutOfBounds() {
        // Arrange
        byte[] bitstring = new byte[] { (byte) 0xFF }; // Only 8 bits

        // Act - Index beyond the bitstring should return false
        Assert.assertFalse(statusListService.isBitSet(bitstring, 100));
    }

    @Test
    public void testIsBitSetWithNullBitstring() {
        // Act
        Assert.assertFalse(statusListService.isBitSet(null, 0));
    }

    @Test
    public void testIsBitSetWithEmptyBitstring() {
        // Act
        Assert.assertFalse(statusListService.isBitSet(new byte[0], 0));
    }

    @Test
    public void testIsRevocationCheckEnabled() {
        // Assert - default should be enabled
        Assert.assertTrue(statusListService.isRevocationCheckEnabled());
    }

    @Test
    public void testDisableRevocationCheck() throws RevocationCheckException {
        // Arrange
        StatusListServiceImpl impl = (StatusListServiceImpl) statusListService;
        impl.setRevocationCheckEnabled(false);

        VerifiableCredential.CredentialStatus credentialStatus = new VerifiableCredential.CredentialStatus();
        credentialStatus.setType("StatusList2021Entry");
        credentialStatus.setStatusListCredential("https://example.com/status/1");
        credentialStatus.setStatusListIndex("42");

        // Act
        RevocationCheckResult result = statusListService.checkRevocationStatus(credentialStatus);

        // Assert - should be skipped when disabled
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getStatus(), RevocationCheckResult.Status.SKIPPED);

        // Cleanup
        impl.setRevocationCheckEnabled(true);
    }

    @Test
    public void testClearCache() {
        // Act - should not throw
        statusListService.clearCache();

        // Assert - service still works after cache clear
        Assert.assertTrue(statusListService.isRevocationCheckEnabled());
    }

    @Test
    public void testRevocationCheckResultFactoryMethods() {
        // Test factory methods for RevocationCheckResult
        RevocationCheckResult valid = RevocationCheckResult.valid("Test credential");
        Assert.assertEquals(valid.getStatus(), RevocationCheckResult.Status.VALID);

        RevocationCheckResult revoked = RevocationCheckResult.revoked("Revoked reason");
        Assert.assertEquals(revoked.getStatus(), RevocationCheckResult.Status.REVOKED);

        RevocationCheckResult suspended = RevocationCheckResult.suspended("Suspended reason");
        Assert.assertEquals(suspended.getStatus(), RevocationCheckResult.Status.SUSPENDED);

        RevocationCheckResult unknown = RevocationCheckResult.unknown("Unknown reason");
        Assert.assertEquals(unknown.getStatus(), RevocationCheckResult.Status.UNKNOWN);

        RevocationCheckResult skipped = RevocationCheckResult.skipped("Skipped reason");
        Assert.assertEquals(skipped.getStatus(), RevocationCheckResult.Status.SKIPPED);
    }

    @Test
    public void testBitstringStatusListType() throws RevocationCheckException {
        // Arrange
        VerifiableCredential.CredentialStatus credentialStatus = new VerifiableCredential.CredentialStatus();
        credentialStatus.setType("BitstringStatusListEntry");
        credentialStatus.setStatusListCredential(null); // Will cause unknown due to missing URL
        credentialStatus.setStatusListIndex("42");

        // Act
        RevocationCheckResult result = statusListService.checkRevocationStatus(credentialStatus);

        // Assert - Should recognize the type but return unknown due to missing URL
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getStatus(), RevocationCheckResult.Status.UNKNOWN);
    }
}
