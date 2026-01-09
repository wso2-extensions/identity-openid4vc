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
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.TrustedVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.TrustedVerifierServiceImpl;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Unit tests for TrustedVerifierService.
 */
public class TrustedVerifierServiceTest {

    private TrustedVerifierService trustedVerifierService;
    private static final String TENANT_DOMAIN = "carbon.super";

    @BeforeMethod
    public void setUp() {
        trustedVerifierService = new TrustedVerifierServiceImpl();
    }

    @Test
    public void testAddTrustedVerifier() throws VPException {
        // Arrange
        TrustedVerifier verifier = new TrustedVerifier.Builder()
                .did("did:web:verifier.example.com")
                .name("Test Verifier")
                .organizationName("Test Org")
                .build();

        // Act
        TrustedVerifier added = trustedVerifierService.addTrustedVerifier(verifier, TENANT_DOMAIN);

        // Assert
        Assert.assertNotNull(added);
        Assert.assertNotNull(added.getId());
        Assert.assertEquals(added.getDid(), "did:web:verifier.example.com");
        Assert.assertEquals(added.getName(), "Test Verifier");
        Assert.assertNotNull(added.getCreatedAt());
    }

    @Test
    public void testGetTrustedVerifierByDid() throws VPException {
        // Arrange
        String did = "did:web:verifier2.example.com";
        TrustedVerifier verifier = new TrustedVerifier.Builder()
                .did(did)
                .name("Verifier 2")
                .build();
        trustedVerifierService.addTrustedVerifier(verifier, TENANT_DOMAIN);

        // Act
        Optional<TrustedVerifier> retrieved = trustedVerifierService.getTrustedVerifier(did, TENANT_DOMAIN);

        // Assert
        Assert.assertTrue(retrieved.isPresent());
        Assert.assertEquals(retrieved.get().getDid(), did);
    }

    @Test
    public void testGetTrustedVerifierByClientId() throws VPException {
        // Arrange
        String clientId = "client-123";
        TrustedVerifier verifier = new TrustedVerifier.Builder()
                .clientId(clientId)
                .name("Client Verifier")
                .build();
        trustedVerifierService.addTrustedVerifier(verifier, TENANT_DOMAIN);

        // Act
        Optional<TrustedVerifier> retrieved = trustedVerifierService.getTrustedVerifierByClientId(
                clientId, TENANT_DOMAIN);

        // Assert
        Assert.assertTrue(retrieved.isPresent());
        Assert.assertEquals(retrieved.get().getClientId(), clientId);
    }

    @Test
    public void testGetTrustedVerifierNotFound() {
        // Act
        Optional<TrustedVerifier> retrieved = trustedVerifierService.getTrustedVerifier(
                "did:web:nonexistent.example.com", TENANT_DOMAIN);

        // Assert
        Assert.assertFalse(retrieved.isPresent());
    }

    @Test
    public void testIsVerifierTrustedWhenStrictModeDisabled() {
        // Arrange - strict mode disabled by default
        String did = "did:web:unknown.example.com";

        // Act
        boolean trusted = trustedVerifierService.isVerifierTrusted(did, TENANT_DOMAIN);

        // Assert - should be trusted when strict mode is disabled
        Assert.assertTrue(trusted);
    }

    @Test
    public void testIsVerifierTrustedWhenStrictModeEnabled() throws VPException {
        // Arrange
        TrustedVerifierServiceImpl impl = (TrustedVerifierServiceImpl) trustedVerifierService;
        impl.setStrictVerificationEnabled(TENANT_DOMAIN, true);

        String trustedDid = "did:web:trusted.example.com";
        String untrustedDid = "did:web:untrusted.example.com";

        TrustedVerifier verifier = new TrustedVerifier.Builder()
                .did(trustedDid)
                .name("Trusted Verifier")
                .status(TrustedVerifier.VerifierStatus.ACTIVE)
                .build();
        trustedVerifierService.addTrustedVerifier(verifier, TENANT_DOMAIN);

        // Act & Assert
        Assert.assertTrue(trustedVerifierService.isVerifierTrusted(trustedDid, TENANT_DOMAIN));
        Assert.assertFalse(trustedVerifierService.isVerifierTrusted(untrustedDid, TENANT_DOMAIN));
    }

    @Test
    public void testIsVerifierTrustedWithInactiveStatus() throws VPException {
        // Arrange
        TrustedVerifierServiceImpl impl = (TrustedVerifierServiceImpl) trustedVerifierService;
        impl.setStrictVerificationEnabled(TENANT_DOMAIN, true);

        String did = "did:web:suspended.example.com";
        TrustedVerifier verifier = new TrustedVerifier.Builder()
                .did(did)
                .name("Suspended Verifier")
                .status(TrustedVerifier.VerifierStatus.SUSPENDED)
                .build();
        trustedVerifierService.addTrustedVerifier(verifier, TENANT_DOMAIN);

        // Act
        boolean trusted = trustedVerifierService.isVerifierTrusted(did, TENANT_DOMAIN);

        // Assert - suspended verifier should not be trusted
        Assert.assertFalse(trusted);
    }

    @Test
    public void testGetAllTrustedVerifiers() throws VPException {
        // Arrange
        trustedVerifierService.addTrustedVerifier(
                new TrustedVerifier.Builder().did("did:web:v1.example.com").name("V1").build(),
                TENANT_DOMAIN);
        trustedVerifierService.addTrustedVerifier(
                new TrustedVerifier.Builder().did("did:web:v2.example.com").name("V2").build(),
                TENANT_DOMAIN);

        // Act
        List<TrustedVerifier> verifiers = trustedVerifierService.getTrustedVerifiers(TENANT_DOMAIN);

        // Assert
        Assert.assertNotNull(verifiers);
        Assert.assertTrue(verifiers.size() >= 2);
    }

    @Test
    public void testUpdateTrustedVerifier() throws VPException {
        // Arrange
        TrustedVerifier original = new TrustedVerifier.Builder()
                .did("did:web:update.example.com")
                .name("Original Name")
                .build();
        TrustedVerifier added = trustedVerifierService.addTrustedVerifier(original, TENANT_DOMAIN);

        TrustedVerifier updated = new TrustedVerifier.Builder()
                .did("did:web:update.example.com")
                .name("Updated Name")
                .description("Added description")
                .build();

        // Act
        TrustedVerifier result = trustedVerifierService.updateTrustedVerifier(
                added.getId(), updated, TENANT_DOMAIN);

        // Assert
        Assert.assertEquals(result.getName(), "Updated Name");
        Assert.assertEquals(result.getDescription(), "Added description");
        Assert.assertEquals(result.getId(), added.getId()); // ID should be preserved
    }

    @Test(expectedExceptions = VPException.class)
    public void testUpdateNonExistentVerifier() throws VPException {
        // Arrange
        TrustedVerifier verifier = new TrustedVerifier.Builder()
                .did("did:web:nonexistent.example.com")
                .name("Test")
                .build();

        // Act - should throw exception
        trustedVerifierService.updateTrustedVerifier("nonexistent-id", verifier, TENANT_DOMAIN);
    }

    @Test
    public void testRemoveTrustedVerifier() throws VPException {
        // Arrange
        TrustedVerifier verifier = new TrustedVerifier.Builder()
                .did("did:web:toremove.example.com")
                .name("To Remove")
                .build();
        TrustedVerifier added = trustedVerifierService.addTrustedVerifier(verifier, TENANT_DOMAIN);

        // Act
        trustedVerifierService.removeTrustedVerifier(added.getId(), TENANT_DOMAIN);

        // Assert
        Optional<TrustedVerifier> retrieved = trustedVerifierService.getTrustedVerifier(
                "did:web:toremove.example.com", TENANT_DOMAIN);
        Assert.assertFalse(retrieved.isPresent());
    }

    @Test
    public void testValidateVerifierRequest() throws VPException {
        // Arrange
        TrustedVerifierServiceImpl impl = (TrustedVerifierServiceImpl) trustedVerifierService;
        impl.setStrictVerificationEnabled(TENANT_DOMAIN, true);

        String did = "did:web:validate.example.com";
        TrustedVerifier verifier = new TrustedVerifier.Builder()
                .did(did)
                .name("Validator")
                .allowedCredentialTypes(Arrays.asList("IdentityCredential", "AgeCredential"))
                .status(TrustedVerifier.VerifierStatus.ACTIVE)
                .build();
        trustedVerifierService.addTrustedVerifier(verifier, TENANT_DOMAIN);

        // Act & Assert
        Assert.assertTrue(trustedVerifierService.validateVerifierRequest(
                did, Arrays.asList("IdentityCredential"), TENANT_DOMAIN));
        Assert.assertTrue(trustedVerifierService.validateVerifierRequest(
                did, Arrays.asList("AgeCredential"), TENANT_DOMAIN));
        Assert.assertFalse(trustedVerifierService.validateVerifierRequest(
                did, Arrays.asList("UnallowedCredential"), TENANT_DOMAIN));
    }

    @Test
    public void testValidateRedirectUri() throws VPException {
        // Arrange
        TrustedVerifierServiceImpl impl = (TrustedVerifierServiceImpl) trustedVerifierService;
        impl.setRedirectUriValidationMode(TENANT_DOMAIN, 
                TrustedVerifierService.RedirectUriValidationMode.STRICT);

        String did = "did:web:redirect.example.com";
        TrustedVerifier verifier = new TrustedVerifier.Builder()
                .did(did)
                .name("Redirect Validator")
                .allowedRedirectUris(Arrays.asList(
                        "https://app.example.com/callback",
                        "https://app.example.com/auth"))
                .build();
        trustedVerifierService.addTrustedVerifier(verifier, TENANT_DOMAIN);

        // Act & Assert
        Assert.assertTrue(trustedVerifierService.validateRedirectUri(
                did, "https://app.example.com/callback", TENANT_DOMAIN));
        Assert.assertFalse(trustedVerifierService.validateRedirectUri(
                did, "https://malicious.example.com/callback", TENANT_DOMAIN));
    }

    @Test
    public void testRedirectUriValidationDisabled() {
        // Arrange
        TrustedVerifierServiceImpl impl = (TrustedVerifierServiceImpl) trustedVerifierService;
        impl.setRedirectUriValidationMode(TENANT_DOMAIN, 
                TrustedVerifierService.RedirectUriValidationMode.DISABLED);

        // Act & Assert - any redirect URI should be valid
        Assert.assertTrue(trustedVerifierService.validateRedirectUri(
                "did:web:any.example.com", "https://any.example.com/callback", TENANT_DOMAIN));
    }

    @Test(expectedExceptions = VPException.class)
    public void testAddVerifierWithoutDidOrClientId() throws VPException {
        // Arrange
        TrustedVerifier verifier = new TrustedVerifier.Builder()
                .name("Invalid Verifier")
                // No DID or clientId
                .build();

        // Act - should throw exception
        trustedVerifierService.addTrustedVerifier(verifier, TENANT_DOMAIN);
    }

    @Test(expectedExceptions = VPException.class)
    public void testAddVerifierWithoutName() throws VPException {
        // Arrange
        TrustedVerifier verifier = new TrustedVerifier.Builder()
                .did("did:web:noname.example.com")
                // No name
                .build();

        // Act - should throw exception
        trustedVerifierService.addTrustedVerifier(verifier, TENANT_DOMAIN);
    }

    @Test
    public void testVerifierWithExpiration() throws VPException {
        // Arrange
        TrustedVerifierServiceImpl impl = (TrustedVerifierServiceImpl) trustedVerifierService;
        impl.setStrictVerificationEnabled(TENANT_DOMAIN, true);

        String did = "did:web:expired.example.com";
        TrustedVerifier verifier = new TrustedVerifier.Builder()
                .did(did)
                .name("Expired Verifier")
                .status(TrustedVerifier.VerifierStatus.ACTIVE)
                .expiresAt(Instant.now().minusSeconds(3600)) // Expired 1 hour ago
                .build();
        trustedVerifierService.addTrustedVerifier(verifier, TENANT_DOMAIN);

        // Act
        boolean trusted = trustedVerifierService.isVerifierTrusted(did, TENANT_DOMAIN);

        // Assert - expired verifier should not be trusted
        Assert.assertFalse(trusted);
    }
}
