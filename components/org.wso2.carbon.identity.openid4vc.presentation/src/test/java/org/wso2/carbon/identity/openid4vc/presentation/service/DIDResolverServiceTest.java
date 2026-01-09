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
import org.wso2.carbon.identity.openid4vc.presentation.exception.DIDResolutionException;
import org.wso2.carbon.identity.openid4vc.presentation.model.DIDDocument;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.DIDResolverServiceImpl;

import java.security.PublicKey;

/**
 * Unit tests for DIDResolverService.
 */
public class DIDResolverServiceTest {

    private DIDResolverService didResolverService;

    @BeforeMethod
    public void setUp() {
        didResolverService = new DIDResolverServiceImpl();
    }

    @Test
    public void testResolveDidJwk() throws DIDResolutionException {
        // Arrange - did:jwk with EC P-256 key
        // Base64url encoded JWK: {"kty":"EC","crv":"P-256","x":"...","y":"..."}
        String jwkBase64 = "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InVVZmRnMlpfX0FfVFdoTTl3VnFmaUNXUDl5UXp3a0I0SExWTzhYNl9HUjQiLCJ5IjoiX1BzSXczbW5SNm5WS3hyd0FEYXYySnRlVTBQVzA4cnpFQ3c0YzNtODdOQSJ9";
        String didJwk = "did:jwk:" + jwkBase64;

        // Act
        DIDDocument didDoc = didResolverService.resolve(didJwk);

        // Assert
        Assert.assertNotNull(didDoc);
        Assert.assertEquals(didDoc.getId(), didJwk);
        Assert.assertNotNull(didDoc.getVerificationMethod());
        Assert.assertFalse(didDoc.getVerificationMethod().isEmpty());
    }

    @Test
    public void testGetPublicKeyFromDidJwk() throws DIDResolutionException {
        // Arrange - did:jwk with EC P-256 key
        String jwkBase64 = "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InVVZmRnMlpfX0FfVFdoTTl3VnFmaUNXUDl5UXp3a0I0SExWTzhYNl9HUjQiLCJ5IjoiX1BzSXczbW5SNm5WS3hyd0FEYXYySnRlVTBQVzA4cnpFQ3c0YzNtODdOQSJ9";
        String didJwk = "did:jwk:" + jwkBase64;

        // Act
        PublicKey publicKey = didResolverService.getPublicKey(didJwk, null);

        // Assert
        Assert.assertNotNull(publicKey);
        Assert.assertEquals(publicKey.getAlgorithm(), "EC");
    }

    @Test
    public void testResolveDidKey() throws DIDResolutionException {
        // Arrange - did:key with Ed25519 public key (multibase encoded)
        // This is a z prefix multibase with ed25519-pub multicodec (0xed01)
        String didKey = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        // Act
        DIDDocument didDoc = didResolverService.resolve(didKey);

        // Assert
        Assert.assertNotNull(didDoc);
        Assert.assertEquals(didDoc.getId(), didKey);
        Assert.assertNotNull(didDoc.getVerificationMethod());
    }

    @Test(expectedExceptions = DIDResolutionException.class)
    public void testResolveUnsupportedDIDMethod() throws DIDResolutionException {
        // Arrange
        String unsupportedDid = "did:unsupported:abc123";

        // Act - should throw exception
        didResolverService.resolve(unsupportedDid);
    }

    @Test(expectedExceptions = DIDResolutionException.class)
    public void testResolveInvalidDID() throws DIDResolutionException {
        // Arrange
        String invalidDid = "not-a-did";

        // Act - should throw exception
        didResolverService.resolve(invalidDid);
    }

    @Test(expectedExceptions = DIDResolutionException.class)
    public void testResolveNullDID() throws DIDResolutionException {
        // Act - should throw exception
        didResolverService.resolve(null);
    }

    @Test
    public void testIsSupportedMethod() {
        // Assert
        Assert.assertTrue(didResolverService.isSupported("did:jwk:abc"));
        Assert.assertTrue(didResolverService.isSupported("did:key:z6Mk"));
        Assert.assertTrue(didResolverService.isSupported("did:web:example.com"));
        Assert.assertFalse(didResolverService.isSupported("did:unsupported:xyz"));
        Assert.assertFalse(didResolverService.isSupported("not-a-did"));
    }

    @Test
    public void testCachingBehavior() throws DIDResolutionException {
        // Arrange
        String jwkBase64 = "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InVVZmRnMlpfX0FfVFdoTTl3VnFmaUNXUDl5UXp3a0I0SExWTzhYNl9HUjQiLCJ5IjoiX1BzSXczbW5SNm5WS3hyd0FEYXYySnRlVTBQVzA4cnpFQ3c0YzNtODdOQSJ9";
        String didJwk = "did:jwk:" + jwkBase64;

        // Act - Resolve twice
        DIDDocument doc1 = didResolverService.resolve(didJwk);
        DIDDocument doc2 = didResolverService.resolve(didJwk);

        // Assert - Both should be valid (caching implementation detail)
        Assert.assertNotNull(doc1);
        Assert.assertNotNull(doc2);
        Assert.assertEquals(doc1.getId(), doc2.getId());
    }

    @Test
    public void testExtractDIDMethod() {
        // Test internal method behavior via public interface
        String didWeb = "did:web:example.com";
        String didJwk = "did:jwk:eyJrdHkiOiJFQyJ9";
        String didKey = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        Assert.assertTrue(didResolverService.isSupported(didWeb));
        Assert.assertTrue(didResolverService.isSupported(didJwk));
        Assert.assertTrue(didResolverService.isSupported(didKey));
    }
}
