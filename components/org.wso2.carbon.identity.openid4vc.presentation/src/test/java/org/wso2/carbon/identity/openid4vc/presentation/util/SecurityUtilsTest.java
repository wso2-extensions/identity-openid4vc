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

package org.wso2.carbon.identity.openid4vc.presentation.util;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Unit tests for SecurityUtils.
 */
public class SecurityUtilsTest {

    @Test
    public void testGenerateNonce() {
        String nonce1 = SecurityUtils.generateNonce();
        String nonce2 = SecurityUtils.generateNonce();

        Assert.assertNotNull(nonce1);
        Assert.assertNotNull(nonce2);
        Assert.assertNotEquals(nonce1, nonce2, "Nonces should be unique");
        Assert.assertTrue(nonce1.length() > 20, "Nonce should be sufficiently long");
    }

    @Test
    public void testGenerateState() {
        String state1 = SecurityUtils.generateState();
        String state2 = SecurityUtils.generateState();

        Assert.assertNotNull(state1);
        Assert.assertNotNull(state2);
        Assert.assertNotEquals(state1, state2, "States should be unique");
    }

    @Test
    public void testIsValidDID() {
        Assert.assertTrue(SecurityUtils.isValidDID("did:web:example.com"));
        Assert.assertTrue(SecurityUtils.isValidDID("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"));
        Assert.assertTrue(SecurityUtils.isValidDID("did:jwk:eyJrdHkiOiJFQyJ9"));

        Assert.assertFalse(SecurityUtils.isValidDID(null));
        Assert.assertFalse(SecurityUtils.isValidDID(""));
        Assert.assertFalse(SecurityUtils.isValidDID("not-a-did"));
        Assert.assertFalse(SecurityUtils.isValidDID("did:"));
        Assert.assertFalse(SecurityUtils.isValidDID("did:web:"));
    }

    @Test
    public void testIsValidUrl() {
        Assert.assertTrue(SecurityUtils.isValidUrl("https://example.com"));
        Assert.assertTrue(SecurityUtils.isValidUrl("https://example.com/path"));
        Assert.assertTrue(SecurityUtils.isValidUrl("https://example.com:8443/path"));
        Assert.assertTrue(SecurityUtils.isValidUrl("http://localhost:8080"));

        Assert.assertFalse(SecurityUtils.isValidUrl(null));
        Assert.assertFalse(SecurityUtils.isValidUrl(""));
        Assert.assertFalse(SecurityUtils.isValidUrl("not-a-url"));
        Assert.assertFalse(SecurityUtils.isValidUrl("ftp://example.com"));
    }

    @Test
    public void testIsValidNonce() {
        Assert.assertTrue(SecurityUtils.isValidNonce("abc123"));
        Assert.assertTrue(SecurityUtils.isValidNonce("test_nonce-123"));
        Assert.assertTrue(SecurityUtils.isValidNonce(SecurityUtils.generateNonce()));

        Assert.assertFalse(SecurityUtils.isValidNonce(null));
        Assert.assertFalse(SecurityUtils.isValidNonce(""));
        Assert.assertFalse(SecurityUtils.isValidNonce("nonce with spaces"));
        Assert.assertFalse(SecurityUtils.isValidNonce("nonce<script>"));
    }

    @Test
    public void testIsValidState() {
        Assert.assertTrue(SecurityUtils.isValidState("abc123"));
        Assert.assertTrue(SecurityUtils.isValidState("state_value-123"));

        Assert.assertFalse(SecurityUtils.isValidState(null));
        Assert.assertFalse(SecurityUtils.isValidState(""));
    }

    @Test
    public void testIsValidUUID() {
        Assert.assertTrue(SecurityUtils.isValidUUID("550e8400-e29b-41d4-a716-446655440000"));
        Assert.assertTrue(SecurityUtils.isValidUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"));

        Assert.assertFalse(SecurityUtils.isValidUUID(null));
        Assert.assertFalse(SecurityUtils.isValidUUID(""));
        Assert.assertFalse(SecurityUtils.isValidUUID("not-a-uuid"));
        Assert.assertFalse(SecurityUtils.isValidUUID("550e8400-e29b-41d4-a716")); // Too short
    }

    @Test
    public void testIsValidVPTokenSize() {
        Assert.assertTrue(SecurityUtils.isValidVPTokenSize("small token"));
        
        // Create a large token (but within limit)
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            sb.append("x".repeat(100));
        }
        Assert.assertTrue(SecurityUtils.isValidVPTokenSize(sb.toString()));

        Assert.assertFalse(SecurityUtils.isValidVPTokenSize(null));
        Assert.assertFalse(SecurityUtils.isValidVPTokenSize(""));
    }

    @Test
    public void testSanitizeForLogging() {
        Assert.assertEquals(SecurityUtils.sanitizeForLogging("short", 10), "[masked]");
        Assert.assertEquals(SecurityUtils.sanitizeForLogging("", 5), "[empty]");
        Assert.assertEquals(SecurityUtils.sanitizeForLogging(null, 5), "[empty]");

        String result = SecurityUtils.sanitizeForLogging("this is a longer string for testing", 4);
        Assert.assertTrue(result.startsWith("this"));
        Assert.assertTrue(result.endsWith("ting"));
        Assert.assertTrue(result.contains("..."));
    }

    @Test
    public void testSanitizeDIDForLogging() {
        String result = SecurityUtils.sanitizeDIDForLogging("did:web:verifier.example.com");
        Assert.assertTrue(result.startsWith("did:web:"));
        Assert.assertTrue(result.contains("..."));

        Assert.assertEquals(SecurityUtils.sanitizeDIDForLogging(""), "[empty]");
        Assert.assertEquals(SecurityUtils.sanitizeDIDForLogging(null), "[empty]");
    }

    @Test
    public void testIsSafeRedirectUri() {
        Assert.assertTrue(SecurityUtils.isSafeRedirectUri("https://example.com/callback"));
        Assert.assertTrue(SecurityUtils.isSafeRedirectUri("https://example.com:8443/callback"));
        Assert.assertTrue(SecurityUtils.isSafeRedirectUri("http://localhost:8080/callback"));
        Assert.assertTrue(SecurityUtils.isSafeRedirectUri("http://127.0.0.1:8080/callback"));

        Assert.assertFalse(SecurityUtils.isSafeRedirectUri(null));
        Assert.assertFalse(SecurityUtils.isSafeRedirectUri(""));
        Assert.assertFalse(SecurityUtils.isSafeRedirectUri("http://example.com/callback")); // Not HTTPS
        Assert.assertFalse(SecurityUtils.isSafeRedirectUri("https://example.com/callback#fragment"));
    }

    @Test
    public void testConstantTimeEquals() {
        Assert.assertTrue(SecurityUtils.constantTimeEquals("test", "test"));
        Assert.assertTrue(SecurityUtils.constantTimeEquals("", ""));
        Assert.assertTrue(SecurityUtils.constantTimeEquals(null, null));

        Assert.assertFalse(SecurityUtils.constantTimeEquals("test1", "test2"));
        Assert.assertFalse(SecurityUtils.constantTimeEquals("short", "longer"));
        Assert.assertFalse(SecurityUtils.constantTimeEquals("test", null));
        Assert.assertFalse(SecurityUtils.constantTimeEquals(null, "test"));
    }

    @Test
    public void testExtractDIDMethod() {
        Assert.assertEquals(SecurityUtils.extractDIDMethod("did:web:example.com"), "web");
        Assert.assertEquals(SecurityUtils.extractDIDMethod("did:key:z6Mk..."), "key");
        Assert.assertEquals(SecurityUtils.extractDIDMethod("did:jwk:eyJ..."), "jwk");

        Assert.assertNull(SecurityUtils.extractDIDMethod(null));
        Assert.assertNull(SecurityUtils.extractDIDMethod(""));
        Assert.assertNull(SecurityUtils.extractDIDMethod("not-a-did"));
        Assert.assertNull(SecurityUtils.extractDIDMethod("did:"));
    }

    @Test
    public void testIsWellFormedJWT() {
        // Valid JWT structure (header.payload.signature)
        Assert.assertTrue(SecurityUtils.isWellFormedJWT("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"));

        Assert.assertFalse(SecurityUtils.isWellFormedJWT(null));
        Assert.assertFalse(SecurityUtils.isWellFormedJWT(""));
        Assert.assertFalse(SecurityUtils.isWellFormedJWT("not-a-jwt"));
        Assert.assertFalse(SecurityUtils.isWellFormedJWT("only.two."));
        Assert.assertFalse(SecurityUtils.isWellFormedJWT("header..signature"));
    }

    @Test
    public void testSha256() {
        String hash1 = SecurityUtils.sha256("test");
        String hash2 = SecurityUtils.sha256("test");
        String hash3 = SecurityUtils.sha256("different");

        Assert.assertNotNull(hash1);
        Assert.assertEquals(hash1, hash2, "Same input should produce same hash");
        Assert.assertNotEquals(hash1, hash3, "Different inputs should produce different hashes");
        Assert.assertEquals(hash1.length(), 64, "SHA-256 hex output should be 64 characters");
    }

    @Test
    public void testGenerateChallenge() {
        String challenge1 = SecurityUtils.generateChallenge();
        String challenge2 = SecurityUtils.generateChallenge();

        Assert.assertNotNull(challenge1);
        Assert.assertNotNull(challenge2);
        Assert.assertNotEquals(challenge1, challenge2, "Challenges should be unique");
        Assert.assertEquals(challenge1.length(), 43, "Challenge should be 43 characters");
    }
}
