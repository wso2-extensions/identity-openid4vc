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

package org.wso2.carbon.identity.openid4vc.sdjwt.util;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.sdjwt.constant.SDJWTConstants;
import org.wso2.carbon.identity.openid4vc.sdjwt.exception.SDJWTException;

import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

/**
 * Test class for SDJWTUtil.
 * Tests utility methods for SD-JWT operations.
 */
public class SDJWTUtilTest {

    private static final String TEST_STRING = "Hello, World!";

    @Test(priority = 1, description = "Test salt generation")
    public void testGenerateSalt() {
        String salt = SDJWTUtil.generateSalt();

        Assert.assertNotNull(salt);
        Assert.assertFalse(salt.contains("="), "Should not contain padding");

        // Verify 16 bytes (128 bits)
        byte[] saltBytes = Base64.getUrlDecoder().decode(salt);
        Assert.assertEquals(saltBytes.length, SDJWTConstants.DEFAULT_SALT_LENGTH_BYTES);
    }

    @Test(priority = 2, description = "Test multiple salts are unique")
    public void testSaltUniqueness() {
        Set<String> salts = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            salts.add(SDJWTUtil.generateSalt());
        }
        Assert.assertEquals(salts.size(), 100, "All salts should be unique");
    }

    @Test(priority = 3, description = "Test base64url encoding round-trip")
    public void testBase64UrlRoundTrip() {
        String encoded = SDJWTUtil.base64UrlEncode(TEST_STRING);
        String decoded = SDJWTUtil.base64UrlDecodeToString(encoded);

        Assert.assertEquals(decoded, TEST_STRING);
        Assert.assertFalse(encoded.contains("="), "Should not contain padding");
    }

    @Test(priority = 4, description = "Test SHA-256 hashing")
    public void testHashSHA256() throws SDJWTException {
        byte[] hash = SDJWTUtil.hash(TEST_STRING.getBytes(), SDJWTConstants.HASH_ALG_SHA256);

        Assert.assertNotNull(hash);
        Assert.assertEquals(hash.length, 32, "SHA-256 should produce 32 bytes");
    }

    @Test(priority = 5, description = "Test hash and encode")
    public void testHashAndEncode() throws SDJWTException {
        String digest = SDJWTUtil.hashAndEncode(TEST_STRING, SDJWTConstants.HASH_ALG_SHA256);

        Assert.assertNotNull(digest);
        Assert.assertFalse(digest.contains("="));
        Assert.assertFalse(digest.contains("+"));
        Assert.assertFalse(digest.contains("/"));
    }

    @Test(priority = 6, description = "Test IANA to Java algorithm mapping")
    public void testToJavaAlgorithm() throws SDJWTException {
        Assert.assertEquals(SDJWTUtil.toJavaAlgorithm("sha-256"), "SHA-256");
        Assert.assertEquals(SDJWTUtil.toJavaAlgorithm("sha-384"), "SHA-384");
        Assert.assertEquals(SDJWTUtil.toJavaAlgorithm("sha-512"), "SHA-512");
    }

    @Test(priority = 7, description = "Test unsupported hash algorithm",
            expectedExceptions = SDJWTException.class,
            expectedExceptionsMessageRegExp = ".*Unsupported hash algorithm.*")
    public void testUnsupportedAlgorithm() throws SDJWTException {
        SDJWTUtil.hash(TEST_STRING.getBytes(), "md5");
    }

    @Test(priority = 8, description = "Test null algorithm",
            expectedExceptions = SDJWTException.class,
            expectedExceptionsMessageRegExp = ".*Hash algorithm cannot be null.*")
    public void testNullAlgorithm() throws SDJWTException {
        SDJWTUtil.toJavaAlgorithm(null);
    }
}
