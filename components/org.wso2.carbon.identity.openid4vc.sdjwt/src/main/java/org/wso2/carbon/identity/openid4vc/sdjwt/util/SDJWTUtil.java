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

import com.sun.tools.javac.util.StringUtils;
import org.wso2.carbon.identity.openid4vc.sdjwt.constant.SDJWTConstants;
import org.wso2.carbon.identity.openid4vc.sdjwt.exception.SDJWTException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility class for SD-JWT operations.
 */
public final class SDJWTUtil {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private SDJWTUtil() {
        // Private constructor to prevent instantiation
    }

    /**
     * Generate a cryptographically secure random salt.
     * The salt is 128 bits (16 bytes) as recommended by the SD-JWT specification
     * and is returned as a base64url-encoded string without padding.
     *
     * @return Base64url-encoded salt string
     */
    public static String generateSalt() {

        byte[] saltBytes = new byte[SDJWTConstants.DEFAULT_SALT_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(saltBytes);
        return base64UrlEncode(saltBytes);
    }

    /**
     * Compute hash of the given data using the specified algorithm.
     *
     * @param data      Data to hash
     * @param algorithm Hash algorithm (e.g., "sha-256")
     * @return Hash bytes
     * @throws SDJWTException If the algorithm is not supported
     */
    public static byte[] hash(byte[] data, String algorithm) throws SDJWTException {

        try {
            String javaAlgorithm = toJavaAlgorithm(algorithm);
            MessageDigest digest = MessageDigest.getInstance(javaAlgorithm);
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new SDJWTException("Unsupported hash algorithm: " + algorithm, e);
        }
    }

    /**
     * Compute hash and return as base64url-encoded string.
     *
     * @param data      Data to hash
     * @param algorithm Hash algorithm
     * @return Base64url-encoded hash
     * @throws SDJWTException If the algorithm is not supported
     */
    public static String hashAndEncode(byte[] data, String algorithm) throws SDJWTException {

        return base64UrlEncode(hash(data, algorithm));
    }

    /**
     * Compute hash of a string using its US-ASCII bytes and return as base64url-encoded string.
     *
     * @param input     String to hash
     * @param algorithm Hash algorithm
     * @return Base64url-encoded hash
     * @throws SDJWTException If the algorithm is not supported
     */
    public static String hashAndEncode(String input, String algorithm) throws SDJWTException {

        return hashAndEncode(input.getBytes(StandardCharsets.US_ASCII), algorithm);
    }

    /**
     * Convert IANA hash algorithm name to Java MessageDigest algorithm name.
     *
     * @param ianaAlgorithm IANA algorithm name (e.g., "sha-256")
     * @return Java algorithm name (e.g., "SHA-256")
     * @throws SDJWTException If the algorithm is unknown
     */
    public static String toJavaAlgorithm(String ianaAlgorithm) throws SDJWTException {

        if (ianaAlgorithm == null) {
            throw new SDJWTException("Hash algorithm cannot be null");
        }

        switch (StringUtils.toLowerCase(ianaAlgorithm)) {
            case SDJWTConstants.HASH_ALG_SHA256:
                return "SHA-256";
            case SDJWTConstants.HASH_ALG_SHA384:
                return "SHA-384";
            case SDJWTConstants.HASH_ALG_SHA512:
                return "SHA-512";
            default:
                throw new SDJWTException("Unknown hash algorithm: " + ianaAlgorithm);
        }
    }

    /**
     * Base64url encode data without padding.
     *
     * @param data Data to encode
     * @return Base64url-encoded string without padding
     */
    public static String base64UrlEncode(byte[] data) {

        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Base64url encode a string using UTF-8 encoding.
     *
     * @param input String to encode
     * @return Base64url-encoded string without padding
     */
    public static String base64UrlEncode(String input) {

        return base64UrlEncode(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Base64url decode a string.
     *
     * @param encoded Base64url-encoded string
     * @return Decoded bytes
     */
    public static byte[] base64UrlDecode(String encoded) {

        return Base64.getUrlDecoder().decode(encoded);
    }

    /**
     * Base64url decode a string and convert to UTF-8 string.
     *
     * @param encoded Base64url-encoded string
     * @return Decoded string
     */
    public static String base64UrlDecodeToString(String encoded) {

        return new String(base64UrlDecode(encoded), StandardCharsets.UTF_8);
    }
}
