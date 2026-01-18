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

import com.google.gson.Gson;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages cryptographic keys for DID documents.
 * Generates and caches keys per tenant for DID operations.
 */
public class DIDKeyManager {

    private static final Log LOG = LogFactory.getLog(DIDKeyManager.class);
    private static final Gson GSON = new Gson();

    // Cache for tenant keys: tenantId -> KeyPair
    private static final Map<Integer, KeyPair> keyCache = new ConcurrentHashMap<>();

    /**
     * Get or generate a key pair for the given tenant.
     * Uses ES256 (P-256) by default.
     * 
     * @param tenantId The tenant ID
     * @return KeyPair for the tenant
     * @throws Exception if key generation fails
     */
    public static KeyPair getOrGenerateKeyPair(int tenantId) throws Exception {
        if (keyCache.containsKey(tenantId)) {
            LOG.debug("Using cached key pair for tenant: " + tenantId);
            return keyCache.get(tenantId);
        }

        LOG.info("Generating new key pair for tenant: " + tenantId);
        KeyPair keyPair = generateES256KeyPair();
        keyCache.put(tenantId, keyPair);
        return keyPair;
    }

    /**
     * Generate a new ES256 (P-256) key pair.
     * 
     * @return KeyPair
     * @throws Exception if generation fails
     */
    private static KeyPair generateES256KeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1"); // P-256
        keyGen.initialize(ecSpec);
        return keyGen.generateKeyPair();
    }

    /**
     * Generate a new RSA key pair (2048-bit).
     * 
     * @return KeyPair
     * @throws Exception if generation fails
     */
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    /**
     * Convert a public key to JWK format as a Map.
     * 
     * @param keyPair The key pair containing the public key
     * @param keyId The key ID (e.g., "key-1")
     * @return JWK as Map
     */
    public static Map<String, Object> publicKeyToJWK(KeyPair keyPair, String keyId) {
        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "EC");
        jwk.put("kid", keyId);
        jwk.put("use", "sig");

        if (keyPair.getPublic() instanceof ECPublicKey) {
            ECPublicKey ecKey = (ECPublicKey) keyPair.getPublic();
            
            // Determine curve
            int fieldSize = ecKey.getParams().getCurve().getField().getFieldSize();
            String crv;
            if (fieldSize == 256) {
                crv = "P-256";
            } else if (fieldSize == 384) {
                crv = "P-384";
            } else if (fieldSize == 521) {
                crv = "P-521";
            } else {
                crv = "P-256"; // default
            }
            jwk.put("crv", crv);

            // Get x and y coordinates
            byte[] x = ecKey.getW().getAffineX().toByteArray();
            byte[] y = ecKey.getW().getAffineY().toByteArray();

            // Ensure 32 bytes for P-256 (remove sign byte if present)
            x = ensureLength(x, 32);
            y = ensureLength(y, 32);

            jwk.put("x", base64UrlEncode(x));
            jwk.put("y", base64UrlEncode(y));

        } else if (keyPair.getPublic() instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) keyPair.getPublic();
            jwk.put("kty", "RSA");
            jwk.put("n", base64UrlEncode(rsaKey.getModulus().toByteArray()));
            jwk.put("e", base64UrlEncode(rsaKey.getPublicExponent().toByteArray()));
        }

        return jwk;
    }

    /**
     * Convert JWK Map to JSON string.
     * 
     * @param jwk JWK as Map
     * @return JSON string
     */
    public static String jwkToJson(Map<String, Object> jwk) {
        return GSON.toJson(jwk);
    }

    /**
     * Ensure byte array is exactly the specified length.
     * Removes leading zero bytes or pads with zeros as needed.
     * 
     * @param bytes Input byte array
     * @param length Desired length
     * @return Adjusted byte array
     */
    private static byte[] ensureLength(byte[] bytes, int length) {
        if (bytes.length == length) {
            return bytes;
        } else if (bytes.length > length) {
            // Remove leading zeros (sign bytes)
            int start = bytes.length - length;
            byte[] result = new byte[length];
            System.arraycopy(bytes, start, result, 0, length);
            return result;
        } else {
            // Pad with leading zeros
            byte[] result = new byte[length];
            int start = length - bytes.length;
            System.arraycopy(bytes, 0, result, start, bytes.length);
            return result;
        }
    }

    /**
     * Base64 URL encode without padding.
     * 
     * @param data Byte array to encode
     * @return Base64 URL encoded string
     */
    private static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Regenerate keys for a tenant.
     * 
     * @param tenantId The tenant ID
     * @return New KeyPair
     * @throws Exception if generation fails
     */
    public static KeyPair regenerateKeyPair(int tenantId) throws Exception {
        LOG.info("Regenerating key pair for tenant: " + tenantId);
        KeyPair keyPair = generateES256KeyPair();
        keyCache.put(tenantId, keyPair);
        return keyPair;
    }

    /**
     * Check if keys exist for the tenant.
     * 
     * @param tenantId The tenant ID
     * @return true if keys exist
     */
    public static boolean hasKeys(int tenantId) {
        return keyCache.containsKey(tenantId);
    }

    /**
     * Remove keys for a tenant.
     * 
     * @param tenantId The tenant ID
     */
    public static void removeKeys(int tenantId) {
        keyCache.remove(tenantId);
        LOG.info("Removed keys for tenant: " + tenantId);
    }
}
