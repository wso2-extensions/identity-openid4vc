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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages cryptographic keys for DID documents.
 * Generates and caches keys per tenant for DID operations.
 */
public class DIDKeyManager {

    private static final Log LOG = LogFactory.getLog(DIDKeyManager.class);
    private static final ConcurrentHashMap<Integer, KeyPair> keyCache = new ConcurrentHashMap<>();

    /**
     * Get or generate a key pair for the given tenant.
     * Uses Ed25519 by default.
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
        KeyPair keyPair = generateEd25519KeyPair();
        keyCache.put(tenantId, keyPair);
        return keyPair;
    }

    /**
     * Generate a new Ed25519 key pair.
     * 
     * @return KeyPair
     * @throws Exception if generation fails
     */
    private static KeyPair generateEd25519KeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519");
        return keyGen.generateKeyPair();
    }

    /**
     * Convert Ed25519 public key to multibase format.
     * Format: z + base58btc(0xed01 + public key bytes)
     * 
     * @param keyPair The key pair containing the Ed25519 public key
     * @return Multibase encoded string (z-prefix for base58btc)
     */
    public static String publicKeyToMultibase(KeyPair keyPair) {
        try {
            byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
            
            // For Ed25519, extract the 32-byte raw public key from X.509 encoding
            // X.509 format: algorithm identifier (12 bytes) + raw key (32 bytes)
            byte[] rawKey = new byte[32];
            System.arraycopy(publicKeyBytes, publicKeyBytes.length - 32, rawKey, 0, 32);
            
            // Prepend multicodec prefix for Ed25519-pub (0xed01)
            byte[] multicodecKey = new byte[34];
            multicodecKey[0] = (byte) 0xed;
            multicodecKey[1] = (byte) 0x01;
            System.arraycopy(rawKey, 0, multicodecKey, 2, 32);
            
            // Base58 encode and prepend 'z' for base58btc multibase
            return "z" + base58Encode(multicodecKey);
        } catch (Exception e) {
            LOG.error("Failed to convert public key to multibase", e);
            return null;
        }
    }

    /**
     * Base58 encode (Bitcoin alphabet).
     * 
     * @param input Byte array to encode
     * @return Base58 encoded string
     */
    private static String base58Encode(byte[] input) {
        String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        if (input.length == 0) {
            return "";
        }

        // Convert to base58
        byte[] inputCopy = new byte[input.length];
        System.arraycopy(input, 0, inputCopy, 0, input.length);
        
        // Count leading zeros
        int zeros = 0;
        while (zeros < inputCopy.length && inputCopy[zeros] == 0) {
            zeros++;
        }

        // Convert to base58
        byte[] encoded = new byte[inputCopy.length * 2];
        int outputStart = encoded.length;
        for (int inputStart = zeros; inputStart < inputCopy.length; ) {
            encoded[--outputStart] = (byte) ALPHABET.charAt(divmod(inputCopy, inputStart, 256, 58));
            if (inputCopy[inputStart] == 0) {
                inputStart++;
            }
        }

        // Skip leading zeros in encoded result
        while (outputStart < encoded.length && encoded[outputStart] == (byte) ALPHABET.charAt(0)) {
            outputStart++;
        }

        // Add original leading zeros
        while (--zeros >= 0) {
            encoded[--outputStart] = (byte) ALPHABET.charAt(0);
        }

        return new String(encoded, outputStart, encoded.length - outputStart);
    }

    private static byte divmod(byte[] number, int firstDigit, int base, int divisor) {
        int remainder = 0;
        for (int i = firstDigit; i < number.length; i++) {
            int digit = (int) number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return (byte) remainder;
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
        KeyPair keyPair = generateEd25519KeyPair();
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
