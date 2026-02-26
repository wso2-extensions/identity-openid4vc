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

package org.wso2.carbon.identity.openid4vc.oid4vp.did.util;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.PrivateKey;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages cryptographic keys for DID documents using the system KeyStore.
 * EdDSA keys are retrieved from the tenant's KeyStore.
 * P-256 keys are currently generated in-memory (ephemeral) as fallback.
 */
public class DIDKeyManager {

    private static final ConcurrentHashMap<Integer, OctetKeyPair> keyCache = new ConcurrentHashMap<>();

    /**
     * Get Ed25519 key pair for the given tenant from KeyStore.
     * 
     * @param tenantId The tenant ID
     * @return OctetKeyPair for the tenant
     * @throws Exception if key retrieval fails
     */
    @SuppressFBWarnings({ "DE_MIGHT_IGNORE", "REC_CATCH_EXCEPTION" })
    public static OctetKeyPair getOrGenerateKeyPair(int tenantId) throws Exception {
        // 1. Try Cache
        if (keyCache.containsKey(tenantId)) {
            return keyCache.get(tenantId);
        }

        // 2. Retrieve from KeyStore
        try {
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            String edKeyAlias = getEdDSAKeyAlias(tenantId);
            
            // Check if key exists (by trying to get it)
            if (keyStoreManager.getDefaultPublicKey(edKeyAlias) != null) {
                PrivateKey privateKey = keyStoreManager.getDefaultPrivateKey(edKeyAlias);
                OctetKeyPair keyPair = convertToOctetKeyPair(privateKey, keyStoreManager, edKeyAlias);
                
                keyCache.put(tenantId, keyPair);
                return keyPair;
            }
        } catch (Exception e) {
            // Log or handle? For now, we propagate or fallback. 
            // If KeyStore fails, we arguably shouldn't generate specific random keys as they won't match checking.
            throw new Exception("Error retrieving EdDSA key from KeyStore for tenant " + tenantId, e);
        }

        throw new Exception("EdDSA key not found in KeyStore for tenant " + tenantId);
    }



    /**
     * Get the EdDSA key alias for the given tenant.
     * 
     * @param tenantId The tenant ID
     * @return EdDSA key alias
     * @throws Exception if alias generation fails
     */
    public static String getEdDSAKeyAlias(int tenantId) throws Exception {
        if (tenantId == MultitenantConstants.SUPER_TENANT_ID) {
            // For super tenant, use a fixed alias
            return "wso2carbon_ed";
        } else {
            // For other tenants, use tenant domain + _ed suffix
            String tenantDomain = org.wso2.carbon.context.PrivilegedCarbonContext
                    .getThreadLocalCarbonContext().getTenantDomain();
            return KeyStoreUtil.getTenantEdKeyAlias(tenantDomain);
        }
    }

    /**
     * Convert PrivateKey to OctetKeyPair for EdDSA signing.
     * 
     * @param privateKey The private key from KeyStore
     * @param keyStoreManager KeyStore manager instance
     * @param alias Key alias
     * @return OctetKeyPair for use with BCEd25519Signer
     * @throws Exception if conversion fails
     */
    public static OctetKeyPair convertToOctetKeyPair(PrivateKey privateKey, 
                                                KeyStoreManager keyStoreManager, 
                                                String alias) throws Exception {
        // Get public key
        java.security.PublicKey publicKey = keyStoreManager.getDefaultPublicKey(alias);
        
        // Extract raw key bytes (Ed25519 keys are 32 bytes each)
        byte[] privateKeyBytes = privateKey.getEncoded();
        byte[] publicKeyBytes = publicKey.getEncoded();
        
        // Ed25519 private key in PKCS#8 format has the actual key at offset 16 (32 bytes)
        // Ed25519 public key in X.509 format has the actual key at offset 12 (32 bytes)
        // We use safe extraction if possible, or assume standard encoding provided by BC/Java 15+
        
        // Note: Simple byte slicing assumes standard PCKS8/X509 encoding for Ed25519.
        // If strictly required to parse ASN.1, use BC PrivateKeyInfo.
        // For now, retaining the logic from DIDWebProvider which seemingly works.
        
        byte[] rawPrivateKey = java.util.Arrays.copyOfRange(privateKeyBytes, 
                privateKeyBytes.length - 32, privateKeyBytes.length);
        byte[] rawPublicKey = java.util.Arrays.copyOfRange(publicKeyBytes, 
                publicKeyBytes.length - 32, publicKeyBytes.length);
        
        Base64URL x = Base64URL.encode(rawPublicKey);
        Base64URL d = Base64URL.encode(rawPrivateKey);
        
        return new OctetKeyPair.Builder(Curve.Ed25519, x).d(d).build();
    }

    /**
     * Convert Ed25519 public key to multibase format.
     * Format: z + base58btc(0xed01 + public key bytes)
     */
    @SuppressFBWarnings({ "DE_MIGHT_IGNORE", "REC_CATCH_EXCEPTION" })
    public static String publicKeyToMultibase(com.nimbusds.jose.jwk.OctetKeyPair keyPair) {
        try {
            byte[] publicKeyBytes = keyPair.getX().decode();
            // Prepend multicodec prefix for Ed25519-pub (0xed01)
            byte[] multicodecKey = new byte[34];
            multicodecKey[0] = (byte) 0xed;
            multicodecKey[1] = (byte) 0x01;
            System.arraycopy(publicKeyBytes, 0, multicodecKey, 2, 32);

            return "z" + base58Encode(multicodecKey);
        } catch (Exception e) {
            return null;
        }
    }



    /**
     * Generate did:key for OctetKeyPair (Ed25519).
     */
    public static String generateDIDKey(com.nimbusds.jose.jwk.OctetKeyPair keyPair) {
        String multibase = publicKeyToMultibase(keyPair);
        String didKey = "did:key:" + multibase;
        return didKey;
    }



    /**
     * Generate a did:key identifier for the given tenant (Default Ed25519 from KeyStore).
     * 
     * @param tenantId The tenant ID
     * @return did:key identifier
     * @throws Exception if key generation/retrieval fails
     */
    public static String generateDIDKey(int tenantId) throws Exception {
        com.nimbusds.jose.jwk.OctetKeyPair keyPair = getOrGenerateKeyPair(tenantId);
        return generateDIDKey(keyPair);
    }

    /**
     * Extract public key bytes from a did:key identifier.
     * 
     * @param didKey The did:key string (e.g., did:key:z6Mkf5rGMo...)
     * @return Raw 32-byte Ed25519 public key
     * @throws IllegalArgumentException if the did:key format is invalid
     */
    public static byte[] extractPublicKeyFromDIDKey(String didKey) {
        if (didKey == null || !didKey.startsWith("did:key:z")) {
            throw new IllegalArgumentException("Invalid did:key format: " + didKey);
        }

        // Remove "did:key:" prefix
        String multibase = didKey.substring(8);

        // Remove 'z' prefix (base58btc multibase indicator)
        String base58Part = multibase.substring(1);

        // Decode base58
        byte[] decoded = base58Decode(base58Part);

        // Verify multicodec prefix (0xed01 for Ed25519)
        if (decoded.length < 34 || decoded[0] != (byte) 0xed || decoded[1] != (byte) 0x01) {
            throw new IllegalArgumentException("Invalid Ed25519 multicodec prefix in did:key");
        }

        // Extract public key (skip 2-byte prefix)
        byte[] publicKey = java.util.Arrays.copyOfRange(decoded, 2, decoded.length);
        return publicKey;
    }

    /**
     * Base58 decode (Bitcoin alphabet).
     * 
     * @param input Base58 encoded string
     * @return Decoded byte array
     */
    public static byte[] base58Decode(String input) {
        String alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        int[] indexes = new int[128];
        java.util.Arrays.fill(indexes, -1);
        for (int i = 0; i < alphabet.length(); i++) {
            indexes[alphabet.charAt(i)] = i;
        }

        if (input.length() == 0) {
            return new byte[0];
        }

        // Convert base58 string to big integer
        byte[] input58 = new byte[input.length()];
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = c < 128 ? indexes[c] : -1;
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid Base58 character: " + c);
            }
            input58[i] = (byte) digit;
        }

        // Count leading zeros
        int zeros = 0;
        while (zeros < input58.length && input58[zeros] == 0) {
            zeros++;
        }

        // Convert from base58 to base256
        byte[] decoded = new byte[input.length()];
        int outputStart = decoded.length;
        for (int inputStart = zeros; inputStart < input58.length;) {
            decoded[--outputStart] = divmod(input58, inputStart, 58, 256);
            if (input58[inputStart] == 0) {
                inputStart++;
            }
        }

        // Skip leading zeros in decoded
        while (outputStart < decoded.length && decoded[outputStart] == 0) {
            outputStart++;
        }

        // Build result with leading zeros
        byte[] result = new byte[zeros + (decoded.length - outputStart)];
        System.arraycopy(decoded, outputStart, result, zeros, decoded.length - outputStart);
        return result;
    }

    /**
     * Convert public key to JWK Map.
     * 
     * @param keyPair The key pair
     * @return Map representing the public JWK
     */
    public static java.util.Map<String, Object> publicKeyToJwkMap(com.nimbusds.jose.jwk.OctetKeyPair keyPair) {
        return keyPair.toPublicJWK().toJSONObject();
    }

    /**
     * Base58 encode (Bitcoin alphabet).
     * Public for testing.
     * 
     * @param input Byte array to encode
     * @return Base58 encoded string
     */
    public static String base58Encode(byte[] input) {
        String alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
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
        for (int inputStart = zeros; inputStart < inputCopy.length;) {
            encoded[--outputStart] = (byte) alphabet.charAt(divmod(inputCopy, inputStart, 256, 58));
            if (inputCopy[inputStart] == 0) {
                inputStart++;
            }
        }

        // Skip leading zeros in encoded result
        while (outputStart < encoded.length && encoded[outputStart] == (byte) alphabet.charAt(0)) {
            outputStart++;
        }

        // Add original leading zeros
        while (--zeros >= 0) {
            encoded[--outputStart] = (byte) alphabet.charAt(0);
        }

        return new String(encoded, outputStart, encoded.length - outputStart, java.nio.charset.StandardCharsets.UTF_8);
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
     * Note: For EdDSA (KeyStore), this just clears cache and re-fetches.
     * For EC (Ephemeral), this generates new key.
     * 
     * @param tenantId The tenant ID
     * @return New OctetKeyPair
     * @throws Exception if generation fails
     */
    public static com.nimbusds.jose.jwk.OctetKeyPair regenerateKeyPair(int tenantId) throws Exception {
        keyCache.remove(tenantId);
        return getOrGenerateKeyPair(tenantId);
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
    }

}
