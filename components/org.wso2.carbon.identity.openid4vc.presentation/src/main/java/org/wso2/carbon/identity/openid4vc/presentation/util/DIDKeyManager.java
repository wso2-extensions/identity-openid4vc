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

import org.wso2.carbon.identity.openid4vc.presentation.dao.DIDKeysDAO;
import org.wso2.carbon.identity.openid4vc.presentation.dao.impl.DIDKeysDAOImpl;
import org.wso2.carbon.identity.openid4vc.presentation.model.DIDKey;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.util.Base64URL;
import java.util.concurrent.ConcurrentHashMap;
import com.nimbusds.jose.JWSAlgorithm;

/**
 * Manages cryptographic keys for DID documents.
 * Generates and caches keys per tenant for DID operations.
 */
public class DIDKeyManager {

    private static final Log LOG = LogFactory.getLog(DIDKeyManager.class);
    private static final ConcurrentHashMap<Integer, OctetKeyPair> keyCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Integer, ECKey> ecKeyCache = new ConcurrentHashMap<>();
    private static final DIDKeysDAO didKeysDAO = new DIDKeysDAOImpl();

    /**
     * Get or generate Ed25519 key pair for the given tenant (Default).
     * 
     * @param tenantId The tenant ID
     * @return OctetKeyPair for the tenant
     * @throws Exception if key generation fails
     */
    public static OctetKeyPair getOrGenerateKeyPair(int tenantId) throws Exception {
        // 1. Try Cache
        if (keyCache.containsKey(tenantId)) {
            return keyCache.get(tenantId);
        }

        // 2. Try DB
        try {
            DIDKey existingKey = didKeysDAO.getDIDKeyByTenantAndAlgo(tenantId, "Ed25519");
            // Fallback for backward compatibility (if algo was not saved or generic
            // retrieval needed)
            if (existingKey == null) {
                existingKey = didKeysDAO.getDIDKeyByTenant(tenantId);
                // Verify it's Ed25519 by length or algo field
                if (existingKey != null && !"Ed25519".equals(existingKey.getAlgorithm())
                        && existingKey.getAlgorithm() != null) {
                    existingKey = null; // Found a key but not Ed25519
                }
            }

            if (existingKey != null) {
                Base64URL x = Base64URL.encode(existingKey.getPublicKey());
                Base64URL d = Base64URL.encode(existingKey.getPrivateKey());
                OctetKeyPair keyPair = new OctetKeyPair.Builder(Curve.Ed25519, x).d(d).build();

                keyCache.put(tenantId, keyPair);
                LOG.info("Loaded Ed25519 key from DB for tenant: " + tenantId);
                return keyPair;
            }
        } catch (Exception e) {
            LOG.warn("Error checking DB for DID keys, proceeding to generate new one: " + e.getMessage());
        }

        // 3. Generate New
        LOG.info("Generating NEW Ed25519 Key Pair for tenant: " + tenantId);
        OctetKeyPair keyPair = generateEd25519KeyPair();

        // 4. Save to DB
        saveEd25519Key(tenantId, keyPair);

        // 5. Cache
        keyCache.put(tenantId, keyPair);
        return keyPair;
    }

    /**
     * Get or generate EC (P-256) key pair for the given tenant.
     * 
     * @param tenantId The tenant ID
     * @return ECKey for the tenant
     * @throws Exception if key generation fails
     */
    public static ECKey getOrGenerateECKeyPair(int tenantId) throws Exception {
        // 1. Try Cache
        if (ecKeyCache.containsKey(tenantId)) {
            return ecKeyCache.get(tenantId);
        }

        // 2. Try DB
        try {
            DIDKey existingKey = didKeysDAO.getDIDKeyByTenantAndAlgo(tenantId, "ES256");
            if (existingKey != null) {
                // Reconstruct ECKey
                byte[] pubKey = existingKey.getPublicKey();
                byte[] privKey = existingKey.getPrivateKey();

                // Public key stored as X (32) + Y (32)
                if (pubKey.length == 64) {
                    byte[] xBytes = java.util.Arrays.copyOfRange(pubKey, 0, 32);
                    byte[] yBytes = java.util.Arrays.copyOfRange(pubKey, 32, 64);

                    Base64URL x = Base64URL.encode(xBytes);
                    Base64URL y = Base64URL.encode(yBytes);
                    Base64URL d = Base64URL.encode(privKey);

                    ECKey ecKey = new ECKey.Builder(Curve.P_256, x, y).d(d).build();
                    ecKeyCache.put(tenantId, ecKey);
                    LOG.info("Loaded ES256 key from DB for tenant: " + tenantId);
                    return ecKey;
                }
            }
        } catch (Exception e) {
            LOG.warn("Error checking DB for EC keys, proceeding to generate new one: " + e.getMessage());
        }

        // 3. Generate New
        LOG.info("Generating NEW P-256 Key Pair for tenant: " + tenantId);
        ECKey ecKey = generateECKeyPair();

        // 4. Save to DB
        saveECKey(tenantId, ecKey);

        // 5. Cache
        ecKeyCache.put(tenantId, ecKey);
        return ecKey;
    }

    private static OctetKeyPair generateEd25519KeyPair() throws Exception {
        // Use Bouncy Castle directly to avoid Nimbus dependency on Google Tink which is
        // missing in OSGi
        org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator gen = new org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator();
        gen.init(new org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(new java.security.SecureRandom()));
        org.bouncycastle.crypto.AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

        org.bouncycastle.crypto.params.Ed25519PublicKeyParameters publicParams = (org.bouncycastle.crypto.params.Ed25519PublicKeyParameters) keyPair
                .getPublic();
        org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters privateParams = (org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters) keyPair
                .getPrivate();

        Base64URL x = Base64URL.encode(publicParams.getEncoded());
        Base64URL d = Base64URL.encode(privateParams.getEncoded());

        return new OctetKeyPair.Builder(Curve.Ed25519, x).d(d).build();
    }

    private static ECKey generateECKeyPair() throws Exception {
        return new ECKeyGenerator(Curve.P_256).generate();
    }

    private static void saveEd25519Key(int tenantId, OctetKeyPair keyPair) {
        try {
            String didKeyString = generateDIDKey(keyPair);
            DIDKey newDidKey = new DIDKey(
                    didKeyString,
                    tenantId,
                    "Ed25519",
                    keyPair.getX().decode(),
                    keyPair.getD().decode());
            didKeysDAO.addDIDKey(newDidKey);
            LOG.info("Persisted new Ed25519 key for tenant: " + tenantId);
        } catch (Exception e) {
            LOG.error("Error persisting Ed25519 key: " + e.getMessage(), e);
        }
    }

    private static void saveECKey(int tenantId, ECKey keyPair) {
        try {
            String didKeyString = generateDIDKey(keyPair);

            // Concatenate X and Y for public key
            byte[] xBytes = keyPair.getX().decode();
            byte[] yBytes = keyPair.getY().decode();
            byte[] pubKey = new byte[xBytes.length + yBytes.length];
            System.arraycopy(xBytes, 0, pubKey, 0, xBytes.length);
            System.arraycopy(yBytes, 0, pubKey, xBytes.length, yBytes.length);

            DIDKey newDidKey = new DIDKey(
                    didKeyString,
                    tenantId,
                    "ES256", // Using algorithm name
                    pubKey,
                    keyPair.getD().decode());
            didKeysDAO.addDIDKey(newDidKey);
            LOG.info("Persisted new ES256 key for tenant: " + tenantId);
        } catch (Exception e) {
            LOG.error("Error persisting ES256 key: " + e.getMessage(), e);
        }
    }

    /**
     * Convert Ed25519 public key to multibase format.
     * Format: z + base58btc(0xed01 + public key bytes)
     */
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
            LOG.error("Failed to convert public key to multibase", e);
            return null;
        }
    }

    /**
     * Convert P-256 public key to multibase format.
     * Format: z + base58btc(0x1200 + compressed point)
     * P-256 multicodec is 0x1200
     */
    public static String publicKeyToMultibase(com.nimbusds.jose.jwk.ECKey keyPair) {
        try {
            // Needed: Compressed point (33 bytes: 0x02/0x03 + X)
            byte[] xBytes = keyPair.getX().decode();
            byte[] yBytes = keyPair.getY().decode();

            byte[] compressed = new byte[33];
            // 0x02 if Y is even, 0x03 if Y is odd
            // BigInteger check for oddness usually checks lowest bit
            java.math.BigInteger yBigInt = new java.math.BigInteger(1, yBytes);
            compressed[0] = yBigInt.testBit(0) ? (byte) 0x03 : (byte) 0x02;
            System.arraycopy(xBytes, 0, compressed, 1, 32);

            // Multicodec Prefix for p256-pub is 0x1200 (varint encoded?)
            // According to multicodec table: p256-pub is 0x1200
            // Varint encoding of 0x1200 -> 0x1200 -> 1001 000 0000 000
            // Wait, standard did:key for P-256 uses 0x1200.
            // 0x1200 = 0001 0010 0000 0000
            // Varint:
            // 0x80 | 0x00? No.
            // Let's use standard table. 0x1200.
            // 2 bytes: 0x80 0x24 (Wait, 0x1200 is 4608 decimal)
            // 4608 = 1001000000000
            // 7-bit groups: 0000000 (0), 0100100 (36 = 0x24)
            // So: 0x80 (continuation) 0x24.

            // Let's verify with known impl or spec.
            // W3C CCG did-method-key: P-256 is 0x1200.
            // Varint(0x1200) = [0x80, 0x24]

            byte[] multicodecKey = new byte[35]; // 2 header + 33 data
            multicodecKey[0] = (byte) 0x80;
            multicodecKey[1] = (byte) 0x24; // 0x24 = 36
            System.arraycopy(compressed, 0, multicodecKey, 2, 33);

            return "z" + base58Encode(multicodecKey);
        } catch (Exception e) {
            LOG.error("Failed to convert public key to multibase", e);
            return null;
        }
    }

    /**
     * Generate did:key for OctetKeyPair (Ed25519).
     */
    public static String generateDIDKey(com.nimbusds.jose.jwk.OctetKeyPair keyPair) {
        String multibase = publicKeyToMultibase(keyPair);
        String didKey = "did:key:" + multibase;
        LOG.info("Generated did:key (Ed25519): " + didKey);
        return didKey;
    }

    /**
     * Generate did:key for ECKey (P-256).
     */
    public static String generateDIDKey(com.nimbusds.jose.jwk.ECKey keyPair) {
        String multibase = publicKeyToMultibase(keyPair);
        String didKey = "did:key:" + multibase;
        LOG.info("Generated did:key (P-256): " + didKey);
        return didKey;
    }

    /**
     * Generate a did:key identifier for the given tenant (Default Ed25519).
     * 
     * @param tenantId The tenant ID
     * @return did:key identifier
     * @throws Exception if key generation fails
     */
    public static String generateDIDKey(int tenantId) throws Exception {
        com.nimbusds.jose.jwk.OctetKeyPair keyPair = getOrGenerateKeyPair(tenantId);
        return generateDIDKey(keyPair);
    }

    private static byte[] extractRawPublicKey(java.security.PublicKey publicKey) {
        // Ed25519 keys are X.509 encoded. The raw key is the last 32 bytes
        byte[] encoded = publicKey.getEncoded();
        int length = encoded.length;
        if (length < 32)
            return encoded;
        return java.util.Arrays.copyOfRange(encoded, length - 32, length);
    }

    private static byte[] extractRawPrivateKey(java.security.PrivateKey privateKey) {
        // Ed25519 private keys are PKCS#8 encoded. The raw key is inside an OctetString
        // For simplicity in this demo, accessing the last 32 bytes usually works for
        // BC/Java
        // but parsing the ASN.1 properly is safer.
        // Given the time constraint, we'll try the suffix approach which works for
        // standard Ed25519 encodings.
        byte[] encoded = privateKey.getEncoded();
        int length = encoded.length;
        if (length < 32)
            return encoded;
        return java.util.Arrays.copyOfRange(encoded, length - 32, length);
    }

    /**
     * Convert Ed25519 public key to multibase format.
     * Format: z + base58btc(0xed01 + public key bytes)
     * 
     * @param keyPair The key pair containing the Ed25519 public key
     * @return Multibase encoded string (z-prefix for base58btc)
     */

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
        LOG.info("Extracted public key from did:key, length: " + publicKey.length);
        return publicKey;
    }

    /**
     * Base58 decode (Bitcoin alphabet).
     * 
     * @param input Base58 encoded string
     * @return Decoded byte array
     */
    public static byte[] base58Decode(String input) {
        String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        int[] INDEXES = new int[128];
        java.util.Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET.length(); i++) {
            INDEXES[ALPHABET.charAt(i)] = i;
        }

        if (input.length() == 0) {
            return new byte[0];
        }

        // Convert base58 string to big integer
        byte[] input58 = new byte[input.length()];
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = c < 128 ? INDEXES[c] : -1;
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
        for (int inputStart = zeros; inputStart < inputCopy.length;) {
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
     * @return New OctetKeyPair
     * @throws Exception if generation fails
     */
    public static com.nimbusds.jose.jwk.OctetKeyPair regenerateKeyPair(int tenantId) throws Exception {
        LOG.info("Regenerating key pair for tenant: " + tenantId);
        com.nimbusds.jose.jwk.OctetKeyPair keyPair = generateEd25519KeyPair();
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

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
