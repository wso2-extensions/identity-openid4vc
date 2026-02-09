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

package org.wso2.carbon.identity.openid4vc.presentation.did.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.identity.openid4vc.presentation.did.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.DIDDocument;
import org.wso2.carbon.identity.openid4vc.presentation.util.BCEd25519Signer;
import org.wso2.carbon.identity.openid4vc.presentation.util.DIDKeyManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * DID Provider implementation for 'did:web' method.
 * Supports RSA (default via KeyStore), EdDSA and ES256 (via DIDKeyManager).
 */
public class DIDWebProvider implements DIDProvider {

    @Override
    public String getName() {
        return "web";
    }

    @Override
    public String getDID(int tenantId, String baseUrl) throws VPException {
        if (baseUrl == null || baseUrl.isEmpty()) {
            throw new VPException("Base URL is required for did:web generation");
        }
        String domain = baseUrl.replace("https://", "").replace("http://", "");
        if (domain.endsWith("/")) {
            domain = domain.substring(0, domain.length() - 1);
        }
        // Encode port colon if present
        if (domain.contains(":")) {
            domain = domain.replace(":", "%3A");
        }
        return "did:web:" + domain;
    }

    @Override
    public String getSigningKeyId(int tenantId, String baseUrl) throws VPException {
        return getDID(tenantId, baseUrl) + "#owner";
    }

    @Override
    public String getSigningKeyId(int tenantId, String baseUrl, String algorithm) throws VPException {
        String did = getDID(tenantId, baseUrl);
        if ("EdDSA".equals(algorithm)) {
            return did + "#" + "ed25519";
        } else if ("ES256".equals(algorithm)) {
            return did + "#" + "p256";
        }
        // Default (RS256)
        return did + "#owner";
    }

    @Override
    public JWSAlgorithm getSigningAlgorithm() {
        return JWSAlgorithm.RS256;
    }

    @Override
    public JWSAlgorithm getSigningAlgorithm(String algorithm) {
        if ("EdDSA".equals(algorithm)) {
            return JWSAlgorithm.EdDSA;
        }
        if ("ES256".equals(algorithm)) {
            return JWSAlgorithm.ES256;
        }
        return JWSAlgorithm.RS256;
    }

    @Override
    public JWSSigner getSigner(int tenantId) throws VPException {
        try {
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            PrivateKey privateKey = keyStoreManager.getDefaultPrivateKey();
            return new RSASSASigner(privateKey);
        } catch (Exception e) {
            throw new VPException("Error retrieving RSA private key for did:web", e);
        }
    }

    @Override
    public JWSSigner getSigner(int tenantId, String algorithm) throws VPException {
        try {
            if ("EdDSA".equals(algorithm)) {
                // Use KeyStore for EdDSA keys
                KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
                String edKeyAlias = getEdDSAKeyAlias(tenantId);
                PrivateKey privateKey = keyStoreManager.getDefaultPrivateKey(edKeyAlias);
                
                // Convert PrivateKey to OctetKeyPair for BCEd25519Signer
                OctetKeyPair keyPair = convertToOctetKeyPair(privateKey, keyStoreManager, edKeyAlias);
                return new BCEd25519Signer(keyPair);
            } else if ("ES256".equals(algorithm)) {
                ECKey key = DIDKeyManager.getOrGenerateECKeyPair(tenantId);
                return new ECDSASigner(key);
            }
            return getSigner(tenantId);
        } catch (Exception e) {
            throw new VPException("Error creating signer for did:web with algo: " + algorithm, e);
        }
    }

    @Override
    public DIDDocument getDIDDocument(int tenantId, String baseUrl) throws VPException {
        return getDIDDocument(tenantId, baseUrl, null);
    }

    @Override
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("DE_MIGHT_IGNORE")
    public DIDDocument getDIDDocument(int tenantId, String baseUrl, String algorithm) throws VPException {
        try {
            String did = getDID(tenantId, baseUrl);

            DIDDocument didDocument = new DIDDocument();
            didDocument.setId(did);

            // Add Standard Contexts
            List<String> contexts = new ArrayList<>();
            contexts.add("https://www.w3.org/ns/did/v1");
            contexts.add("https://w3id.org/security/suites/ed25519-2020/v1");
            contexts.add("https://w3id.org/security/suites/ecdsa-secp256r1-2019/v1");
            contexts.add("https://w3id.org/security/suites/rsa-2018/v1");
            didDocument.setContext(contexts);

            List<DIDDocument.VerificationMethod> verificationMethods = new ArrayList<>();
            List<String> relationships = new ArrayList<>();

            boolean includeAll = (algorithm == null);

            // 1. Add RSA Key (RsaVerificationKey2018)
            if (includeAll || "RS256".equals(algorithm)) {
                try {
                    String keyId = getSigningKeyId(tenantId, baseUrl, "RS256");
                    KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
                    Certificate certificate = keyStoreManager.getDefaultPrimaryCertificate();
                    RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();

                    com.nimbusds.jose.jwk.RSAKey rsaKey = new com.nimbusds.jose.jwk.RSAKey.Builder(publicKey)
                            .keyID(keyId)
                            .build();

                    DIDDocument.VerificationMethod vm = new DIDDocument.VerificationMethod();
                    vm.setId(keyId);
                    vm.setController(did);
                    vm.setType("RsaVerificationKey2018");
                    vm.setPublicKeyJwkMap(rsaKey.toJSONObject());

                    verificationMethods.add(vm);
                    relationships.add(keyId);

                } catch (Exception e) {
                }
            }

            // 2. Add EdDSA Key (Ed25519VerificationKey2020)
            if (includeAll || "EdDSA".equals(algorithm)) {
                try {
                    String keyId = getSigningKeyId(tenantId, baseUrl, "EdDSA");
                    
                    // Use KeyStore for EdDSA keys
                    KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
                    String edKeyAlias = getEdDSAKeyAlias(tenantId);
                    java.security.PublicKey publicKey = keyStoreManager.getDefaultPublicKey(edKeyAlias);

                    DIDDocument.VerificationMethod vm = new DIDDocument.VerificationMethod();
                    vm.setId(keyId);
                    vm.setController(did);
                    vm.setType("Ed25519VerificationKey2020");

                    // Convert PublicKey to multibase format
                    String multibase = convertPublicKeyToMultibase(publicKey);
                    vm.setPublicKeyMultibase(multibase);

                    verificationMethods.add(vm);
                    relationships.add(keyId);

                } catch (Exception e) {
                }
            }

            // 3. Add ES256 Key (EcdsaSecp256r1VerificationKey2019)
            if (includeAll || "ES256".equals(algorithm)) {
                try {
                    String keyId = getSigningKeyId(tenantId, baseUrl, "ES256");
                    ECKey key = DIDKeyManager.getOrGenerateECKeyPair(tenantId);

                    DIDDocument.VerificationMethod vm = new DIDDocument.VerificationMethod();
                    vm.setId(keyId);
                    vm.setController(did);
                    vm.setType("EcdsaSecp256r1VerificationKey2019");
                    vm.setPublicKeyJwkMap(key.toPublicJWK().toJSONObject());

                    verificationMethods.add(vm);
                    relationships.add(keyId);

                } catch (Exception e) {
                }
            }

            didDocument.setVerificationMethod(verificationMethods);
            didDocument.setAuthentication(relationships);
            didDocument.setAssertionMethod(relationships);

            return didDocument;

        } catch (Exception e) {
            throw new VPException("Error generating DID Document for did:web algo: " + algorithm, e);
        }
    }

    /**
     * Get the EdDSA key alias for the given tenant.
     * 
     * @param tenantId The tenant ID
     * @return EdDSA key alias
     * @throws Exception if alias generation fails
     */
    private String getEdDSAKeyAlias(int tenantId) throws Exception {
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
    private OctetKeyPair convertToOctetKeyPair(PrivateKey privateKey, 
                                                KeyStoreManager keyStoreManager, 
                                                String alias) throws Exception {
        // Get public key
        java.security.PublicKey publicKey = keyStoreManager.getDefaultPublicKey(alias);
        
        // Extract raw key bytes (Ed25519 keys are 32 bytes each)
        byte[] privateKeyBytes = privateKey.getEncoded();
        byte[] publicKeyBytes = publicKey.getEncoded();
        
        // Ed25519 private key in PKCS#8 format has the actual key at offset 16 (32 bytes)
        // Ed25519 public key in X.509 format has the actual key at offset 12 (32 bytes)
        byte[] rawPrivateKey = java.util.Arrays.copyOfRange(privateKeyBytes, 
                privateKeyBytes.length - 32, privateKeyBytes.length);
        byte[] rawPublicKey = java.util.Arrays.copyOfRange(publicKeyBytes, 
                publicKeyBytes.length - 32, publicKeyBytes.length);
        
        Base64URL x = Base64URL.encode(rawPublicKey);
        Base64URL d = Base64URL.encode(rawPrivateKey);
        
        return new OctetKeyPair.Builder(com.nimbusds.jose.jwk.Curve.Ed25519, x).d(d).build();
    }

    /**
     * Convert PublicKey to multibase format for DID document.
     * 
     * @param publicKey The public key from KeyStore
     * @return Multibase encoded string
     * @throws Exception if conversion fails
     */
    private String convertPublicKeyToMultibase(java.security.PublicKey publicKey) throws Exception {
        byte[] publicKeyBytes = publicKey.getEncoded();
        
        // Extract raw Ed25519 public key (32 bytes at the end)
        byte[] rawPublicKey = java.util.Arrays.copyOfRange(publicKeyBytes, 
                publicKeyBytes.length - 32, publicKeyBytes.length);
        
        // Prepend multicodec prefix for Ed25519-pub (0xed01)
        byte[] multicodecKey = new byte[34];
        multicodecKey[0] = (byte) 0xed;
        multicodecKey[1] = (byte) 0x01;
        System.arraycopy(rawPublicKey, 0, multicodecKey, 2, 32);
        
        return "z" + base58Encode(multicodecKey);
    }

    /**
     * Base58 encode (Bitcoin alphabet).
     * 
     * @param input Byte array to encode
     * @return Base58 encoded string
     */
    private String base58Encode(byte[] input) {
        String alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        if (input.length == 0) {
            return "";
        }

        byte[] inputCopy = new byte[input.length];
        System.arraycopy(input, 0, inputCopy, 0, input.length);

        int zeros = 0;
        while (zeros < inputCopy.length && inputCopy[zeros] == 0) {
            zeros++;
        }

        byte[] encoded = new byte[inputCopy.length * 2];
        int outputStart = encoded.length;
        for (int inputStart = zeros; inputStart < inputCopy.length;) {
            encoded[--outputStart] = (byte) alphabet.charAt(divmod(inputCopy, inputStart, 256, 58));
            if (inputCopy[inputStart] == 0) {
                inputStart++;
            }
        }

        while (outputStart < encoded.length && encoded[outputStart] == (byte) alphabet.charAt(0)) {
            outputStart++;
        }

        while (--zeros >= 0) {
            encoded[--outputStart] = (byte) alphabet.charAt(0);
        }

        return new String(encoded, outputStart, encoded.length - outputStart, java.nio.charset.StandardCharsets.UTF_8);
    }

    private byte divmod(byte[] number, int firstDigit, int base, int divisor) {
        int remainder = 0;
        for (int i = firstDigit; i < number.length; i++) {
            int digit = (int) number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return (byte) remainder;
    }
}
