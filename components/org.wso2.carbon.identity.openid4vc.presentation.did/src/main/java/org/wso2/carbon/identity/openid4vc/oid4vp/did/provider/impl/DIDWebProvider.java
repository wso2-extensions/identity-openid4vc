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

package org.wso2.carbon.identity.openid4vc.oid4vp.did.provider.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.OctetKeyPair;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.openid4vc.oid4vp.did.provider.DIDProvider;
import org.wso2.carbon.identity.openid4vc.oid4vp.did.util.BCEd25519Signer;
import org.wso2.carbon.identity.openid4vc.oid4vp.did.util.DIDKeyManager;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.common.model.DIDDocument;

import java.security.PrivateKey;
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
        return getDID(tenantId, baseUrl) + "#ed25519";
    }

    @Override
    public JWSAlgorithm getSigningAlgorithm() {
        return JWSAlgorithm.EdDSA;
    }

    @Override
    public JWSSigner getSigner(int tenantId) throws VPException {
        try {
            // Use KeyStore for EdDSA keys
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            String edKeyAlias = DIDKeyManager.getEdDSAKeyAlias(tenantId);
            PrivateKey privateKey = keyStoreManager.getDefaultPrivateKey(edKeyAlias);
            
            // Convert PrivateKey to OctetKeyPair for BCEd25519Signer
            OctetKeyPair keyPair = DIDKeyManager.convertToOctetKeyPair(privateKey, keyStoreManager, edKeyAlias);
            return new BCEd25519Signer(keyPair);
        } catch (Exception e) {
            throw new VPException("Error creating signer for did:web", e);
        }
    }

    @Override
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("DE_MIGHT_IGNORE")
    public DIDDocument getDIDDocument(int tenantId, String baseUrl) throws VPException {
        try {
            String did = getDID(tenantId, baseUrl);

            DIDDocument didDocument = new DIDDocument();
            didDocument.setId(did);

            // Add Standard Contexts
            List<String> contexts = new ArrayList<>();
            contexts.add("https://www.w3.org/ns/did/v1");
            contexts.add("https://w3id.org/security/suites/ed25519-2020/v1");
            didDocument.setContext(contexts);

            List<DIDDocument.VerificationMethod> verificationMethods = new ArrayList<>();
            List<String> relationships = new ArrayList<>();

            try {
                String keyId = getSigningKeyId(tenantId, baseUrl);
                
                // Use KeyStore for EdDSA keys
                KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
                String edKeyAlias = DIDKeyManager.getEdDSAKeyAlias(tenantId);
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

            didDocument.setVerificationMethod(verificationMethods);
            didDocument.setAuthentication(relationships);
            didDocument.setAssertionMethod(relationships);

            return didDocument;

        } catch (Exception e) {
            throw new VPException("Error generating DID Document for did:web", e);
        }
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
