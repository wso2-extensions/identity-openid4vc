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
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.openid4vc.presentation.did.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.DIDDocument;
import org.wso2.carbon.identity.openid4vc.presentation.util.BCEd25519Signer;
import org.wso2.carbon.identity.openid4vc.presentation.util.DIDKeyManager;

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
                OctetKeyPair keyPair = DIDKeyManager.getOrGenerateKeyPair(tenantId);
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
                    OctetKeyPair keyPair = DIDKeyManager.getOrGenerateKeyPair(tenantId);

                    DIDDocument.VerificationMethod vm = new DIDDocument.VerificationMethod();
                    vm.setId(keyId);
                    vm.setController(did);
                    vm.setType("Ed25519VerificationKey2020");

                    // Ed25519VerificationKey2020 requires publicKeyMultibase
                    String multibase = DIDKeyManager.publicKeyToMultibase(keyPair);
                    vm.setPublicKeyMultibase(multibase.substring(1)); // Remove 'z' prefix as sometimes library expects
                                                                      // raw, but standard is multibase with z.
                    // Wait, standard uses z. DIDKeyManager.publicKeyToMultibase returns with 'z'.
                    // DIDKeyProvider does: verifyMethod.setPublicKeyMultibase(did.substring(8));
                    // did:key:z... -> substring(8) -> z...
                    // So we should keep the 'z'.
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
}
