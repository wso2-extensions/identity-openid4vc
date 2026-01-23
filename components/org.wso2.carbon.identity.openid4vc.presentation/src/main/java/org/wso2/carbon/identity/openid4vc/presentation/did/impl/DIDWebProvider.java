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
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.openid4vc.presentation.did.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.DIDDocument;
import org.wso2.carbon.identity.openid4vc.presentation.util.BCEd25519Signer;
import org.wso2.carbon.identity.openid4vc.presentation.util.DIDKeyManager;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;

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
        if ("EdDSA".equals(algorithm))
            return JWSAlgorithm.EdDSA;
        if ("ES256".equals(algorithm))
            return JWSAlgorithm.ES256;
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
    public DIDDocument getDIDDocument(int tenantId, String baseUrl, String algorithm) throws VPException {
        try {
            String did = getDID(tenantId, baseUrl);
            String keyId = getSigningKeyId(tenantId, baseUrl, algorithm);

            DIDDocument didDocument = new DIDDocument();
            didDocument.setId(did);

            DIDDocument.VerificationMethod verifyMethod = new DIDDocument.VerificationMethod();
            verifyMethod.setId(keyId);
            verifyMethod.setController(did);

            if ("EdDSA".equals(algorithm)) {
                OctetKeyPair keyPair = DIDKeyManager.getOrGenerateKeyPair(tenantId);
                verifyMethod.setType("JsonWebKey2020");
                verifyMethod.setPublicKeyJwkMap(keyPair.toPublicJWK().toJSONObject());

            } else if ("ES256".equals(algorithm)) {
                ECKey key = DIDKeyManager.getOrGenerateECKeyPair(tenantId);
                verifyMethod.setType("JsonWebKey2020");
                verifyMethod.setPublicKeyJwkMap(key.toPublicJWK().toJSONObject());

            } else {
                // Default: RS256
                KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
                Certificate certificate = keyStoreManager.getDefaultPrimaryCertificate();
                RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();

                // Convert RSA Public Key to JWK
                com.nimbusds.jose.jwk.RSAKey rsaKey = new com.nimbusds.jose.jwk.RSAKey.Builder(publicKey)
                        .keyID(keyId)
                        .build();

                verifyMethod.setType("JsonWebKey2020");
                verifyMethod.setPublicKeyJwkMap(rsaKey.toJSONObject());
            }

            didDocument.setVerificationMethod(Collections.singletonList(verifyMethod));
            didDocument.setAuthentication(Collections.singletonList(keyId));
            didDocument.setAssertionMethod(Collections.singletonList(keyId));

            return didDocument;

        } catch (Exception e) {
            throw new VPException("Error generating DID Document for did:web algo: " + algorithm, e);
        }
    }
}
