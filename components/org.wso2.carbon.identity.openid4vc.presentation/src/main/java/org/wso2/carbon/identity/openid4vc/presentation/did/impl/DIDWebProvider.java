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
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.openid4vc.presentation.did.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.DIDDocument;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;

/**
 * DID Provider implementation for 'did:web' method using RSA keys from WSO2
 * KeyStore.
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
    public JWSAlgorithm getSigningAlgorithm() {
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
    public DIDDocument getDIDDocument(int tenantId, String baseUrl) throws VPException {
        try {
            String did = getDID(tenantId, baseUrl);
            String keyId = getSigningKeyId(tenantId, baseUrl);

            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            Certificate certificate = keyStoreManager.getDefaultPrimaryCertificate();
            RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();

            // Convert RSA Public Key to JWK
            com.nimbusds.jose.jwk.RSAKey rsaKey = new com.nimbusds.jose.jwk.RSAKey.Builder(publicKey)
                    .keyID(keyId)
                    .build();

            DIDDocument didDocument = new DIDDocument();
            didDocument.setId(did);

            DIDDocument.VerificationMethod verifyMethod = new DIDDocument.VerificationMethod();
            verifyMethod.setId(keyId);
            verifyMethod.setType("JsonWebKey2020");
            verifyMethod.setController(did);
            verifyMethod.setPublicKeyJwkMap(rsaKey.toJSONObject());

            didDocument.setVerificationMethod(Collections.singletonList(verifyMethod));
            didDocument.setAuthentication(Collections.singletonList(keyId));
            didDocument.setAssertionMethod(Collections.singletonList(keyId));

            return didDocument;

        } catch (Exception e) {
            throw new VPException("Error generating DID Document for did:web", e);
        }
    }
}
