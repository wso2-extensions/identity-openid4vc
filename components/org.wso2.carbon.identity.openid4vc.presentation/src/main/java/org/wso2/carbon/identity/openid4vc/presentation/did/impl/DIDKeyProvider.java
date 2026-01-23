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
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.ECKey;
import org.wso2.carbon.identity.openid4vc.presentation.did.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.DIDDocument;
import org.wso2.carbon.identity.openid4vc.presentation.util.BCEd25519Signer;
import org.wso2.carbon.identity.openid4vc.presentation.util.DIDKeyManager;

import java.util.Collections;

/**
 * DID Provider implementation for 'did:key' method using Ed25519 (default) or
 * P-256 keys.
 */
public class DIDKeyProvider implements DIDProvider {

    @Override
    public String getName() {
        return "key";
    }

    @Override
    public String getDID(int tenantId, String baseUrl) throws VPException {
        // Default to Ed25519
        return getDID(tenantId, baseUrl, null);
    }

    @Override
    public String getDID(int tenantId, String baseUrl, String algorithm) throws VPException {
        try {
            if ("ES256".equals(algorithm)) {
                ECKey key = DIDKeyManager.getOrGenerateECKeyPair(tenantId);
                return DIDKeyManager.generateDIDKey(key);
            }
            return DIDKeyManager.generateDIDKey(tenantId);
        } catch (Exception e) {
            throw new VPException("Error retrieving/generating did:key for tenant: " + tenantId, e);
        }
    }

    @Override
    public String getSigningKeyId(int tenantId, String baseUrl) throws VPException {
        return getSigningKeyId(tenantId, baseUrl, null);
    }

    @Override
    public String getSigningKeyId(int tenantId, String baseUrl, String algorithm) throws VPException {
        String did = getDID(tenantId, baseUrl, algorithm);
        // Remove "did:key:" prefix to get the multibase part which is used as fragment
        String multibase = did.substring(8);
        return did + "#" + multibase;
    }

    @Override
    public JWSAlgorithm getSigningAlgorithm() {
        return JWSAlgorithm.EdDSA;
    }

    @Override
    public JWSAlgorithm getSigningAlgorithm(String algorithm) {
        if ("ES256".equals(algorithm)) {
            return JWSAlgorithm.ES256;
        }
        return JWSAlgorithm.EdDSA;
    }

    @Override
    public JWSSigner getSigner(int tenantId) throws VPException {
        return getSigner(tenantId, null);
    }

    @Override
    public JWSSigner getSigner(int tenantId, String algorithm) throws VPException {
        try {
            if ("ES256".equals(algorithm)) {
                ECKey key = DIDKeyManager.getOrGenerateECKeyPair(tenantId);
                return new ECDSASigner(key);
            }

            OctetKeyPair keyPair = DIDKeyManager.getOrGenerateKeyPair(tenantId);
            return new BCEd25519Signer(keyPair);
        } catch (Exception e) {
            throw new VPException("Error creating signer for did:key with algo: " + algorithm, e);
        }
    }

    @Override
    public DIDDocument getDIDDocument(int tenantId, String baseUrl) throws VPException {
        return getDIDDocument(tenantId, baseUrl, null);
    }

    @Override
    public DIDDocument getDIDDocument(int tenantId, String baseUrl, String algorithm) throws VPException {
        String did = getDID(tenantId, baseUrl, algorithm);
        String keyId = getSigningKeyId(tenantId, baseUrl, algorithm);
        DIDDocument didDocument = new DIDDocument();
        didDocument.setId(did);

        DIDDocument.VerificationMethod verifyMethod = new DIDDocument.VerificationMethod();
        verifyMethod.setId(keyId);
        verifyMethod.setController(did);

        if ("ES256".equals(algorithm)) {
            try {
                ECKey key = DIDKeyManager.getOrGenerateECKeyPair(tenantId);
                verifyMethod.setType("JsonWebKey2020");
                verifyMethod.setPublicKeyJwkMap(key.toPublicJWK().toJSONObject());
            } catch (Exception e) {
                throw new VPException("Error retrieving EC key for DID Document", e);
            }
        } else {
            // Ed25519
            verifyMethod.setType("Ed25519VerificationKey2020");
            verifyMethod.setPublicKeyMultibase(did.substring(8));
        }

        didDocument.setVerificationMethod(Collections.singletonList(verifyMethod));
        didDocument.setAuthentication(Collections.singletonList(keyId));
        didDocument.setAssertionMethod(Collections.singletonList(keyId));

        return didDocument;
    }
}
