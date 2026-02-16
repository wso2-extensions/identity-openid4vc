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
import com.nimbusds.jose.util.Base64URL;
import org.wso2.carbon.identity.openid4vc.oid4vp.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.oid4vp.common.model.DIDDocument;
import org.wso2.carbon.identity.openid4vc.oid4vp.did.provider.DIDProvider;
import org.wso2.carbon.identity.openid4vc.oid4vp.did.util.BCEd25519Signer;
import org.wso2.carbon.identity.openid4vc.oid4vp.did.util.DIDKeyManager;

import java.util.Collections;

/**
 * DID Provider implementation for 'did:jwk' method using Ed25519 keys.
 */
public class DIDJwkProvider implements DIDProvider {

    @Override
    public String getName() {
        return "jwk";
    }

    @Override
    public String getDID(int tenantId, String baseUrl) throws VPException {
        try {
            OctetKeyPair keyPair = DIDKeyManager.getOrGenerateKeyPair(tenantId);
            String jwkJson = keyPair.toPublicJWK().toJSONString();
            String b64 = Base64URL.encode(jwkJson).toString();
            return "did:jwk:" + b64;
        } catch (Exception e) {
            throw new VPException("Error generating did:jwk", e);
        }
    }

    @Override
    public String getSigningKeyId(int tenantId, String baseUrl) throws VPException {
        // did:jwk usually refers to itself as the key ID or with #0
        return getDID(tenantId, baseUrl) + "#0";
    }

    @Override
    public JWSAlgorithm getSigningAlgorithm() {
        return JWSAlgorithm.EdDSA;
    }

    @Override
    public JWSSigner getSigner(int tenantId) throws VPException {
        try {
            OctetKeyPair keyPair = DIDKeyManager.getOrGenerateKeyPair(tenantId);
            return new BCEd25519Signer(keyPair);
        } catch (Exception e) {
            throw new VPException("Error creating signer for did:jwk", e);
        }
    }

    @Override
    public DIDDocument getDIDDocument(int tenantId, String baseUrl) throws VPException {
        try {
            String did = getDID(tenantId, baseUrl);
            String keyId = getSigningKeyId(tenantId, baseUrl);
            OctetKeyPair keyPair = DIDKeyManager.getOrGenerateKeyPair(tenantId);
            
            DIDDocument didDocument = new DIDDocument();
            didDocument.setId(did);
            
            DIDDocument.VerificationMethod verifyMethod = new DIDDocument.VerificationMethod();
            verifyMethod.setId(keyId);
            verifyMethod.setType("JsonWebKey2020");
            verifyMethod.setController(did);
            verifyMethod.setPublicKeyJwkMap(keyPair.toPublicJWK().toJSONObject());
            
            didDocument.setVerificationMethod(Collections.singletonList(verifyMethod));
            didDocument.setAuthentication(Collections.singletonList(keyId));
            didDocument.setAssertionMethod(Collections.singletonList(keyId));

            return didDocument;
        } catch (Exception e) {
            throw new VPException("Error generating DID Document for did:jwk", e);
        }
    }
}
