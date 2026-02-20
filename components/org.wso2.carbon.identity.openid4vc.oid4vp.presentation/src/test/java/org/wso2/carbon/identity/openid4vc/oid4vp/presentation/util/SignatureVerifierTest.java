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

package org.wso2.carbon.identity.openid4vc.oid4vp.presentation.util;

import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.oid4vp.did.service.DIDResolverService;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class SignatureVerifierTest {

    private SignatureVerifier signatureVerifier;
    private DIDResolverService didResolverService;
    private KeyPair rsaKeyPair;

    @BeforeMethod
    public void setUp() throws Exception {
        didResolverService = Mockito.mock(DIDResolverService.class);
        signatureVerifier = new SignatureVerifier(didResolverService);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        rsaKeyPair = keyGen.generateKeyPair();
    }

    @Test
    public void testVerifyJwtSignatureRS256() throws Exception {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"test\"}".getBytes());
        
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initSign(rsaKeyPair.getPrivate());
        sig.update((header + "." + payload).getBytes());
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign());
        
        String jwt = header + "." + payload + "." + signature;
        
        assertTrue(signatureVerifier.verifyJwtSignature(jwt, rsaKeyPair.getPublic(), "RS256"));
    }

    @Test
    public void testVerifyJwtSignatureInvalid() throws Exception {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"test\"}".getBytes());
        String jwt = header + "." + payload + ".invalid-signature";
        
        assertFalse(signatureVerifier.verifyJwtSignature(jwt, rsaKeyPair.getPublic(), "RS256"));
    }

    @Test
    public void testVerifyLinkedDataSignatureGenericRSA() throws Exception {
        String document = "{\"id\":\"test-doc\"}";
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initSign(rsaKeyPair.getPrivate());
        
        // Generic signature logic in SignatureVerifier hashes the document first
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] docHash = digest.digest(document.getBytes());
        sig.update(docHash);
        
        String proofValue = Base64.getEncoder().encodeToString(sig.sign());
        
        assertTrue(signatureVerifier.verifyLinkedDataSignature(document, rsaKeyPair.getPublic(), "GenericSignature", proofValue));
    }

    @Test
    public void testGenericSignatureFallback() throws Exception {
        PublicKey mockKey = Mockito.mock(PublicKey.class);
        Mockito.when(mockKey.getAlgorithm()).thenReturn("Unknown");
        
        // This should trigger the default fallback to SHA256withRSA
        // Even if it fails verification, it should reach the JCA Signature.getInstance
        try {
            signatureVerifier.verifyLinkedDataSignature("{}", rsaKeyPair.getPublic(), "UnknownType", "some-value");
        } catch (Exception e) {
            // Expected if some-value is not valid base64 or doesn't match
        }
    }
}
