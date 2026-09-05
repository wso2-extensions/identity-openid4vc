/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.did.provider.impl;

import com.nimbusds.jose.JWSAlgorithm;
import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.did.model.DIDDocument;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.interfaces.EdECPublicKey;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Unit tests for DIDWebProvider.
 */
public class DIDWebProviderTest {

    /**
     * Tests basic provider metadata methods.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testProviderMetadata() throws Exception {
        DIDWebProvider provider = new DIDWebProvider();

        Assert.assertEquals(provider.getName(), "web");
        Assert.assertEquals(provider.getSigningAlgorithm(), JWSAlgorithm.EdDSA);
        Assert.assertEquals(provider.getSigningKeyId(-1234, "https://example.com"), "did:web:example.com#ed25519");
    }

    /**
     * Tests DID generation with URL variants.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testGetDIDWithVariants() throws Exception {
        DIDWebProvider provider = new DIDWebProvider();

        Assert.assertEquals(provider.getDID(-1234, "https://example.com"), "did:web:example.com");
        Assert.assertEquals(provider.getDID(-1234, "http://example.com:9443"), "did:web:example.com%3A9443");
        Assert.assertEquals(provider.getDID(-1234, "https://example.com/path/to"), "did:web:example.com:path:to");
        Assert.assertEquals(provider.getDID(-1234, "https://example.com/"), "did:web:example.com");
    }

    /**
     * Tests DID generation failure on empty base URL.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = VPException.class)
    public void testGetDIDWithInvalidBaseUrl() throws Exception {
        DIDWebProvider provider = new DIDWebProvider();
        provider.getDID(-1234, "");
    }

    /**
     * Tests signer creation failure handling.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = VPException.class)
    public void testGetSignerFailure() throws Exception {
        DIDWebProvider provider = new DIDWebProvider();

        try (MockedStatic<KeyStoreManager> keyStoreManagerMockedStatic = mockStatic(KeyStoreManager.class)) {
            keyStoreManagerMockedStatic.when(() -> KeyStoreManager.getInstance(-1234))
                    .thenThrow(new RuntimeException("keystore unavailable"));
            provider.getSigner(-1234);
        }
    }

    /**
     * Tests DID document generation fallback when key resolution fails.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testGetDIDDocumentFallbackOnKeyFailure() throws Exception {
        DIDWebProvider provider = new DIDWebProvider();

        try (MockedStatic<KeyStoreManager> keyStoreManagerMockedStatic = mockStatic(KeyStoreManager.class)) {
            keyStoreManagerMockedStatic.when(() -> KeyStoreManager.getInstance(-1234))
                    .thenThrow(new RuntimeException("keystore unavailable"));

            DIDDocument document = provider.getDIDDocument(-1234, "https://example.com");
            Assert.assertNotNull(document);
            Assert.assertEquals(document.getId(), "did:web:example.com");
            Assert.assertNotNull(document.getContext());
            Assert.assertTrue(document.getContext().contains("https://www.w3.org/ns/did/v1"));
            Assert.assertTrue(document.getVerificationMethod().isEmpty());
        }
    }

    /**
     * Tests DID document generation failure for invalid base URL.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = VPException.class)
    public void testGetDIDDocumentFailureOnInvalidBaseUrl() throws Exception {
        DIDWebProvider provider = new DIDWebProvider();
        provider.getDIDDocument(-1234, "");
    }



    /**
     * Tests successful DID document generation with key material.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testGetDIDDocumentSuccess() throws Exception {
        DIDWebProvider provider = new DIDWebProvider();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        KeyStoreManager keyStoreManager = mock(KeyStoreManager.class);
        when(keyStoreManager.getDefaultPublicKey("wso2carbon_ed"))
                .thenReturn(keyPair.getPublic());

        KeyStore keyStore = mock(KeyStore.class);
        when(keyStore.aliases()).thenReturn(java.util.Collections.enumeration(
                java.util.Collections.singletonList("wso2carbon_ed")));
        when(keyStore.isKeyEntry("wso2carbon_ed")).thenReturn(true);

        java.security.cert.Certificate certificate = mock(java.security.cert.Certificate.class);
        EdECPublicKey edECPublicKey = mock(EdECPublicKey.class);
        when(certificate.getPublicKey()).thenReturn(edECPublicKey);
        when(keyStore.getCertificate("wso2carbon_ed")).thenReturn(certificate);

        IdentityKeyStoreResolver identityKeyStoreResolver = mock(IdentityKeyStoreResolver.class);
        when(identityKeyStoreResolver.getKeyStore(anyString(),
                eq(IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)))
                .thenReturn(keyStore);

        try (MockedStatic<KeyStoreManager> keyStoreManagerMockedStatic = mockStatic(KeyStoreManager.class);
             MockedStatic<IdentityKeyStoreResolver> identityKeyStoreResolverMockedStatic =
                     mockStatic(IdentityKeyStoreResolver.class)) {
            keyStoreManagerMockedStatic.when(() -> KeyStoreManager.getInstance(-1234))
                    .thenReturn(keyStoreManager);
            identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                    .thenReturn(identityKeyStoreResolver);

            DIDDocument document = provider.getDIDDocument(-1234, "https://example.com");
            Assert.assertNotNull(document);
            Assert.assertEquals(document.getId(), "did:web:example.com");
            Assert.assertNotNull(document.getVerificationMethod());
            Assert.assertFalse(document.getVerificationMethod().isEmpty());
            Assert.assertNotNull(document.getVerificationMethod().get(0).getPublicKeyMultibase());
        }
    }
}
