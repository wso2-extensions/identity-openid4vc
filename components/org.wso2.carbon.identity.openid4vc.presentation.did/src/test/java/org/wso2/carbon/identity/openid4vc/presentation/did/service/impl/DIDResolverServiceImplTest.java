package org.wso2.carbon.identity.openid4vc.presentation.did.service.impl;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.DIDResolutionException;
import org.wso2.carbon.identity.openid4vc.presentation.common.model.DIDDocument;
import org.wso2.carbon.identity.openid4vc.presentation.did.util.DIDKeyManager;

import java.security.PublicKey;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

/**
 * Unit tests for DIDResolverServiceImpl.
 */
public class DIDResolverServiceImplTest {

    private DIDResolverServiceImpl resolver;

    @BeforeClass
    public void setupSystemProperties() {
        System.setProperty("carbon.home", ".");
    }

    @BeforeMethod
    public void setUp() {
        resolver = new DIDResolverServiceImpl();
    }

    @Test
    public void testResolveDidKey() throws Exception {
        // Construct a real Ed25519 multibase string
        // Prefix 0xed01 (little endian bytes 0x01, 0xed) + 32 bytes of public key
        byte[] keyBytes = new byte[34];
        keyBytes[0] = (byte) 0xed;
        keyBytes[1] = (byte) 0x01;
        // The implementation uses: (decoded[0] & 0xFF) | ((decoded[1] & 0xFF) << 8)
        // To get 0xed01: decoded[0] = 0x01, decoded[1] = 0xed
        keyBytes[0] = (byte) 0x01;
        keyBytes[1] = (byte) 0xed;
        
        java.util.Arrays.fill(keyBytes, 2, 34, (byte) 0xFF);
        String multibase = "z" + DIDKeyManager.base58Encode(keyBytes);
        String did = "did:key:" + multibase;
        
        DIDDocument doc = resolver.resolve(did);
        Assert.assertNotNull(doc);
        Assert.assertEquals(doc.getId(), did);
        Assert.assertEquals(doc.getVerificationMethod().get(0).getType(), "Ed25519VerificationKey2020");
    }

    @Test
    public void testResolveDidJwk() throws Exception {
        // did:jwk:<base64url-encoded-jwk>
        String jwkJson = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxG9W_pX997C6j49VfU-H3-XEcE4y9L3j-_N0\"}";
        String b64Jwk = com.nimbusds.jose.util.Base64URL.encode(jwkJson).toString();
        String did = "did:jwk:" + b64Jwk;

        DIDDocument doc = resolver.resolve(did);
        Assert.assertNotNull(doc);
        Assert.assertEquals(doc.getId(), did);
        Assert.assertEquals(doc.getVerificationMethod().get(0).getType(), "JsonWebKey2020");
    }

    @Test
    public void testResolveDidWeb() throws Exception {
        String did = "did:web:example.com";
        String mockResponse = "{\"id\":\"did:web:example.com\",\"verificationMethod\":[{\"id\":\"" +
                "did:web:example.com#key-1\",\"type\":\"Ed25519VerificationKey2020\",\"controller\":\"" +
                "did:web:example.com\",\"publicKeyMultibase\":\"" +
                "z6MkpTHR8VNsBxYRrBcrSthuyT77S9J94DA8vyidbMHWf4id\"}]}";
        
        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(mockResponse).when(spyResolver).fetchUrl(anyString());
        
        DIDDocument doc = spyResolver.resolve(did);
        Assert.assertNotNull(doc);
        Assert.assertEquals(doc.getId(), did);
        Assert.assertFalse(doc.getVerificationMethod().isEmpty());
    }

    @Test
    public void testResolveDidWebWithPath() throws Exception {
        String did = "did:web:example.com:user:alice";
        String mockResponse = "{\"id\":\"did:web:example.com:user:alice\"}";
        
        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(mockResponse).when(spyResolver).fetchUrl("https://example.com/user/alice/did.json");
        
        DIDDocument doc = spyResolver.resolve(did);
        Assert.assertNotNull(doc);
    }

    @Test(expectedExceptions = DIDResolutionException.class)
    public void testResolveInvalidDid() throws Exception {
        resolver.resolve("invalid-did");
    }

    @Test(expectedExceptions = DIDResolutionException.class)
    public void testResolveUnsupportedMethod() throws Exception {
        resolver.resolve("did:unknown:123");
    }

    @Test
    public void testGetPublicKey() throws Exception {
        String did = "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjExcVlBWUt4RzlXX3BYOTk3" +
                "QzZqNDlWZlUtSDMtWEVFRTR5OUwzai1fTjAifQ";
        PublicKey publicKey = resolver.getPublicKey(did, null);
        Assert.assertNotNull(publicKey);
        Assert.assertEquals(publicKey.getAlgorithm(), "Ed25519");
    }

    @Test
    public void testCache() throws Exception {
        String did = "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjExcVlBWUt4RzlXX3BYOTk3" +
                "QzZqNDlWZlUtSDMtWEVFRTR5OUwzai1fTjAifQ";
        DIDDocument doc1 = resolver.resolve(did, true);
        DIDDocument doc2 = resolver.resolve(did, true);
        Assert.assertSame(doc1, doc2, "Documents should be the same instance due to caching");
        
        resolver.clearCache(did);
        DIDDocument doc3 = resolver.resolve(did, true);
        Assert.assertNotSame(doc1, doc3, "Document should be re-resolved after cache clear");
    }
}
