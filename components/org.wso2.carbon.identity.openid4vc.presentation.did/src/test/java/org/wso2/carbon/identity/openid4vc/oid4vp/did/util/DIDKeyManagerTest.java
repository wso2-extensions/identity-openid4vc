package org.wso2.carbon.identity.openid4vc.oid4vp.did.util;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.KeyStoreManager;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for DIDKeyManager.
 */
public class DIDKeyManagerTest {

    @org.testng.annotations.BeforeClass
    public void setupSystemProperties() {
        System.setProperty("carbon.home", ".");
    }

    @AfterMethod
    public void tearDown() {
        // Clear caches to avoid interference between tests
        DIDKeyManager.removeKeys(-1234);
    }

    @Test
    public void testBase58Encode() throws Exception {
        byte[] input = "Hello World".getBytes(StandardCharsets.UTF_8);
        String encoded = invokeBase58Encode(input);
        Assert.assertEquals(encoded, "JxF12TrwUP45BMd", "Base58 encoding failed");
    }

    @Test
    public void testBase58Decode() {
        String input = "JxF12TrwUP45BMd";
        byte[] decoded = DIDKeyManager.base58Decode(input);
        Assert.assertEquals(new String(decoded, StandardCharsets.UTF_8), "Hello World", "Base58 decoding failed");
    }

    @Test
    public void testBase58EncodeEmpty() throws Exception {
        Assert.assertEquals(invokeBase58Encode(new byte[0]), "");
    }

    @Test
    public void testBase58DecodeEmpty() {
        Assert.assertEquals(DIDKeyManager.base58Decode("").length, 0);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testBase58DecodeInvalidChar() {
        DIDKeyManager.base58Decode("0OIl"); // 0, O, I, l are not in Bitcoin alphabet
    }

    @Test
    public void testPublicKeyToMultibaseEd25519() {
        Base64URL x = new Base64URL("11qYAYKxG9W_pX997C6j49VfU-H3-XEcE4y9L3j-_N0");
        OctetKeyPair keyPair = new OctetKeyPair.Builder(Curve.Ed25519, x).build();
        String multibase = DIDKeyManager.publicKeyToMultibase(keyPair);
        Assert.assertNotNull(multibase);
        Assert.assertTrue(multibase.startsWith("z6Mk"), "Ed25519 multibase should start with z6Mk");
    }


    @Test
    public void testGetOrGenerateKeyPairFromKeyStore() throws Exception {
        int tenantId = -1234;
        String alias = "wso2carbon_ed";
        
        try (MockedStatic<KeyStoreManager> mockedKeyStoreManager = Mockito.mockStatic(KeyStoreManager.class)) {
            KeyStoreManager keyStoreManager = mock(KeyStoreManager.class);
            mockedKeyStoreManager.when(() -> KeyStoreManager.getInstance(tenantId)).thenReturn(keyStoreManager);
            
            PublicKey publicKey = mock(PublicKey.class);
            PrivateKey privateKey = mock(PrivateKey.class);
            
            byte[] encodedPub = new byte[44]; 
            byte[] encodedPriv = new byte[48];
            when(publicKey.getEncoded()).thenReturn(encodedPub);
            when(privateKey.getEncoded()).thenReturn(encodedPriv);
            
            when(keyStoreManager.getDefaultPublicKey(alias)).thenReturn(publicKey);
            when(keyStoreManager.getDefaultPrivateKey(alias)).thenReturn(privateKey);
            
            OctetKeyPair keyPair = DIDKeyManager.getOrGenerateKeyPair(tenantId);
            Assert.assertNotNull(keyPair);
            Assert.assertEquals(keyPair.getCurve(), Curve.Ed25519);
        }
    }


    @Test
    public void testGenerateDIDKeyByTenantId() throws Exception {
        int tenantId = -1234;
        String alias = "wso2carbon_ed";
        
        try (MockedStatic<KeyStoreManager> mockedKeyStoreManager = Mockito.mockStatic(KeyStoreManager.class)) {
            KeyStoreManager keyStoreManager = mock(KeyStoreManager.class);
            mockedKeyStoreManager.when(() -> KeyStoreManager.getInstance(tenantId)).thenReturn(keyStoreManager);
            
            PublicKey publicKey = mock(PublicKey.class);
            PrivateKey privateKey = mock(PrivateKey.class);
            when(publicKey.getEncoded()).thenReturn(new byte[44]);
            when(privateKey.getEncoded()).thenReturn(new byte[48]);
            
            when(keyStoreManager.getDefaultPublicKey(alias)).thenReturn(publicKey);
            when(keyStoreManager.getDefaultPrivateKey(alias)).thenReturn(privateKey);
            
            String didKey = DIDKeyManager.generateDIDKey(tenantId);
            Assert.assertTrue(didKey.startsWith("did:key:z6Mk"));
        }
    }

    @Test
    public void testGenerateDIDKeyEd25519() {
        Base64URL x = new Base64URL("11qYAYKxG9W_pX997C6j49VfU-H3-XEcE4y9L3j-_N0");
        OctetKeyPair keyPair = new OctetKeyPair.Builder(Curve.Ed25519, x).build();
        String didKey = DIDKeyManager.generateDIDKey(keyPair);
        Assert.assertTrue(didKey.startsWith("did:key:z6Mk"));
    }

    @Test
    public void testExtractPublicKeyFromDIDKey() {
        String didKey = "did:key:z6Mkqv2q_test_key_placeholder"; // This will fail multicodec check if not valid
        // Let's use a real one generated above
        Base64URL x = new Base64URL("11qYAYKxG9W_pX997C6j49VfU-H3-XEcE4y9L3j-_N0");
        OctetKeyPair keyPair = new OctetKeyPair.Builder(Curve.Ed25519, x).build();
        String realDidKey = DIDKeyManager.generateDIDKey(keyPair);
        
        byte[] extractedX = DIDKeyManager.extractPublicKeyFromDIDKey(realDidKey);
        Assert.assertEquals(Base64URL.encode(extractedX), x);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testExtractPublicKeyFromInvalidDIDKey() {
        DIDKeyManager.extractPublicKeyFromDIDKey("did:key:abc");
    }

    @Test
    public void testPublicKeyToJwkMap() {
        Base64URL x = new Base64URL("11qYAYKxG9W_pX997C6j49VfU-H3-XEcE4y9L3j-_N0");
        OctetKeyPair keyPair = new OctetKeyPair.Builder(Curve.Ed25519, x).build();
        java.util.Map<String, Object> jwkMap = DIDKeyManager.publicKeyToJwkMap(keyPair);
        Assert.assertEquals(jwkMap.get("kty"), "OKP");
        Assert.assertEquals(jwkMap.get("crv"), "Ed25519");
        Assert.assertEquals(jwkMap.get("x"), x.toString());
    }

    @Test
    public void testGetEdDSAKeyAlias() throws Exception {
        // Test Super Tenant
        // Use a different mock scope or just call it if it doesn't need PCC
        String alias = DIDKeyManager.getEdDSAKeyAlias(-1234);
        Assert.assertEquals(alias, "wso2carbon_ed");

        // Test Tenant
        try (MockedStatic<PrivilegedCarbonContext> mockedPrivilegedCarbonContext = 
                Mockito.mockStatic(PrivilegedCarbonContext.class)) {
            PrivilegedCarbonContext context = mock(PrivilegedCarbonContext.class);
            mockedPrivilegedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(context);
            when(context.getTenantDomain()).thenReturn("test.com");

            String tenantAlias = DIDKeyManager.getEdDSAKeyAlias(1);
            Assert.assertEquals(tenantAlias, "test.com_ed");
        }
    }

    // Helper to invoke private base58Encode via reflection
    private String invokeBase58Encode(byte[] input) throws Exception {
        java.lang.reflect.Method method = DIDKeyManager.class.getDeclaredMethod("base58Encode", byte[].class);
        method.setAccessible(true);
        return (String) method.invoke(null, (Object) input);
    }
}
