package org.wso2.carbon.identity.openid4vc.presentation.did.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Unit tests for BCEd25519Signer.
 */
public class BCEd25519SignerTest {

    private OctetKeyPair keyPair;
    private BCEd25519Signer signer;

    @BeforeMethod
    public void setUp() throws Exception {
        // Generate a new Ed25519 key pair using Bouncy Castle
        Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = keyPairGenerator.generateKeyPair();
        
        Ed25519PrivateKeyParameters privateKeyParams = (Ed25519PrivateKeyParameters) kp.getPrivate();
        Ed25519PublicKeyParameters publicKeyParams = (Ed25519PublicKeyParameters) kp.getPublic();
        
        Base64URL d = Base64URL.encode(privateKeyParams.getEncoded());
        Base64URL x = Base64URL.encode(publicKeyParams.getEncoded());
        
        keyPair = new OctetKeyPair.Builder(Curve.Ed25519, x).d(d).build();
        signer = new BCEd25519Signer(keyPair);
    }

    @Test
    public void testSign() throws Exception {
        String payload = "Hello, world!";
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).build();

        Base64URL signature = signer.sign(header, payloadBytes);
        Assert.assertNotNull(signature);

        // Verify with Bouncy Castle directly (since Nimbus Ed25519Verifier depends on Tink)
        org.bouncycastle.crypto.signers.Ed25519Signer bcVerifier = new org.bouncycastle.crypto.signers.Ed25519Signer();
        byte[] publicKeyBytes = keyPair.getX().decode();
        bcVerifier.init(false, new Ed25519PublicKeyParameters(publicKeyBytes, 0));
        bcVerifier.update(payloadBytes, 0, payloadBytes.length);
        Assert.assertTrue(bcVerifier.verifySignature(signature.decode()), "Signature should be valid");
    }

    @Test(expectedExceptions = JOSEException.class)
    public void testConstructorWithWrongKeyType() throws Exception {
        // Use Builder to create a wrong key type without triggering generator
        OctetKeyPair wrongKey = new OctetKeyPair.Builder(Curve.X25519, Base64URL.encode(new byte[32]))
                .d(Base64URL.encode(new byte[32]))
                .build();
        new BCEd25519Signer(wrongKey);
    }

    @Test(expectedExceptions = JOSEException.class)
    public void testConstructorWithMissingD() throws Exception {
        OctetKeyPair publicOnly = keyPair.toPublicJWK();
        new BCEd25519Signer(publicOnly);
    }

    @Test(expectedExceptions = JOSEException.class)
    public void testSignWithUnsupportedAlgorithm() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
        signer.sign(header, "test".getBytes());
    }

    @Test
    public void testSupportedAlgorithms() {
        Assert.assertTrue(signer.supportedJWSAlgorithms().contains(JWSAlgorithm.EdDSA));
        Assert.assertEquals(signer.supportedJWSAlgorithms().size(), 1);
    }

    @Test
    public void testJCAContext() {
        Assert.assertNotNull(signer.getJCAContext());
    }
}
