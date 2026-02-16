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

package org.wso2.carbon.identity.openid4vc.issuance.credential.validators.proof.impl;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.openid4vc.issuance.credential.dto.ProofDTO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.internal.CredentialIssuanceDataHolder;
import org.wso2.carbon.identity.openid4vc.issuance.credential.nonce.NonceService;
import org.wso2.carbon.identity.openid4vc.issuance.credential.validators.proof.ProofValidator;

import java.lang.reflect.Field;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.JWT_PROOF_TYPE;

/**
 * Unit tests for {@link JwtProofValidator}.
 */
public class JwtProofValidatorTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String CREDENTIAL_ISSUER_URL = "https://localhost:9443/oid4vci";
    private JwtProofValidator validator;
    private NonceService mockNonceService;
    private MockedStatic<ServiceURLBuilder> serviceUrlBuilderMockedStatic;

    @BeforeMethod
    public void setUp() throws Exception {

        validator = new JwtProofValidator();
        mockNonceService = mock(NonceService.class);

        // Inject mock NonceService using reflection
        Field nonceServiceField = JwtProofValidator.class.getDeclaredField("nonceService");
        nonceServiceField.setAccessible(true);
        nonceServiceField.set(validator, mockNonceService);

        CredentialIssuanceDataHolder.getInstance().getProofValidators().clear();

        // Mock ServiceURLBuilder for credential issuer URL
        serviceUrlBuilderMockedStatic = mockServiceUrlBuilder();
    }

    @AfterMethod
    public void tearDown() {

        if (serviceUrlBuilderMockedStatic != null) {
            serviceUrlBuilderMockedStatic.close();
            serviceUrlBuilderMockedStatic = null;
        }
    }

    private MockedStatic<ServiceURLBuilder> mockServiceUrlBuilder() throws Exception {

        ServiceURL serviceURL = mock(ServiceURL.class);
        when(serviceURL.getAbsolutePublicURL()).thenReturn(CREDENTIAL_ISSUER_URL);

        MockedStatic<ServiceURLBuilder> mockedServiceURLBuilder = mockStatic(ServiceURLBuilder.class);
        ServiceURLBuilder mockBuilder = mock(ServiceURLBuilder.class);

        mockedServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockBuilder);
        when(mockBuilder.addPath(any(String[].class))).thenReturn(mockBuilder);
        when(mockBuilder.setTenant(anyString())).thenReturn(mockBuilder);
        when(mockBuilder.addParameter(any(), any())).thenReturn(mockBuilder);
        when(mockBuilder.build()).thenReturn(serviceURL);

        return mockedServiceURLBuilder;
    }

    @Test(description = "Test DataHolder proof validator operations and ProofDTO state")
    public void testProofDataHolderAndDTOState() {

        ProofDTO proofDTO = new ProofDTO();
        proofDTO.setType("jwt");
        proofDTO.setProofs(Collections.singletonList("proof-jwt"));
        proofDTO.setPublicKey(Collections.singletonMap("kty", "RSA"));
        proofDTO.setKeyId("kid-1");
        proofDTO.setIssuedAt(1735689600L);
        proofDTO.setNonce("nonce-123");

        Assert.assertEquals(proofDTO.getType(), "jwt");
        Assert.assertEquals(proofDTO.getProofs(), Collections.singletonList("proof-jwt"));
        Assert.assertEquals(proofDTO.getPublicKey().get("kty"), "RSA");
        Assert.assertEquals(proofDTO.getKeyId(), "kid-1");
        Assert.assertEquals(proofDTO.getIssuedAt(), 1735689600L);
        Assert.assertEquals(proofDTO.getNonce(), "nonce-123");

        CredentialIssuanceDataHolder dataHolder = CredentialIssuanceDataHolder.getInstance();
        ProofValidator proofValidator = new JwtProofValidator();
        dataHolder.addProofValidator(proofValidator);

        Assert.assertEquals(dataHolder.getProofValidators().size(), 1);
        Assert.assertEquals(dataHolder.getProofValidators().get(0).getType(), "jwt");

        dataHolder.removeProofValidator(proofValidator);
        Assert.assertTrue(dataHolder.getProofValidators().isEmpty());
    }

    @Test(description = "Test validation failure when proofs array is empty")
    public void testValidateProofWithEmptyProofList() {

        ProofDTO proofDTO = new ProofDTO();
        proofDTO.setType("jwt");
        proofDTO.setProofs(Collections.emptyList());

        try {
            validator.validateProof(proofDTO, TENANT_DOMAIN);
            Assert.fail("Expected CredentialIssuanceException for empty proof list");
        } catch (CredentialIssuanceException e) {
            Assert.assertTrue(e.getMessage().contains("JWT proof is required"));
        }
    }

    @Test(description = "Test validation failure when multiple proofs are provided")
    public void testValidateProofWithMultipleProofs() {

        ProofDTO proofDTO = new ProofDTO();
        proofDTO.setType("jwt");
        proofDTO.setProofs(Arrays.asList("proof-1", "proof-2"));

        try {
            validator.validateProof(proofDTO, TENANT_DOMAIN);
            Assert.fail("Expected CredentialIssuanceException for multiple proofs");
        } catch (CredentialIssuanceException e) {
            Assert.assertTrue(e.getMessage().contains("Multiple proofs not supported"));
        }
    }

    @Test(description = "Test validation failure for malformed JWT proof")
    public void testValidateProofWithMalformedJwt() {

        ProofDTO proofDTO = new ProofDTO();
        proofDTO.setType("jwt");
        proofDTO.setProofs(Collections.singletonList("invalid.jwt.value"));

        try {
            validator.validateProof(proofDTO, TENANT_DOMAIN);
            Assert.fail("Expected CredentialIssuanceException for malformed JWT");
        } catch (CredentialIssuanceException e) {
            Assert.assertTrue(e.getMessage().contains("Invalid JWT proof format"));
        }
    }

    @Test(description = "Test validation failure when typ header is missing")
    public void testValidateProofWithMissingTypHeader() throws Exception {

        String jwtWithoutTyp = createRS256Jwt(null, false, null);

        ProofDTO proofDTO = new ProofDTO();
        proofDTO.setType("jwt");
        proofDTO.setProofs(Collections.singletonList(jwtWithoutTyp));

        try {
            validator.validateProof(proofDTO, TENANT_DOMAIN);
            Assert.fail("Expected CredentialIssuanceException for missing typ");
        } catch (CredentialIssuanceException e) {
            Assert.assertTrue(e.getMessage().contains("Missing typ header"));
        }
    }

    @Test(description = "Test validation failure for unsupported key type")
    public void testValidateProofWithUnsupportedKeyType() throws Exception {

        String unsupportedKeyTypeJwt = createJwtWithUnsupportedHeaderKeyType();

        ProofDTO proofDTO = new ProofDTO();
        proofDTO.setType("jwt");
        proofDTO.setProofs(Collections.singletonList(unsupportedKeyTypeJwt));

        try {
            validator.validateProof(proofDTO, TENANT_DOMAIN);
            Assert.fail("Expected CredentialIssuanceException for unsupported key type");
        } catch (CredentialIssuanceException e) {
            Assert.assertTrue(e.getMessage().contains("Unsupported key type"));
        }
    }

    @Test(description = "Test validation failure when aud claim is missing")
    public void testValidateProofWithMissingAudienceClaim() throws Exception {

        String jwtWithoutAudience = createRS256Jwt(new JOSEObjectType(JWT_PROOF_TYPE), false, null);

        ProofDTO proofDTO = new ProofDTO();
        proofDTO.setType("jwt");
        proofDTO.setProofs(Collections.singletonList(jwtWithoutAudience));

        try {
            validator.validateProof(proofDTO, TENANT_DOMAIN);
            Assert.fail("Expected CredentialIssuanceException for missing aud claim");
        } catch (CredentialIssuanceException e) {
            Assert.assertTrue(e.getMessage().contains("Missing aud claim"));
        }
    }

    @Test(description = "Test validation failure when nonce claim is missing")
    public void testValidateProofWithMissingNonce() throws Exception {

        String jwtWithoutNonce = createRS256Jwt(new JOSEObjectType(JWT_PROOF_TYPE), true, null);

        ProofDTO proofDTO = new ProofDTO();
        proofDTO.setType("jwt");
        proofDTO.setProofs(Collections.singletonList(jwtWithoutNonce));

        try {
            validator.validateProof(proofDTO, TENANT_DOMAIN);
            Assert.fail("Expected CredentialIssuanceException for missing nonce");
        } catch (CredentialIssuanceException e) {
            Assert.assertTrue(e.getMessage().contains("Missing nonce claim") ||
                            e.getMessage().contains("nonce"),
                    "Exception should indicate missing nonce. Actual: " + e.getMessage());
        }
    }

    @Test(description = "Test validation failure when nonce is invalid or expired")
    public void testValidateProofWithInvalidNonce() throws Exception {

        String invalidNonce = "invalid-nonce-value";
        String jwtWithInvalidNonce = createRS256Jwt(new JOSEObjectType(JWT_PROOF_TYPE), true, invalidNonce);

        // Mock nonceService to return false (invalid nonce)
        when(mockNonceService.validateAndConsumeNonce(invalidNonce, TENANT_DOMAIN)).thenReturn(false);

        ProofDTO proofDTO = new ProofDTO();
        proofDTO.setType("jwt");
        proofDTO.setProofs(Collections.singletonList(jwtWithInvalidNonce));

        try {
            validator.validateProof(proofDTO, TENANT_DOMAIN);
            Assert.fail("Expected CredentialIssuanceException for invalid nonce");
        } catch (CredentialIssuanceException e) {
            Assert.assertTrue(e.getMessage().contains("Invalid") || e.getMessage().contains("expired"),
                    "Exception should indicate invalid or expired nonce. Actual: " + e.getMessage());
        }
    }

    @Test(description = "Test successful proof validation with valid nonce")
    public void testValidateProofWithValidNonce() throws Exception {

        String validNonce = "valid-nonce-value";
        String jwtWithValidNonce = createRS256Jwt(new JOSEObjectType(JWT_PROOF_TYPE), true, validNonce);

        // Mock nonceService to return true (valid nonce)
        when(mockNonceService.validateAndConsumeNonce(validNonce, TENANT_DOMAIN)).thenReturn(true);

        ProofDTO proofDTO = new ProofDTO();
        proofDTO.setType("jwt");
        proofDTO.setProofs(Collections.singletonList(jwtWithValidNonce));

        // Should not throw exception
        validator.validateProof(proofDTO, TENANT_DOMAIN);

        // Verify public key was extracted
        Assert.assertNotNull(proofDTO.getPublicKey(), "Public key should be extracted from proof");
        Assert.assertEquals(proofDTO.getNonce(), validNonce, "Nonce should be set in proofDTO");
    }

    private String createRS256Jwt(JOSEObjectType typ, boolean withAudience, String nonce) throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .keyID("rsa-key-1")
                .build();

        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256).jwk(rsaKey);
        if (typ != null) {
            headerBuilder.type(typ);
        }

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issueTime(new Date());
        if (withAudience) {
            claimsBuilder.audience(CREDENTIAL_ISSUER_URL);
        }
        if (nonce != null) {
            claimsBuilder.claim("nonce", nonce);
        }

        SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), claimsBuilder.build());
        JWSSigner signer = new RSASSASigner(keyPair.getPrivate());
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private String createJwtWithUnsupportedHeaderKeyType() throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        OctetKeyPair okpKey = new OctetKeyPair.Builder(
                Curve.Ed25519, Base64URL.encode(new byte[32]))
                .keyID("okp-key-1")
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType(JWT_PROOF_TYPE))
                .jwk(okpKey)
                .build();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issueTime(new Date())
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new RSASSASigner(keyPair.getPrivate()));
        return signedJWT.serialize();
    }
}
