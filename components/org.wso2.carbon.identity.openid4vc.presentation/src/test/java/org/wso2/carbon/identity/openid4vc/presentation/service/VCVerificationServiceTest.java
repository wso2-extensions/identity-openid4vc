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

package org.wso2.carbon.identity.openid4vc.presentation.service;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VCVerificationResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.CredentialVerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.model.VCVerificationStatus;
import org.wso2.carbon.identity.openid4vc.presentation.model.VerifiableCredential;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.VCVerificationServiceImpl;

import java.util.Date;

/**
 * Unit tests for VCVerificationService.
 */
public class VCVerificationServiceTest {

    private VCVerificationService vcVerificationService;

    @BeforeMethod
    public void setUp() {
        vcVerificationService = new VCVerificationServiceImpl();
    }

    @Test
    public void testParseJsonLdCredential() throws CredentialVerificationException {
        // Arrange
        String vcJson = "{\n" +
                "  \"@context\": [\n" +
                "    \"https://www.w3.org/2018/credentials/v1\",\n" +
                "    \"https://www.w3.org/2018/credentials/examples/v1\"\n" +
                "  ],\n" +
                "  \"id\": \"http://example.edu/credentials/3732\",\n" +
                "  \"type\": [\"VerifiableCredential\", \"UniversityDegreeCredential\"],\n" +
                "  \"issuer\": \"did:example:issuer123\",\n" +
                "  \"issuanceDate\": \"2024-01-01T00:00:00Z\",\n" +
                "  \"expirationDate\": \"2030-01-01T00:00:00Z\",\n" +
                "  \"credentialSubject\": {\n" +
                "    \"id\": \"did:example:holder456\",\n" +
                "    \"degree\": {\n" +
                "      \"type\": \"BachelorDegree\",\n" +
                "      \"name\": \"Bachelor of Science\"\n" +
                "    }\n" +
                "  }\n" +
                "}";

        // Act
        VerifiableCredential vc = vcVerificationService.parseCredential(vcJson, "application/vc+ld+json");

        // Assert
        Assert.assertNotNull(vc);
        Assert.assertEquals(vc.getId(), "http://example.edu/credentials/3732");
        Assert.assertEquals(vc.getIssuer(), "did:example:issuer123");
        Assert.assertNotNull(vc.getType());
        Assert.assertTrue(vc.getType().contains("VerifiableCredential"));
        Assert.assertTrue(vc.getType().contains("UniversityDegreeCredential"));
    }

    @Test
    public void testParseJwtCredential() throws CredentialVerificationException {
        // Arrange - A minimal JWT VC (header.payload.signature)
        // This is a simplified test JWT - in real scenarios the JWT would have proper signatures
        String header = base64UrlEncode("{\"alg\":\"ES256\",\"typ\":\"JWT\"}");
        String payload = base64UrlEncode("{\n" +
                "  \"iss\": \"did:example:issuer123\",\n" +
                "  \"sub\": \"did:example:holder456\",\n" +
                "  \"iat\": 1704067200,\n" +
                "  \"exp\": 1893456000,\n" +
                "  \"vc\": {\n" +
                "    \"@context\": [\"https://www.w3.org/2018/credentials/v1\"],\n" +
                "    \"type\": [\"VerifiableCredential\", \"TestCredential\"],\n" +
                "    \"credentialSubject\": {\n" +
                "      \"id\": \"did:example:holder456\",\n" +
                "      \"name\": \"Test User\"\n" +
                "    }\n" +
                "  }\n" +
                "}");
        String signature = base64UrlEncode("test-signature");
        String jwtVc = header + "." + payload + "." + signature;

        // Act
        VerifiableCredential vc = vcVerificationService.parseCredential(jwtVc, "application/jwt");

        // Assert
        Assert.assertNotNull(vc);
        Assert.assertEquals(vc.getIssuer(), "did:example:issuer123");
        Assert.assertNotNull(vc.getType());
    }

    @Test
    public void testIsExpiredWithFutureDate() {
        // Arrange
        VerifiableCredential vc = new VerifiableCredential();
        vc.setExpirationDate(new Date(System.currentTimeMillis() + 86400000)); // Tomorrow

        // Act
        boolean expired = vcVerificationService.isExpired(vc);

        // Assert
        Assert.assertFalse(expired);
    }

    @Test
    public void testIsExpiredWithPastDate() {
        // Arrange
        VerifiableCredential vc = new VerifiableCredential();
        vc.setExpirationDate(new Date(System.currentTimeMillis() - 86400000)); // Yesterday

        // Act
        boolean expired = vcVerificationService.isExpired(vc);

        // Assert
        Assert.assertTrue(expired);
    }

    @Test
    public void testIsExpiredWithNoDate() {
        // Arrange
        VerifiableCredential vc = new VerifiableCredential();
        vc.setExpirationDate(null);

        // Act
        boolean expired = vcVerificationService.isExpired(vc);

        // Assert
        Assert.assertFalse(expired, "Credential without expiration should not be expired");
    }

    @Test
    public void testVerifyWithExpiredCredential() throws CredentialVerificationException {
        // Arrange
        String vcJson = "{\n" +
                "  \"@context\": [\"https://www.w3.org/2018/credentials/v1\"],\n" +
                "  \"id\": \"http://example.edu/credentials/expired\",\n" +
                "  \"type\": [\"VerifiableCredential\"],\n" +
                "  \"issuer\": \"did:example:issuer\",\n" +
                "  \"issuanceDate\": \"2020-01-01T00:00:00Z\",\n" +
                "  \"expirationDate\": \"2020-12-31T23:59:59Z\",\n" +
                "  \"credentialSubject\": { \"id\": \"did:example:holder\" }\n" +
                "}";

        // Act
        VCVerificationResultDTO result = vcVerificationService.verify(vcJson, "application/vc+ld+json");

        // Assert
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getVerificationStatus(), VCVerificationStatus.EXPIRED);
    }

    @Test(expectedExceptions = CredentialVerificationException.class)
    public void testParseInvalidJson() throws CredentialVerificationException {
        // Arrange
        String invalidJson = "{ invalid json }";

        // Act - should throw exception
        vcVerificationService.parseCredential(invalidJson, "application/vc+ld+json");
    }

    @Test(expectedExceptions = CredentialVerificationException.class)
    public void testParseNullCredential() throws CredentialVerificationException {
        // Act - should throw exception
        vcVerificationService.parseCredential(null, "application/vc+ld+json");
    }

    @Test(expectedExceptions = CredentialVerificationException.class)
    public void testParseEmptyCredential() throws CredentialVerificationException {
        // Act - should throw exception
        vcVerificationService.parseCredential("", "application/vc+ld+json");
    }

    @Test
    public void testAutoDetectJwtFormat() throws CredentialVerificationException {
        // Arrange - JWT without explicit content type
        String header = base64UrlEncode("{\"alg\":\"ES256\",\"typ\":\"JWT\"}");
        String payload = base64UrlEncode("{\"iss\":\"did:example:issuer\",\"vc\":{\"type\":[\"VerifiableCredential\"],\"credentialSubject\":{}}}");
        String signature = base64UrlEncode("sig");
        String jwt = header + "." + payload + "." + signature;

        // Act - should auto-detect JWT format
        VerifiableCredential vc = vcVerificationService.parseCredential(jwt, null);

        // Assert
        Assert.assertNotNull(vc);
    }

    @Test
    public void testAutoDetectJsonLdFormat() throws CredentialVerificationException {
        // Arrange - JSON-LD without explicit content type
        String vcJson = "{\n" +
                "  \"@context\": [\"https://www.w3.org/2018/credentials/v1\"],\n" +
                "  \"type\": [\"VerifiableCredential\"],\n" +
                "  \"issuer\": \"did:example:issuer\",\n" +
                "  \"credentialSubject\": {}\n" +
                "}";

        // Act - should auto-detect JSON-LD format
        VerifiableCredential vc = vcVerificationService.parseCredential(vcJson, null);

        // Assert
        Assert.assertNotNull(vc);
    }

    // Helper method for base64url encoding
    private String base64UrlEncode(String input) {
        return java.util.Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
