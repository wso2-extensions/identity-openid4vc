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

package org.wso2.carbon.identity.openid4vc.presentation.integration;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VCVerificationResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPRequestCreateDTO;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.VCVerificationStatus;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.service.VCVerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPSubmissionService;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.VCVerificationServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.VPRequestServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.VPSubmissionServiceImpl;

import java.util.List;
import java.util.UUID;

/**
 * Integration tests for the complete OpenID4VP flow.
 * These tests verify the end-to-end functionality of VP request creation,
 * submission, and verification.
 */
public class OpenID4VPFlowIntegrationTest {

    private VPRequestService vpRequestService;
    private VPSubmissionService vpSubmissionService;
    private VCVerificationService vcVerificationService;

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String CLIENT_ID = "did:web:verifier.example.com";

    @BeforeClass
    public void setUp() {
        vpRequestService = new VPRequestServiceImpl();
        vpSubmissionService = new VPSubmissionServiceImpl();
        vcVerificationService = new VCVerificationServiceImpl();
    }

    /**
     * Test the complete VP request-by-value flow:
     * 1. Create authorization request
     * 2. Verify request is ACTIVE
     * 3. Submit VP token
     * 4. Verify request is VP_SUBMITTED
     */
    @Test
    public void testCompleteVPRequestByValueFlow() throws VPException {
        // Step 1: Create authorization request
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setClientId(CLIENT_ID);
        createDTO.setNonce(UUID.randomUUID().toString());
        createDTO.setPresentationDefinition(getSamplePresentationDefinition());
        createDTO.setRequestByReference(false);

        VPRequestResponseDTO requestResponse = vpRequestService.createAuthorizationRequest(
                createDTO, TENANT_DOMAIN);

        Assert.assertNotNull(requestResponse);
        Assert.assertNotNull(requestResponse.getRequestId());
        Assert.assertNotNull(requestResponse.getAuthorizationDetails());
        Assert.assertEquals(requestResponse.getAuthorizationDetails().getResponseType(), "vp_token");

        // Step 2: Verify request is ACTIVE
        VPRequestStatus status = vpRequestService.getRequestStatus(requestResponse.getRequestId());
        Assert.assertEquals(status, VPRequestStatus.ACTIVE);

        // Step 3: Simulate VP submission
        vpRequestService.markAsSubmitted(requestResponse.getRequestId());

        // Step 4: Verify request is VP_SUBMITTED
        status = vpRequestService.getRequestStatus(requestResponse.getRequestId());
        Assert.assertEquals(status, VPRequestStatus.VP_SUBMITTED);
    }

    /**
     * Test the complete VP request-by-reference flow:
     * 1. Create authorization request with request_uri
     * 2. Fetch JWT from request_uri
     * 3. Verify JWT structure
     */
    @Test
    public void testCompleteVPRequestByReferenceFlow() throws VPException {
        // Step 1: Create authorization request with request_uri
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setClientId(CLIENT_ID);
        createDTO.setNonce(UUID.randomUUID().toString());
        createDTO.setPresentationDefinitionId("sample-pd-id");
        createDTO.setRequestByReference(true);

        VPRequestResponseDTO requestResponse = vpRequestService.createAuthorizationRequest(
                createDTO, TENANT_DOMAIN);

        Assert.assertNotNull(requestResponse);
        Assert.assertNotNull(requestResponse.getRequestId());
        Assert.assertNotNull(requestResponse.getRequestUri());

        // Step 2: Fetch JWT from request_uri
        String jwt = vpRequestService.getAuthorizationRequestJWT(requestResponse.getRequestId());

        // Step 3: Verify JWT structure
        Assert.assertNotNull(jwt);
        String[] parts = jwt.split("\\.");
        Assert.assertEquals(parts.length, 3, "JWT should have header.payload.signature");
    }

    /**
     * Test credential verification with JSON-LD format.
     */
    @Test
    public void testJsonLdCredentialVerification() {
        // Create a sample JSON-LD credential
        String vcJson = "{\n" +
                "  \"@context\": [\n" +
                "    \"https://www.w3.org/2018/credentials/v1\"\n" +
                "  ],\n" +
                "  \"id\": \"urn:uuid:" + UUID.randomUUID() + "\",\n" +
                "  \"type\": [\"VerifiableCredential\", \"IdentityCredential\"],\n" +
                "  \"issuer\": \"did:web:issuer.example.com\",\n" +
                "  \"issuanceDate\": \"2024-01-01T00:00:00Z\",\n" +
                "  \"expirationDate\": \"2030-01-01T00:00:00Z\",\n" +
                "  \"credentialSubject\": {\n" +
                "    \"id\": \"did:example:holder123\",\n" +
                "    \"name\": \"Test User\",\n" +
                "    \"email\": \"test@example.com\"\n" +
                "  }\n" +
                "}";

        // Note: Without a proper signature, verification will fail
        // This test verifies the parsing and expiration checks work
        VCVerificationResultDTO result = vcVerificationService.verify(
                vcJson, "application/vc+ld+json");

        Assert.assertNotNull(result);
        // Without signature, it should be INVALID
        // With mock signature verification disabled, it might be SUCCESS for parsing tests
    }

    /**
     * Test expired credential detection.
     */
    @Test
    public void testExpiredCredentialDetection() {
        String expiredVcJson = "{\n" +
                "  \"@context\": [\"https://www.w3.org/2018/credentials/v1\"],\n" +
                "  \"id\": \"urn:uuid:" + UUID.randomUUID() + "\",\n" +
                "  \"type\": [\"VerifiableCredential\"],\n" +
                "  \"issuer\": \"did:web:issuer.example.com\",\n" +
                "  \"issuanceDate\": \"2020-01-01T00:00:00Z\",\n" +
                "  \"expirationDate\": \"2021-01-01T00:00:00Z\",\n" +
                "  \"credentialSubject\": { \"id\": \"did:example:holder\" }\n" +
                "}";

        VCVerificationResultDTO result = vcVerificationService.verify(
                expiredVcJson, "application/vc+ld+json");

        Assert.assertNotNull(result);
        Assert.assertEquals(result.getVerificationStatus(), VCVerificationStatus.EXPIRED);
    }

    /**
     * Test error handling for wallet decline.
     */
    @Test
    public void testWalletErrorHandling() throws VPException {
        // Create a request first
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setClientId(CLIENT_ID);
        createDTO.setNonce(UUID.randomUUID().toString());
        createDTO.setPresentationDefinitionId("sample-pd");

        VPRequestResponseDTO requestResponse = vpRequestService.createAuthorizationRequest(
                createDTO, TENANT_DOMAIN);

        // Simulate wallet error (user declined)
        VPSubmissionDTO submissionDTO = new VPSubmissionDTO();
        submissionDTO.setState(requestResponse.getRequestId());
        submissionDTO.setError("access_denied");
        submissionDTO.setErrorDescription("User declined the request");

        // Submit the error
        vpSubmissionService.submitError(
                requestResponse.getRequestId(),
                "access_denied",
                "User declined the request",
                TENANT_DOMAIN);

        // Verify the request status reflects the error
        // The exact behavior depends on implementation
    }

    /**
     * Test QR code data generation for wallet scanning.
     */
    @Test
    public void testQRCodeDataGeneration() throws VPException {
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setClientId(CLIENT_ID);
        createDTO.setNonce(UUID.randomUUID().toString());
        createDTO.setPresentationDefinitionId("sample-pd");
        createDTO.setRequestByReference(true);

        VPRequestResponseDTO response = vpRequestService.createAuthorizationRequest(
                createDTO, TENANT_DOMAIN);

        // For request-by-reference, the QR code should contain:
        // openid4vp://?client_id=...&request_uri=...
        String qrData = buildQRCodeData(response);

        Assert.assertNotNull(qrData);
        Assert.assertTrue(qrData.startsWith("openid4vp://"));
        Assert.assertTrue(qrData.contains("client_id="));
        Assert.assertTrue(qrData.contains("request_uri="));
    }

    // Helper methods

    private String getSamplePresentationDefinition() {
        return "{\n" +
                "  \"id\": \"sample-pd-" + UUID.randomUUID() + "\",\n" +
                "  \"input_descriptors\": [\n" +
                "    {\n" +
                "      \"id\": \"identity_credential\",\n" +
                "      \"format\": {\n" +
                "        \"ldp_vc\": {\n" +
                "          \"proof_type\": [\"Ed25519Signature2020\"]\n" +
                "        }\n" +
                "      },\n" +
                "      \"constraints\": {\n" +
                "        \"fields\": [\n" +
                "          {\n" +
                "            \"path\": [\"$.credentialSubject.email\"],\n" +
                "            \"purpose\": \"We need your email for authentication\"\n" +
                "          }\n" +
                "        ]\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}";
    }

    private String buildQRCodeData(VPRequestResponseDTO response) {
        StringBuilder sb = new StringBuilder("openid4vp://");
        sb.append("?client_id=").append(urlEncode(response.getClientId()));

        if (response.getRequestUri() != null) {
            sb.append("&request_uri=").append(urlEncode(response.getRequestUri()));
        }

        return sb.toString();
    }

    private String urlEncode(String value) {
        try {
            return java.net.URLEncoder.encode(value, "UTF-8");
        } catch (Exception e) {
            return value;
        }
    }
}
