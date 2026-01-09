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
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPRequestCreateDTO;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.service.impl.VPRequestServiceImpl;

/**
 * Unit tests for VPRequestService.
 */
public class VPRequestServiceTest {

    private VPRequestService vpRequestService;
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String CLIENT_ID = "did:web:verifier.example.com";

    @BeforeMethod
    public void setUp() {
        vpRequestService = new VPRequestServiceImpl();
    }

    @Test
    public void testCreateAuthorizationRequest() throws VPException {
        // Arrange
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setClientId(CLIENT_ID);
        createDTO.setNonce("test-nonce-123");
        createDTO.setPresentationDefinitionId("test-pd-id");

        // Act
        VPRequestResponseDTO response = vpRequestService.createAuthorizationRequest(createDTO, TENANT_DOMAIN);

        // Assert
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getRequestId());
        Assert.assertNotNull(response.getTransactionId());
        Assert.assertEquals(response.getClientId(), CLIENT_ID);
        Assert.assertTrue(response.getExpiresAt() > System.currentTimeMillis() / 1000);
    }

    @Test
    public void testCreateAuthorizationRequestWithInlinePD() throws VPException {
        // Arrange
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setClientId(CLIENT_ID);
        createDTO.setNonce("test-nonce-456");
        
        String presentationDefinition = "{\n" +
                "  \"id\": \"test-pd\",\n" +
                "  \"input_descriptors\": [\n" +
                "    {\n" +
                "      \"id\": \"id_credential\",\n" +
                "      \"format\": { \"ldp_vc\": { \"proof_type\": [\"Ed25519Signature2020\"] } },\n" +
                "      \"constraints\": {\n" +
                "        \"fields\": [{ \"path\": [\"$.credentialSubject.id\"] }]\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        createDTO.setPresentationDefinition(presentationDefinition);

        // Act
        VPRequestResponseDTO response = vpRequestService.createAuthorizationRequest(createDTO, TENANT_DOMAIN);

        // Assert
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getRequestId());
        Assert.assertNotNull(response.getAuthorizationDetails());
        Assert.assertNotNull(response.getAuthorizationDetails().getPresentationDefinition());
    }

    @Test(expectedExceptions = VPException.class)
    public void testCreateAuthorizationRequestWithMissingClientId() throws VPException {
        // Arrange
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setNonce("test-nonce");
        // Missing clientId

        // Act - should throw exception
        vpRequestService.createAuthorizationRequest(createDTO, TENANT_DOMAIN);
    }

    @Test(expectedExceptions = VPException.class)
    public void testCreateAuthorizationRequestWithMissingNonce() throws VPException {
        // Arrange
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setClientId(CLIENT_ID);
        // Missing nonce

        // Act - should throw exception
        vpRequestService.createAuthorizationRequest(createDTO, TENANT_DOMAIN);
    }

    @Test
    public void testGetRequestStatus() throws VPException {
        // Arrange - Create a request first
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setClientId(CLIENT_ID);
        createDTO.setNonce("test-nonce-status");
        createDTO.setPresentationDefinitionId("test-pd-id");

        VPRequestResponseDTO response = vpRequestService.createAuthorizationRequest(createDTO, TENANT_DOMAIN);

        // Act
        VPRequestStatus status = vpRequestService.getRequestStatus(response.getRequestId());

        // Assert
        Assert.assertEquals(status, VPRequestStatus.ACTIVE);
    }

    @Test
    public void testGetRequestStatusNotFound() {
        // Act
        VPRequestStatus status = vpRequestService.getRequestStatus("non-existent-request-id");

        // Assert
        Assert.assertNull(status);
    }

    @Test
    public void testMarkAsSubmitted() throws VPException {
        // Arrange - Create a request first
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setClientId(CLIENT_ID);
        createDTO.setNonce("test-nonce-submit");
        createDTO.setPresentationDefinitionId("test-pd-id");

        VPRequestResponseDTO response = vpRequestService.createAuthorizationRequest(createDTO, TENANT_DOMAIN);

        // Act
        vpRequestService.markAsSubmitted(response.getRequestId());

        // Assert
        VPRequestStatus status = vpRequestService.getRequestStatus(response.getRequestId());
        Assert.assertEquals(status, VPRequestStatus.VP_SUBMITTED);
    }

    @Test
    public void testGetAuthorizationRequestJWT() throws VPException {
        // Arrange - Create a request first
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setClientId(CLIENT_ID);
        createDTO.setNonce("test-nonce-jwt");
        createDTO.setPresentationDefinitionId("test-pd-id");

        VPRequestResponseDTO response = vpRequestService.createAuthorizationRequest(createDTO, TENANT_DOMAIN);

        // Act
        String jwt = vpRequestService.getAuthorizationRequestJWT(response.getRequestId());

        // Assert
        Assert.assertNotNull(jwt);
        // JWT format: header.payload.signature
        String[] parts = jwt.split("\\.");
        Assert.assertEquals(parts.length, 3, "JWT should have 3 parts");
    }

    @Test
    public void testRequestByReferenceMode() throws VPException {
        // Arrange
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setClientId(CLIENT_ID);
        createDTO.setNonce("test-nonce-ref");
        createDTO.setPresentationDefinitionId("test-pd-id");
        createDTO.setRequestByReference(true);

        // Act
        VPRequestResponseDTO response = vpRequestService.createAuthorizationRequest(createDTO, TENANT_DOMAIN);

        // Assert
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getRequestUri());
        Assert.assertTrue(response.getRequestUri().contains(response.getRequestId()));
    }

    @Test
    public void testRequestByValueMode() throws VPException {
        // Arrange
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setClientId(CLIENT_ID);
        createDTO.setNonce("test-nonce-value");
        createDTO.setPresentationDefinitionId("test-pd-id");
        createDTO.setRequestByReference(false);

        // Act
        VPRequestResponseDTO response = vpRequestService.createAuthorizationRequest(createDTO, TENANT_DOMAIN);

        // Assert
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getAuthorizationDetails());
        Assert.assertEquals(response.getAuthorizationDetails().getResponseType(), "vp_token");
        Assert.assertEquals(response.getAuthorizationDetails().getResponseMode(), "direct_post");
    }
}
