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

package org.wso2.carbon.identity.openid4vc.presentation.service.impl;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.cache.VPRequestCache;
import org.wso2.carbon.identity.openid4vc.presentation.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.dao.VPRequestDAO;
import org.wso2.carbon.identity.openid4vc.presentation.dao.impl.VPRequestDAOImpl;
import org.wso2.carbon.identity.openid4vc.presentation.dto.AuthorizationDetailsDTO;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPRequestCreateDTO;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPRequestStatusDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPRequestExpiredException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.util.OpenID4VPUtil;
import org.wso2.carbon.identity.openid4vc.presentation.util.PresentationDefinitionUtil;
import org.wso2.carbon.identity.openid4vc.presentation.did.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.did.DIDProviderFactory;

/**
 * Implementation of VPRequestService for managing VP authorization requests.
 */
public class VPRequestServiceImpl implements VPRequestService {

    private static final Log log = LogFactory.getLog(VPRequestServiceImpl.class);

    private final VPRequestDAO vpRequestDAO;
    private final VPRequestCache vpRequestCache;
    private final PresentationDefinitionService presentationDefinitionService;
    private final String baseUrl;

    /**
     * Default constructor.
     */
    public VPRequestServiceImpl() {
        this.vpRequestDAO = new VPRequestDAOImpl();
        this.vpRequestCache = VPRequestCache.getInstance();
        this.presentationDefinitionService = new PresentationDefinitionServiceImpl();
        this.baseUrl = getConfiguredBaseUrl();
    }

    /**
     * Constructor for dependency injection.
     */
    public VPRequestServiceImpl(VPRequestDAO vpRequestDAO, VPRequestCache vpRequestCache,
            PresentationDefinitionService presentationDefinitionService,
            String baseUrl) {
        this.vpRequestDAO = vpRequestDAO;
        this.vpRequestCache = vpRequestCache;
        this.presentationDefinitionService = presentationDefinitionService;
        this.baseUrl = baseUrl;
    }

    @Override
    public VPRequestResponseDTO createVPRequest(VPRequestCreateDTO requestCreateDTO, int tenantId)
            throws VPException {

        if (log.isDebugEnabled()) {
            log.debug("Creating VP request for client: " + requestCreateDTO.getClientId());
        }

        // Validate input
        validateCreateRequest(requestCreateDTO);

        // Generate identifiers
        String requestId = OpenID4VPUtil.generateRequestId();
        String transactionId = StringUtils.isNotBlank(requestCreateDTO.getTransactionId())
                ? requestCreateDTO.getTransactionId()
                : OpenID4VPUtil.generateTransactionId();
        String nonce = StringUtils.isNotBlank(requestCreateDTO.getNonce()) ? requestCreateDTO.getNonce()
                : OpenID4VPUtil.generateNonce();

        // Resolve presentation definition
        String presentationDefinition = resolvePresentationDefinition(requestCreateDTO, tenantId);
        String didMethod = requestCreateDTO.getDidMethod();
        String signingAlgorithm = null;

        // Extract and clean internal configuration
        if (StringUtils.isNotBlank(presentationDefinition)) {
            try {
                JsonObject pdJson = JsonParser.parseString(presentationDefinition).getAsJsonObject();
                if (pdJson.has("_internal")) {
                    JsonObject internal = pdJson.getAsJsonObject("_internal");
                    // Only override if not already set in DTO
                    if (StringUtils.isBlank(didMethod) && internal.has("did_method")) {
                        didMethod = internal.get("did_method").getAsString();
                    }
                    if (internal.has("signing_algorithm")) {
                        signingAlgorithm = internal.get("signing_algorithm").getAsString();
                    }
                    // Remove internal config to keep spec compliant
                    pdJson.remove("_internal");
                    presentationDefinition = pdJson.toString();
                }
            } catch (Exception e) {
                log.warn("Error parsing presentation definition internally", e);
            }
        }

        // Calculate timestamps
        long createdAt = System.currentTimeMillis();
        long expiresAt = OpenID4VPUtil.calculateExpiryTime(createdAt);

        // Build response URI
        String responseUri = OpenID4VPUtil.buildResponseUri(baseUrl);

        // Create VP request model
        VPRequest vpRequest = new VPRequest.Builder()
                .requestId(requestId)
                .transactionId(transactionId)
                .clientId(requestCreateDTO.getClientId())
                .nonce(nonce)
                .presentationDefinitionId(requestCreateDTO.getPresentationDefinitionId())
                .presentationDefinition(presentationDefinition)
                .responseUri(responseUri)
                .responseMode(OpenID4VPConstants.Protocol.RESPONSE_MODE_DIRECT_POST)
                .status(VPRequestStatus.ACTIVE)
                .createdAt(createdAt)
                .expiresAt(expiresAt)
                .tenantId(tenantId)
                .build();

        // Generate and set the Request JWT immediately
        // This ensures the DID method preference is respected at creation time
        String requestJwt = buildRequestObjectJwt(vpRequest, didMethod, signingAlgorithm);
        vpRequest.setRequestJwt(requestJwt);

        // Persist to database
        vpRequestDAO.createVPRequest(vpRequest);

        // Add to cache for fast access
        vpRequestCache.put(vpRequest);

        // Generate request URI if enabled
        String requestUri = null;
        if (OpenID4VPUtil.isRequestUriEnabled()) {
            requestUri = OpenID4VPUtil.buildRequestUri(baseUrl, requestId);
        }

        // Build authorization details for by-value mode
        AuthorizationDetailsDTO authorizationDetails = buildAuthorizationDetails(
                vpRequest, presentationDefinition);

        // Build response
        VPRequestResponseDTO response = new VPRequestResponseDTO();
        response.setTransactionId(transactionId);
        response.setRequestId(requestId);
        response.setRequestUri(requestUri);
        response.setAuthorizationDetails(authorizationDetails);
        response.setExpiresAt(expiresAt);

        if (log.isDebugEnabled()) {
            log.debug("Created VP request: " + requestId + " with transaction: " + transactionId);
        }

        return response;
    }

    @Override
    public VPRequest getVPRequestById(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        // Try cache first
        VPRequest vpRequest = vpRequestCache.getByRequestId(requestId);

        if (vpRequest == null) {
            // Fallback to database
            vpRequest = vpRequestDAO.getVPRequestById(requestId, tenantId);

            if (vpRequest == null) {
                throw new VPRequestNotFoundException(requestId);
            }

            // Populate cache if still active
            if (vpRequest.getStatus() == VPRequestStatus.ACTIVE) {
                vpRequestCache.put(vpRequest);
            }
        }

        return vpRequest;
    }

    @Override
    public VPRequest getVPRequestByTransactionId(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        // Try cache first
        VPRequest vpRequest = vpRequestCache.getByTransactionId(transactionId);

        if (vpRequest == null) {
            // Fallback to database
            vpRequest = vpRequestDAO.getVPRequestByTransactionId(transactionId, tenantId);

            if (vpRequest == null) {
                throw new VPRequestNotFoundException("Transaction not found: " + transactionId);
            }
        }

        return vpRequest;
    }

    @Override
    public VPRequestStatusDTO getVPRequestStatus(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        VPRequest vpRequest = getVPRequestByTransactionId(transactionId, tenantId);

        VPRequestStatusDTO statusDTO = new VPRequestStatusDTO();
        statusDTO.setStatus(vpRequest.getStatus());
        statusDTO.setRequestId(vpRequest.getRequestId());

        return statusDTO;
    }

    @Override
    public void updateVPRequestStatus(String requestId, VPRequestStatus status, int tenantId)
            throws VPRequestNotFoundException, VPRequestExpiredException, VPException {

        VPRequest vpRequest = getVPRequestById(requestId, tenantId);

        // Check if expired
        if (OpenID4VPUtil.isExpired(vpRequest.getExpiresAt())) {
            throw new VPRequestExpiredException(requestId);
        }

        // Update in database
        vpRequestDAO.updateVPRequestStatus(requestId, status, tenantId);

        // Update cache if present
        VPRequest cachedRequest = vpRequestCache.getByRequestId(requestId);
        if (cachedRequest != null) {
            // Remove from cache - will be re-fetched with updated status if needed
            vpRequestCache.remove(requestId);
        }

        if (log.isDebugEnabled()) {
            log.debug("Updated VP request status: " + requestId + " to " + status);
        }
    }

    @Override
    public String getRequestUri(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        // Validate request exists
        getVPRequestById(requestId, tenantId);

        return OpenID4VPUtil.buildRequestUri(baseUrl, requestId);
    }

    @Override
    public String getRequestJwt(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPRequestExpiredException, VPException {

        VPRequest vpRequest = getVPRequestById(requestId, tenantId);

        // Check if expired
        if (OpenID4VPUtil.isExpired(vpRequest.getExpiresAt())) {
            throw new VPRequestExpiredException(requestId);
        }

        // Check if request is still active
        if (vpRequest.getStatus() != VPRequestStatus.ACTIVE) {
            throw new VPException("Request is no longer active: " + requestId);
        }

        // Return existing JWT if already generated
        if (StringUtils.isNotBlank(vpRequest.getRequestJwt())) {
            return vpRequest.getRequestJwt();
        }

        // Generate JWT (Note: Full JWT signing would require key management
        // integration)
        // For now, return the request parameters as a simple structure
        // In production, this should be a signed JWT
        // If JWT is missing (legacy records), attempt to build it with default did:web
        String requestJwt = buildRequestObjectJwt(vpRequest, "web", "RS256");

        // Store generated JWT
        vpRequestDAO.updateVPRequestJwt(requestId, requestJwt, tenantId);

        return requestJwt;
    }

    @Override
    public void deleteVPRequest(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        // Validate exists
        getVPRequestById(requestId, tenantId);

        // Delete from database
        vpRequestDAO.deleteVPRequest(requestId, tenantId);

        // Remove from cache
        vpRequestCache.remove(requestId);

        if (log.isDebugEnabled()) {
            log.debug("Deleted VP request: " + requestId);
        }
    }

    @Override
    public int processExpiredRequests(int tenantId) throws VPException {
        int count = vpRequestDAO.markExpiredRequests(tenantId);

        if (count > 0 && log.isDebugEnabled()) {
            log.debug("Marked " + count + " VP requests as expired for tenant: " + tenantId);
        }

        return count;
    }

    @Override
    public boolean isRequestActive(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        VPRequest vpRequest = getVPRequestById(requestId, tenantId);

        if (OpenID4VPUtil.isExpired(vpRequest.getExpiresAt())) {
            return false;
        }

        return vpRequest.getStatus() == VPRequestStatus.ACTIVE;
    }

    /**
     * Validate the request creation DTO.
     */
    private void validateCreateRequest(VPRequestCreateDTO requestCreateDTO) throws VPException {
        if (requestCreateDTO == null) {
            throw new VPException("Request creation DTO cannot be null");
        }

        if (StringUtils.isBlank(requestCreateDTO.getClientId())) {
            throw new VPException("Client ID is required");
        }

        // Either presentation definition ID or inline definition required
        if (StringUtils.isBlank(requestCreateDTO.getPresentationDefinitionId()) &&
                requestCreateDTO.getPresentationDefinition() == null) {
            throw new VPException("Either presentationDefinitionId or presentationDefinition is required");
        }
    }

    /**
     * Resolve the presentation definition from ID or inline value.
     */
    private String resolvePresentationDefinition(VPRequestCreateDTO requestCreateDTO, int tenantId)
            throws VPException {

        // If inline definition provided, validate and use it
        if (requestCreateDTO.getPresentationDefinition() != null) {
            String definitionJson = requestCreateDTO.getPresentationDefinition().toString();
            if (!PresentationDefinitionUtil.isValidPresentationDefinition(definitionJson)) {
                throw new VPException("Invalid presentation definition JSON");
            }
            return definitionJson;
        }

        // Otherwise, fetch from stored definitions
        String definitionId = requestCreateDTO.getPresentationDefinitionId();
        if (StringUtils.isNotBlank(definitionId)) {
            PresentationDefinition definition = presentationDefinitionService.getPresentationDefinitionById(
                    definitionId, tenantId);
            return definition.getDefinitionJson();
        }

        // Fall back to default definition
        PresentationDefinition defaultDefinition = presentationDefinitionService.getDefaultPresentationDefinition(
                tenantId);
        if (defaultDefinition != null) {
            return defaultDefinition.getDefinitionJson();
        }

        throw new VPException("No presentation definition available");
    }

    /**
     * Build authorization details DTO for by-value response mode.
     */
    private AuthorizationDetailsDTO buildAuthorizationDetails(VPRequest vpRequest,
            String presentationDefinition) {
        AuthorizationDetailsDTO details = new AuthorizationDetailsDTO();
        details.setClientId(vpRequest.getClientId());
        details.setResponseType(OpenID4VPConstants.Protocol.RESPONSE_TYPE_VP_TOKEN);
        details.setResponseMode(vpRequest.getResponseMode());
        details.setResponseUri(vpRequest.getResponseUri());
        details.setNonce(vpRequest.getNonce());
        details.setState(vpRequest.getRequestId());

        // Convert String to JsonObject for the DTO
        if (presentationDefinition != null) {
            JsonObject pdJson = JsonParser.parseString(presentationDefinition).getAsJsonObject();
            details.setPresentationDefinition(pdJson);
        }

        return details;
    }

    /**
     * Get configured base URL for building URIs.
     */
    private String getConfiguredBaseUrl() {
        return OpenID4VPUtil.getBaseUrl();
    }

    /**
     * Build the request object as a JWT.
     * Note: In production, this should be properly signed with the verifier's
     * private key.
     */
    private String buildRequestObjectJwt(VPRequest vpRequest, String didMethod, String signingAlgorithm) {
        try {
            DIDProvider provider = DIDProviderFactory.getProvider(didMethod);
            int tenantId = vpRequest.getTenantId();
            String baseUrl = getConfiguredBaseUrl();

            String did = provider.getDID(tenantId, baseUrl, signingAlgorithm);
            String keyId = provider.getSigningKeyId(tenantId, baseUrl, signingAlgorithm);

            log.info("Building Request Object with DID details - Method: " + provider.getName() + ", DID: " + did);

            // Create claims set
            com.nimbusds.jwt.JWTClaimsSet.Builder claimsBuilder = new com.nimbusds.jwt.JWTClaimsSet.Builder()
                    .issuer(did)
                    .claim(OpenID4VPConstants.RequestParams.RESPONSE_TYPE,
                            OpenID4VPConstants.Protocol.RESPONSE_TYPE_VP_TOKEN)
                    .claim(OpenID4VPConstants.RequestParams.RESPONSE_MODE, vpRequest.getResponseMode())
                    .claim(OpenID4VPConstants.RequestParams.RESPONSE_URI, vpRequest.getResponseUri())
                    .claim(OpenID4VPConstants.RequestParams.NONCE, vpRequest.getNonce())
                    .claim(OpenID4VPConstants.RequestParams.STATE, vpRequest.getRequestId())
                    .claim(OpenID4VPConstants.RequestParams.CLIENT_ID, vpRequest.getClientId())
                    .issueTime(new java.util.Date())
                    .jwtID(java.util.UUID.randomUUID().toString());

            // Set expiration (10 minutes)
            java.util.Date exp = new java.util.Date(System.currentTimeMillis() + 600000);
            claimsBuilder.expirationTime(exp);

            // Add presentation definition JSON object
            JsonObject pdJson = com.google.gson.JsonParser.parseString(vpRequest.getPresentationDefinition())
                    .getAsJsonObject();
            // Convert to Map for Nimbus
            java.util.Map<String, Object> pdMap = new com.google.gson.Gson().fromJson(pdJson, java.util.Map.class);
            claimsBuilder.claim("presentation_definition", pdMap);

            // Add client_metadata
            java.util.Map<String, Object> clientMetadata = new java.util.HashMap<>();
            clientMetadata.put("client_name", did);

            java.util.Map<String, Object> vpFormats = new java.util.HashMap<>();

            java.util.Map<String, Object> ldpVp = new java.util.HashMap<>();
            ldpVp.put("proof_type",
                    java.util.Arrays.asList("Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"));
            vpFormats.put("ldp_vp", ldpVp);

            java.util.Map<String, Object> vcSdJwt = new java.util.HashMap<>();
            vcSdJwt.put("sd-jwt_alg_values", java.util.Arrays.asList("RS256", "ES256", "ES256K", "EdDSA"));
            vcSdJwt.put("kb-jwt_alg_values", java.util.Arrays.asList("RS256", "ES256", "ES256K", "EdDSA"));
            vpFormats.put("vc+sd-jwt", vcSdJwt);

            clientMetadata.put("vp_formats", vpFormats);
            claimsBuilder.claim("client_metadata", clientMetadata);

            com.nimbusds.jwt.JWTClaimsSet claimsSet = claimsBuilder.build();

            // Create header
            com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(
                    provider.getSigningAlgorithm(signingAlgorithm))
                    .keyID(keyId)
                    .type(new com.nimbusds.jose.JOSEObjectType("oauth-authz-req+jwt"))
                    .build();

            com.nimbusds.jose.JWSObject jwsObject = new com.nimbusds.jose.JWSObject(header,
                    new com.nimbusds.jose.Payload(claimsSet.toJSONObject()));

            // Sign using provider logic
            com.nimbusds.jose.JWSSigner signer = provider.getSigner(tenantId, signingAlgorithm);
            jwsObject.sign(signer);

            return jwsObject.serialize();

        } catch (Exception e) {
            log.error("Error building request object JWT", e);
            throw new RuntimeException("Error building request object JWT", e);
        }
    }
}
