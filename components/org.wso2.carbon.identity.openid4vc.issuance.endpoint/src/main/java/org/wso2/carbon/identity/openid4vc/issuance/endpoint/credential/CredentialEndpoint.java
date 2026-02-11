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

package org.wso2.carbon.identity.openid4vc.issuance.endpoint.credential;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.issuance.common.util.CommonUtil;
import org.wso2.carbon.identity.openid4vc.issuance.credential.CredentialIssuanceService;
import org.wso2.carbon.identity.openid4vc.issuance.credential.dto.CredentialIssuanceReqDTO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.dto.CredentialIssuanceRespDTO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.dto.ProofDTO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceClientException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.response.CredentialIssuanceResponse;
import org.wso2.carbon.identity.openid4vc.issuance.endpoint.credential.error.CredentialErrorResponse;
import org.wso2.carbon.identity.openid4vc.issuance.endpoint.credential.factories.CredentialIssuanceServiceFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.JWT_PROOF;
import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.PROOF;
import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.PROOFS;
import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.PROOF_TYPE;


/**
 * Rest implementation of OID4VCI credential endpoint.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class CredentialEndpoint {

    private static final Log LOG = LogFactory.getLog(CredentialEndpoint.class);

    @POST
    @Path("/credential")
    @Consumes("application/json")
    @Produces("application/json")
    public Response requestCredential(@Context HttpServletRequest request, @Context HttpServletResponse response,
                                      String payload) {

        String tenantDomain = CommonUtil.resolveTenantDomain();
        try {

            String authHeader = request.getHeader("Authorization");
            if (StringUtils.isEmpty(authHeader) || !authHeader.startsWith("Bearer ")) {
                String errorResponse = CredentialErrorResponse.builder()
                        .error(CredentialErrorResponse.INVALID_TOKEN)
                        .errorDescription("Missing or invalid Authorization header")
                        .build()
                        .toJson();
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity(errorResponse)
                        .build();
            }

            JsonObject jsonObject;
            try {
                jsonObject = JsonParser.parseString(payload).getAsJsonObject();
            } catch (JsonSyntaxException e) {
                LOG.error("Invalid JSON payload", e);
                String errorResponse = CredentialErrorResponse.builder()
                        .error(CredentialErrorResponse.INVALID_CREDENTIAL_REQUEST)
                        .errorDescription("Invalid JSON format")
                        .build()
                        .toJson();
                return Response.status(Response.Status.BAD_REQUEST).entity(errorResponse).build();
            }

            ProofDTO proofDTO = parseProofs(jsonObject);

            CredentialIssuanceRespDTO credentialIssuanceRespDTO = getCredentialIssuanceRespDTO(authHeader,
                    proofDTO, tenantDomain);
            return buildResponse(credentialIssuanceRespDTO);

        } catch (CredentialIssuanceClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Credential issuance client error for tenant: %s", tenantDomain), e);
            }

            String errorCode = e.getOAuth2ErrorCode() != null ? e.getOAuth2ErrorCode() :
                    CredentialErrorResponse.INVALID_CREDENTIAL_REQUEST;
            String errorResponse = CredentialErrorResponse.builder()
                    .error(errorCode)
                    .errorDescription(e.getMessage())
                    .build()
                    .toJson();

            Response.Status status = determineHttpStatus(errorCode);

            return Response.status(status)
                    .entity(errorResponse)
                    .build();
        } catch (CredentialIssuanceException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Credential issuance failed for tenant: %s", tenantDomain), e);
            }

            // Get error code from exception or default to credential_request_denied
            String errorCode = e.getOAuth2ErrorCode() != null
                    ? e.getOAuth2ErrorCode()
                    : CredentialErrorResponse.CREDENTIAL_REQUEST_DENIED;
            String errorResponse = CredentialErrorResponse.builder()
                    .error(errorCode)
                    .errorDescription(e.getMessage())
                    .build()
                    .toJson();

            // Determine HTTP status based on error code
            Response.Status status = determineHttpStatus(errorCode);

            return Response.status(status)
                    .entity(errorResponse)
                    .build();
        } catch (IllegalStateException e) {
            LOG.error("Credential issuance processor service is unavailable", e);
            String errorResponse = CredentialErrorResponse.builder()
                    .error(CredentialErrorResponse.CREDENTIAL_REQUEST_DENIED)
                    .errorDescription("Credential issuance service is unavailable")
                    .build()
                    .toJson();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(errorResponse)
                    .build();
        } catch (Exception e) {
            LOG.error("Error building credential response", e);
            String errorResponse = CredentialErrorResponse.builder()
                    .error(CredentialErrorResponse.CREDENTIAL_REQUEST_DENIED)
                    .errorDescription("Error processing credential request")
                    .build()
                    .toJson();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .header("Cache-Control", "no-store")
                    .entity(errorResponse)
                    .build();
        }
    }

    /**
     * Parse proof/proofs from the JSON request payload.
     * Supports both:
     * - {@code proof} (singular): {"proof_type":"jwt","jwt":"<jwt>"}  -- single credential issuance
     * - {@code proofs} (plural):  {"jwt":["<jwt>"]}                   -- batch / multi-proof
     * The request MUST NOT contain both.
     *
     * @param jsonObject the parsed JSON object
     * @return ProofDTO, or null if neither field is present
     */
    private static ProofDTO parseProofs(JsonObject jsonObject) throws CredentialIssuanceException {

        boolean hasProof = jsonObject.has(PROOF);
        boolean hasProofs = jsonObject.has(PROOFS);

        if (hasProof && hasProofs) {
            throw new CredentialIssuanceClientException(
                    "Request MUST NOT contain both 'proof' and 'proofs'",
                    CredentialErrorResponse.INVALID_PROOF);
        }

        if (hasProof) {
            return parseSingularProof(jsonObject.getAsJsonObject(PROOF));
        }

        if (hasProofs) {
            return parsePluralProofs(jsonObject.getAsJsonObject(PROOFS));
        }

        return null;
    }

    /**
     * Parse the singular {@code proof} object.
     * Expected structure: {"proof_type":"jwt","jwt":"<jwt-string>"}
     */
    private static ProofDTO parseSingularProof(JsonObject proofObject) throws CredentialIssuanceException {

        if (proofObject == null) {
            throw new CredentialIssuanceClientException("'proof' must be a JSON object",
                    CredentialErrorResponse.INVALID_PROOF);
        }

        if (!proofObject.has(PROOF_TYPE)) {
            throw new CredentialIssuanceClientException("Missing 'proof_type' in proof",
                    CredentialErrorResponse.INVALID_PROOF);
        }

        String proofType = proofObject.get(PROOF_TYPE).getAsString();
        if (!JWT_PROOF.equals(proofType)) {
            throw new CredentialIssuanceClientException("Unsupported proof type: " + proofType,
                    CredentialErrorResponse.INVALID_PROOF);
        }

        if (!proofObject.has(JWT_PROOF) || !proofObject.get(JWT_PROOF).isJsonPrimitive()) {
            throw new CredentialIssuanceClientException("Missing or invalid 'jwt' value in proof",
                    CredentialErrorResponse.INVALID_PROOF);
        }

        String jwt = proofObject.get(JWT_PROOF).getAsString().trim();
        if (jwt.isEmpty()) {
            throw new CredentialIssuanceClientException("JWT proof cannot be empty",
                    CredentialErrorResponse.INVALID_PROOF);
        }

        ProofDTO proofDTO = new ProofDTO();
        proofDTO.setType(proofType);
        proofDTO.setProofs(Collections.singletonList(jwt));
        return proofDTO;
    }

    /**
     * Parse the plural {@code proofs} object.
     * Expected structure: {"jwt":["<jwt-string-1>", ...]}
     */
    private static ProofDTO parsePluralProofs(JsonObject proofsObject) throws CredentialIssuanceException {

        if (proofsObject == null) {
            throw new CredentialIssuanceClientException("'proofs' must be a JSON object",
                    CredentialErrorResponse.INVALID_PROOF);
        }

        if (proofsObject.keySet().size() != 1) {
            throw new CredentialIssuanceClientException("'proofs' must contain exactly one proof type",
                    CredentialErrorResponse.INVALID_PROOF);
        }

        String proofType = proofsObject.keySet().iterator().next();
        if (!JWT_PROOF.equals(proofType)) {
            throw new CredentialIssuanceClientException("Unsupported proof type: " + proofType,
                    CredentialErrorResponse.INVALID_PROOF);
        }

        JsonArray proofsArray = proofsObject.getAsJsonArray(proofType);
        if (proofsArray == null) {
            throw new CredentialIssuanceClientException("'proofs." + proofType + "' must be an array",
                    CredentialErrorResponse.INVALID_PROOF);
        }

        List<String> jwtProofs = new ArrayList<>(proofsArray.size());
        for (JsonElement e : proofsArray) {
            if (e == null || !e.isJsonPrimitive() || !e.getAsJsonPrimitive().isString()) {
                throw new CredentialIssuanceClientException("Each entry in 'proofs.jwt' must be a JWT string",
                        CredentialErrorResponse.INVALID_PROOF);
            }
            String jwt = e.getAsString().trim();
            if (jwt.isEmpty()) {
                throw new CredentialIssuanceClientException("JWT proof cannot be empty",
                        CredentialErrorResponse.INVALID_PROOF);
            }
            jwtProofs.add(jwt);
        }

        ProofDTO proofDTO = new ProofDTO();
        proofDTO.setType(proofType);
        proofDTO.setProofs(jwtProofs);
        return proofDTO;
    }

    private static CredentialIssuanceRespDTO getCredentialIssuanceRespDTO(String authHeader,
                                                                          ProofDTO proofDTO,
                                                                          String tenantDomain)
            throws CredentialIssuanceException {

        String token = authHeader.substring(7);

        CredentialIssuanceReqDTO credentialIssuanceReqDTO = new CredentialIssuanceReqDTO();
        credentialIssuanceReqDTO.setTenantDomain(tenantDomain);
        credentialIssuanceReqDTO.setToken(token);
        credentialIssuanceReqDTO.setProofDTO(proofDTO);

        CredentialIssuanceService credentialIssuanceService = CredentialIssuanceServiceFactory
                .getCredentialIssuanceService();
        return credentialIssuanceService.issueCredential(credentialIssuanceReqDTO);
    }

    /**
     * Determines the appropriate HTTP status code based on the OpenID4VCI/RFC6750 error code.
     *
     * @param errorCode the error code
     * @return the appropriate HTTP status
     */
    private Response.Status determineHttpStatus(String errorCode) {

        if (errorCode == null) {
            return Response.Status.BAD_REQUEST;
        }

        switch (errorCode) {
            case CredentialErrorResponse.INVALID_TOKEN:
                return Response.Status.UNAUTHORIZED;
            case CredentialErrorResponse.INSUFFICIENT_SCOPE:
                return Response.Status.FORBIDDEN;
            case CredentialErrorResponse.INVALID_CREDENTIAL_REQUEST:
            case CredentialErrorResponse.UNKNOWN_CREDENTIAL_CONFIGURATION:
            case CredentialErrorResponse.UNKNOWN_CREDENTIAL_IDENTIFIER:
            case CredentialErrorResponse.INVALID_PROOF:
            case CredentialErrorResponse.INVALID_NONCE:
            case CredentialErrorResponse.INVALID_ENCRYPTION_PARAMETERS:
                return Response.Status.BAD_REQUEST;
            case CredentialErrorResponse.CREDENTIAL_REQUEST_DENIED:
            default:
                return Response.Status.BAD_REQUEST;
        }
    }

    /**
     * Builds the successful credential issuance response.
     *
     * @param credentialIssuanceRespDTO the credential issuance response DTO
     * @return the HTTP response
     * @throws CredentialIssuanceException if an error occurs while building the response
     */
    private Response buildResponse(CredentialIssuanceRespDTO credentialIssuanceRespDTO)
            throws CredentialIssuanceException {

        String payload = CredentialIssuanceResponse.builder()
                .credential(credentialIssuanceRespDTO.getCredential())
                .build()
                .toJson();
        return Response.ok(payload, MediaType.APPLICATION_JSON).build();
    }
}
