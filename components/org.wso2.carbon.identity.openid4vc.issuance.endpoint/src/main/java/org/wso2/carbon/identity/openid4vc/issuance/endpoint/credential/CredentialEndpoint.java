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
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceClientException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.response.CredentialIssuanceResponse;
import org.wso2.carbon.identity.openid4vc.issuance.endpoint.credential.error.CredentialErrorResponse;
import org.wso2.carbon.identity.openid4vc.issuance.endpoint.credential.factories.CredentialIssuanceServiceFactory;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.CREDENTIAL_CONFIGURATION_ID;


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



            // Parse the JSON payload to extract credential_configuration_id
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

            // Validate required field: credential_configuration_id
            if (!jsonObject.has(CREDENTIAL_CONFIGURATION_ID)) {
                String errorResponse = CredentialErrorResponse.builder()
                        .error(CredentialErrorResponse.INVALID_CREDENTIAL_REQUEST)
                        .errorDescription("Missing required field: credential_configuration_id")
                        .build()
                        .toJson();
                return Response.status(Response.Status.BAD_REQUEST).entity(errorResponse).build();
            }

            String credentialConfigurationId = jsonObject.get(CREDENTIAL_CONFIGURATION_ID).getAsString();

            CredentialIssuanceRespDTO credentialIssuanceRespDTO = getCredentialIssuanceRespDTO(authHeader,
                    tenantDomain, credentialConfigurationId);
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

    private static CredentialIssuanceRespDTO getCredentialIssuanceRespDTO(String authHeader, String tenantDomain,
                                                                          String credentialConfigurationId)
            throws CredentialIssuanceException {

        String token = authHeader.substring(7);

        CredentialIssuanceReqDTO credentialIssuanceReqDTO = new CredentialIssuanceReqDTO();
        credentialIssuanceReqDTO.setTenantDomain(tenantDomain);
        credentialIssuanceReqDTO.setCredentialConfigurationId(credentialConfigurationId);
        credentialIssuanceReqDTO.setToken(token);

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
