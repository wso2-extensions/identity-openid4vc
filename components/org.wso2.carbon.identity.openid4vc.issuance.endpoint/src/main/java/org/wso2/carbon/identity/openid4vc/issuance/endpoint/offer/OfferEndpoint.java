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

package org.wso2.carbon.identity.openid4vc.issuance.endpoint.offer;

import com.google.gson.Gson;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.issuance.common.util.CommonUtil;
import org.wso2.carbon.identity.openid4vc.issuance.endpoint.offer.error.OfferErrorResponse;
import org.wso2.carbon.identity.openid4vc.issuance.endpoint.offer.factories.CredentialOfferServiceFactory;
import org.wso2.carbon.identity.openid4vc.issuance.offer.CredentialOfferProcessor;
import org.wso2.carbon.identity.openid4vc.issuance.offer.exception.CredentialOfferClientException;
import org.wso2.carbon.identity.openid4vc.issuance.offer.exception.CredentialOfferException;
import org.wso2.carbon.identity.openid4vc.issuance.offer.response.CredentialOfferResponse;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * REST implementation of OID4VCI credential offer endpoint.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class OfferEndpoint {

    private static final Log LOG = LogFactory.getLog(OfferEndpoint.class);
    private static final Gson GSON = new Gson();

    @GET
    @Path("/credential-offer/{offer_id}")
    public Response getCredentialOffer(
            @PathParam("offer_id") String offerId) {

        String tenantDomain = CommonUtil.resolveTenantDomain();

        if (StringUtils.isEmpty(offerId)) {
            String errorResponse = OfferErrorResponse.builder()
                    .error(OfferErrorResponse.INVALID_REQUEST)
                    .errorDescription("offer_id is required")
                    .build()
                    .toJson();
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorResponse)
                    .build();
        }

        try {
            CredentialOfferProcessor processor = CredentialOfferServiceFactory.getOfferProcessor();
            CredentialOfferResponse offerResponse = processor.generateOffer(offerId, tenantDomain);
            String responsePayload = GSON.toJson(offerResponse.getOffer());
            return Response.ok(responsePayload, MediaType.APPLICATION_JSON).build();

        } catch (CredentialOfferClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Credential offer client error for tenant: %s, offerId: %s",
                        tenantDomain, offerId), e);
            }

            String errorCode = e.getErrorCode() != null ? e.getErrorCode() : OfferErrorResponse.OFFER_NOT_FOUND;
            String errorResponse = OfferErrorResponse.builder()
                    .error(OfferErrorResponse.OFFER_NOT_FOUND)
                    .errorDescription(e.getDescription() != null ? e.getDescription() : e.getMessage())
                    .build()
                    .toJson();

            Response.Status status = determineHttpStatus(errorCode);

            return Response.status(status)
                    .entity(errorResponse)
                    .build();

        } catch (CredentialOfferException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Credential offer failed for tenant: %s, offerId: %s",
                        tenantDomain, offerId), e);
            }

            String errorCode = e.getErrorCode() != null ? e.getErrorCode() : OfferErrorResponse.SERVER_ERROR;
            String errorResponse = OfferErrorResponse.builder()
                    .error(errorCode)
                    .errorDescription(e.getDescription() != null ? e.getDescription() : e.getMessage())
                    .build()
                    .toJson();

            Response.Status status = determineHttpStatus(errorCode);

            return Response.status(status)
                    .entity(errorResponse)
                    .build();

        } catch (IllegalStateException e) {
            LOG.error("Credential offer processor service is unavailable", e);
            String errorResponse = OfferErrorResponse.builder()
                    .error(OfferErrorResponse.SERVER_ERROR)
                    .errorDescription("Credential offer service is unavailable")
                    .build()
                    .toJson();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(errorResponse)
                    .build();

        } catch (Exception e) {
            LOG.error("Error building credential offer response", e);
            String errorResponse = OfferErrorResponse.builder()
                    .error(OfferErrorResponse.SERVER_ERROR)
                    .errorDescription("Error processing credential offer request")
                    .build()
                    .toJson();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .header("Cache-Control", "no-store")
                    .entity(errorResponse)
                    .build();
        }
    }

    /**
     * Determines the appropriate HTTP status code based on the error code.
     *
     * @param errorCode the error code
     * @return the appropriate HTTP status
     */
    private Response.Status determineHttpStatus(String errorCode) {

        if (errorCode == null) {
            return Response.Status.BAD_REQUEST;
        }

        // Client error codes (60xxx) return 4xx, Server error codes (65xxx) return 5xx
        if (errorCode.startsWith("60")) {
            return Response.Status.NOT_FOUND;
        } else if (errorCode.startsWith("65")) {
            return Response.Status.INTERNAL_SERVER_ERROR;
        }

        // Default mapping based on error type
        switch (errorCode) {
            case OfferErrorResponse.INVALID_REQUEST:
                return Response.Status.BAD_REQUEST;
            case OfferErrorResponse.OFFER_NOT_FOUND:
                return Response.Status.NOT_FOUND;
            case OfferErrorResponse.SERVER_ERROR:
            default:
                return Response.Status.INTERNAL_SERVER_ERROR;
        }
    }
}

