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

package org.wso2.carbon.identity.openid4vc.issuance.endpoint.metadata;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.issuance.common.util.CommonUtil;
import org.wso2.carbon.identity.openid4vc.issuance.endpoint.metadata.factories.CredentialIssuerMetadataServiceFactory;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.CredentialIssuerMetadataProcessor;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.exception.CredentialIssuerMetadataException;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.response.CredentialIssuerMetadataResponse;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Rest implementation of OID4VCI metadata endpoint.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class MetadataEndpoint {

    private static final Log LOG = LogFactory.getLog(MetadataEndpoint.class);

    @GET
    @Path("/.well-known/openid-credential-issuer")
    public Response getIssuerMetadata() {

        String tenantDomain = CommonUtil.resolveTenantDomain();
        try {
            CredentialIssuerMetadataProcessor processor =
                    CredentialIssuerMetadataServiceFactory.getMetadataProcessor();
            CredentialIssuerMetadataResponse metadataResponse =
                    processor.getMetadataResponse(tenantDomain);
            String responsePayload = metadataResponse.toJson();
            return Response.ok(responsePayload, MediaType.APPLICATION_JSON).build();
        } catch (CredentialIssuerMetadataException e) {
            LOG.error(String.format("Error while resolving OpenID4VCI metadata for tenant: %s", tenantDomain), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        }
    }
}
