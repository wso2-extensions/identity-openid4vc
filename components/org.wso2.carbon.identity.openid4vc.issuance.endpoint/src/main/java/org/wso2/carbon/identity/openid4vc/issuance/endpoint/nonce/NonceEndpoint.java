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

package org.wso2.carbon.identity.openid4vc.issuance.endpoint.nonce;

import com.google.gson.Gson;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.issuance.common.util.CommonUtil;
import org.wso2.carbon.identity.openid4vc.issuance.credential.nonce.NonceService;
import org.wso2.carbon.identity.openid4vc.issuance.endpoint.nonce.factories.NonceServiceFactory;

import java.util.LinkedHashMap;
import java.util.Map;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.C_NONCE;

/**
 * OID4VCI Nonce Endpoint (draft 16, Section 7).
 *
 * <p>Issues {@code c_nonce} values for wallets to embed in proof JWTs.
 * This endpoint requires no authorization — it is intentionally public.
 * Per the spec, the response MUST set {@code Cache-Control: no-store}.</p>
 *
 * <p>Response body (draft 16 — {@code c_nonce_expires_in} was removed):
 * <pre>{"c_nonce": "&lt;value&gt;"}</pre>
 * </p>
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class NonceEndpoint {

    private static final Log LOG = LogFactory.getLog(NonceEndpoint.class);
    private static final Gson GSON = new Gson();

    @POST
    @Path("/nonce")
    @Produces(MediaType.APPLICATION_JSON)
    public Response requestNonce() {

        String tenantDomain = CommonUtil.resolveTenantDomain();
        try {
            NonceService nonceService = NonceServiceFactory.getService();
            String cNonce = nonceService.generateNonce(tenantDomain);

            Map<String, String> responseBody = new LinkedHashMap<>();
            responseBody.put(C_NONCE, cNonce);

            return Response.ok(GSON.toJson(responseBody), MediaType.APPLICATION_JSON)
                    .header("Cache-Control", "no-store")
                    .build();

        } catch (Exception e) {
            LOG.error(String.format("Failed to generate nonce for tenant: %s", tenantDomain), e);
            return Response.serverError()
                    .header("Cache-Control", "no-store")
                    .entity("{\"error\":\"server_error\",\"error_description\":\"Failed to generate nonce\"}")
                    .build();
        }
    }
}
