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

package org.wso2.carbon.identity.openid4vc.issuance.credential.response;

import com.google.gson.Gson;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents the response generated after issuing an OpenID4VCI credential.
 */
public class CredentialIssuanceResponse {

    private static final Gson GSON = new Gson();
    private final Map<String, Object> payload;

    private CredentialIssuanceResponse(Map<String, Object> payload) {
        this.payload = payload;
    }

    public String toJson() {
        return GSON.toJson(payload);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder class for constructing CredentialIssuanceResponse instances.
     */
    public static class Builder {
        private final Map<String, Object> payload = new HashMap<>();

        public Builder credential(String credential) {
            if (credential == null) {
                throw new IllegalArgumentException("Credential cannot be null");
            }
            payload.put("credential", credential);
            return this;
        }

        public CredentialIssuanceResponse build() throws CredentialIssuanceException {
            if (!payload.containsKey("credential")) {
                throw new CredentialIssuanceException("Credential is required");
            }
            return new CredentialIssuanceResponse(payload);
        }
    }
}
