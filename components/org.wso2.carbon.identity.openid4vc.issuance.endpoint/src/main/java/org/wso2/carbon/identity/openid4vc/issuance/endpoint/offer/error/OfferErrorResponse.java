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

package org.wso2.carbon.identity.openid4vc.issuance.endpoint.offer.error;

import com.google.gson.Gson;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents an error response for credential offer requests.
 */
public class OfferErrorResponse {

    private static final Gson GSON = new Gson();

    // Error codes for credential offer
    public static final String INVALID_REQUEST = "invalid_request";
    public static final String OFFER_NOT_FOUND = "offer_not_found";
    public static final String SERVER_ERROR = "server_error";

    private final String error;
    private final String errorDescription;

    private OfferErrorResponse(String error, String errorDescription) {
        this.error = error;
        this.errorDescription = errorDescription;
    }

    public String toJson() {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", error);
        if (errorDescription != null && !errorDescription.isEmpty()) {
            errorMap.put("error_description", errorDescription);
        }
        return GSON.toJson(errorMap);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder class for constructing OfferErrorResponse instances.
     */
    public static class Builder {
        private String error;
        private String errorDescription;

        public Builder error(String error) {
            this.error = error;
            return this;
        }

        public Builder errorDescription(String errorDescription) {
            this.errorDescription = errorDescription;
            return this;
        }

        public OfferErrorResponse build() {
            return new OfferErrorResponse(error, errorDescription);
        }
    }
}

