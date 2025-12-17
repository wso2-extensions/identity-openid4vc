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

package org.wso2.carbon.identity.openid4vc.issuance.offer.constant;

/**
 * Constants for Credential Offer processing.
 */
public class CredentialOfferConstants {

    private CredentialOfferConstants() {
    }

    /**
     * Error messages for credential offer operations.
     */
    public enum ErrorMessages {

        // Client errors
        ERROR_CODE_INVALID_OFFER_ID("VCO-60002", "Invalid offer ID.",
                "The provided offer ID is invalid or malformed."),

        // Server errors
        ERROR_CODE_RETRIEVAL_ERROR("VCO-65001", "Error while retrieving VC template.",
                "Error while retrieving VC template for offer ID: %s"),
        ERROR_CODE_URL_BUILD_ERROR("VCO-65002", "Error while constructing URLs.",
                "Error while constructing credential offer URLs.");

        private final String code;
        private final String message;
        private final String description;

        ErrorMessages(String code, String message, String description) {

            this.code = code;
            this.message = message;
            this.description = description;
        }

        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }

        public String getDescription() {

            return description;
        }
    }
}

