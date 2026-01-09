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

package org.wso2.carbon.identity.openid4vc.presentation.dto;

import com.google.gson.annotations.SerializedName;

/**
 * Data Transfer Object for API error responses.
 */
public class ErrorDTO {

    @SerializedName("error")
    private String error;

    @SerializedName("error_description")
    private String errorDescription;

    @SerializedName("error_code")
    private String errorCode;

    /**
     * Default constructor.
     */
    public ErrorDTO() {
    }

    /**
     * Constructor with error code.
     *
     * @param errorCode Error code enum
     */
    public ErrorDTO(ErrorCode errorCode) {
        this.error = errorCode.getError();
        this.errorDescription = errorCode.getDescription();
        this.errorCode = errorCode.name();
    }

    /**
     * Constructor with custom error and description.
     *
     * @param error            Error type
     * @param errorDescription Error description
     */
    public ErrorDTO(String error, String errorDescription) {
        this.error = error;
        this.errorDescription = errorDescription;
    }

    // Getters and Setters

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    /**
     * Enum defining standard error codes.
     */
    public enum ErrorCode {
        INVALID_REQUEST("invalid_request", "The request is invalid or malformed"),
        INVALID_CLIENT("invalid_client", "Client authentication failed"),
        INVALID_TOKEN("invalid_token", "The token is invalid or expired"),
        MISSING_PARAMETER("missing_parameter", "A required parameter is missing"),
        PRESENTATION_DEFINITION_NOT_FOUND("presentation_definition_not_found", 
            "The requested presentation definition was not found"),
        VP_REQUEST_NOT_FOUND("vp_request_not_found", 
            "The VP request was not found"),
        VP_SUBMISSION_NOT_FOUND("vp_submission_not_found", 
            "No VP submission found for the given transaction"),
        INVALID_TRANSACTION_ID("invalid_transaction_id", 
            "The transaction ID is invalid or not found"),
        VP_REQUEST_EXPIRED("vp_request_expired", 
            "The VP request has expired"),
        VERIFICATION_FAILED("verification_failed", 
            "Credential verification failed"),
        INTERNAL_ERROR("server_error", "An internal server error occurred"),
        INVALID_VP_TOKEN("invalid_vp_token", "The VP token is invalid or malformed"),
        BOTH_ID_AND_PD_CANNOT_BE_NULL("invalid_request", 
            "Either presentationDefinitionId or presentationDefinition must be provided");

        private final String error;
        private final String description;

        ErrorCode(String error, String description) {
            this.error = error;
            this.description = description;
        }

        public String getError() {
            return error;
        }

        public String getDescription() {
            return description;
        }
    }

    @Override
    public String toString() {
        return "ErrorDTO{" +
                "error='" + error + '\'' +
                ", errorDescription='" + errorDescription + '\'' +
                ", errorCode='" + errorCode + '\'' +
                '}';
    }
}
