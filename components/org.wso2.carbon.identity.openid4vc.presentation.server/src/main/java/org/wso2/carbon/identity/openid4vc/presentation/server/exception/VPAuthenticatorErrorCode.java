/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.presentation.server.exception;

/**
 * Error codes for presentation authenticator client/server exception handling.
 */
public enum VPAuthenticatorErrorCode {

    INVALID_REQUEST("VPA-40001", "invalid_request",
            "Invalid request.", "Invalid or malformed request."),

    VP_REQUEST_NOT_FOUND("VPA-40401", "vp_request_not_found",
            "VP request was not found.", "The VP request was not found."),

    VP_REQUEST_EXPIRED("VPA-41001", "vp_request_expired",
            "VP request has expired.", "The VP request has expired."),

    INTERNAL_SERVER_ERROR("VPA-50001", "server_error",
            "Internal server error.", "An internal server error occurred."),

    INVALID_PRESENTATION_DEFINITION("VPA-40003", "invalid_presentation_definition",
            "Invalid presentation definition.", "The presentation definition is invalid or missing."),

    CLIENT_METADATA_ERROR("VPA-40004", "invalid_client_metadata",
            "Invalid client metadata.", "The client metadata is invalid or malformed."),

    VERIFICATION_FAILED("VPA-40101", "verification_failed",
            "VP verification failed.", "The verifiable presentation verification failed."),

    SIGNING_ERROR("VPA-50002", "signing_error",
            "Error occurred during signing.", "An error occurred while signing the request object.");

    private final String code;
    private final String oauth2ErrorCode;
    private final String message;
    private final String description;

    VPAuthenticatorErrorCode(final String errorCode, final String oauth2Code,
                             final String errorMsg, final String errorDescription) {
        this.code = errorCode;
        this.oauth2ErrorCode = oauth2Code;
        this.message = errorMsg;
        this.description = errorDescription;
    }

    public String getCode() { return code; }
    public String getOAuth2ErrorCode() { return oauth2ErrorCode; }
    public String getMessage() { return message; }
    public String getDescription() { return description; }
}
