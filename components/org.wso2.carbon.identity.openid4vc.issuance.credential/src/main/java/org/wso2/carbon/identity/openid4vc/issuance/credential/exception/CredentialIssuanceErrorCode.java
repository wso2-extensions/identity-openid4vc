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

package org.wso2.carbon.identity.openid4vc.issuance.credential.exception;

/**
 * Enum representing error codes for credential issuance operations.
 * Error codes follow OpenID4VCI specification and RFC6750.
 */
public enum CredentialIssuanceErrorCode {

    // Client errors (4xx) - OpenID4VCI spec Section 8.3.1.2
    INVALID_CREDENTIAL_REQUEST("VCI-40001", "invalid_credential_request",
            "Invalid credential request.",
            "The credential request is invalid or malformed."),
    UNKNOWN_CREDENTIAL_CONFIGURATION("VCI-40002", "unknown_credential_configuration",
            "Unknown credential configuration.",
            "The requested credential configuration is not supported or does not exist."),
    UNKNOWN_CREDENTIAL_IDENTIFIER("VCI-40003", "unknown_credential_identifier",
            "Unknown credential identifier.",
            "The requested credential identifier is unknown or invalid."),
    INVALID_PROOF("VCI-40004", "invalid_proof",
            "Invalid proof.",
            "The provided proof is invalid or cannot be verified."),
    INVALID_NONCE("VCI-40005", "invalid_nonce",
            "Invalid nonce.",
            "The provided nonce is invalid or has expired."),
    INVALID_ENCRYPTION_PARAMETERS("VCI-40006", "invalid_encryption_parameters",
            "Invalid encryption parameters.",
            "The encryption parameters provided are invalid or not supported."),

    // RFC6750 error codes for authorization errors
    INVALID_TOKEN("VCI-40101", "invalid_token",
            "Invalid access token.",
            "The access token is invalid, expired, or has been revoked."),
    INSUFFICIENT_SCOPE("VCI-40301", "insufficient_scope",
            "Insufficient scope.",
            "The access token does not contain the required scope to access this credential."),

    // Server errors (5xx)
    CREDENTIAL_REQUEST_DENIED("VCI-50001", "credential_request_denied",
            "Credential request denied.",
            "The credential request was denied by the server."),
    VC_TEMPLATE_MANAGER_NOT_AVAILABLE("VCI-50002", "credential_request_denied",
            "VC template manager not available.",
            "The verifiable credential template manager service is not available."),
    USER_REALM_ERROR("VCI-50003", "credential_request_denied",
            "User realm error.",
            "An error occurred while retrieving the user realm for credential issuance."),
    USER_STORE_ERROR("VCI-50004", "credential_request_denied",
            "User store error.",
            "An error occurred while retrieving user information from the user store."),
    CREDENTIAL_SIGNING_ERROR("VCI-50005", "credential_request_denied",
            "Credential signing error.",
            "An error occurred while signing the verifiable credential."),
    INTERNAL_SERVER_ERROR("VCI-50006", "credential_request_denied",
            "Internal server error.",
            "An internal server error occurred while processing the credential request.");

    private final String code;
    private final String oauth2ErrorCode;
    private final String message;
    private final String description;

    CredentialIssuanceErrorCode(String code, String oauth2ErrorCode, String message, String description) {

        this.code = code;
        this.oauth2ErrorCode = oauth2ErrorCode;
        this.message = message;
        this.description = description;
    }

    /**
     * Get the internal error code (e.g., VCI-40001).
     *
     * @return Internal error code.
     */
    public String getCode() {

        return code;
    }

    /**
     * Get the OpenID4VCI/RFC6750 error code (e.g., invalid_credential_request).
     *
     * @return OpenID4VCI/RFC6750 error code.
     */
    public String getOAuth2ErrorCode() {

        return oauth2ErrorCode;
    }

    /**
     * Get the error message.
     *
     * @return Error message.
     */
    public String getMessage() {

        return message;
    }

    /**
     * Get the error description.
     *
     * @return Error description.
     */
    public String getDescription() {

        return description;
    }

    @Override
    public String toString() {

        return code + " - " + message;
    }
}

