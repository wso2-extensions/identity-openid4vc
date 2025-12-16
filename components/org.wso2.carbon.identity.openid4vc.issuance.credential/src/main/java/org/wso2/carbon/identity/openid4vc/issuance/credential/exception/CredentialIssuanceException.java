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
 * Base exception type for credential issuance related failures.
 * This class serves as the parent for both client and server exceptions.
 */
public class CredentialIssuanceException extends Exception {

    private final CredentialIssuanceErrorCode errorCode;
    private final String description;

    public CredentialIssuanceException(String message) {

        super(message);
        this.errorCode = null;
        this.description = null;
    }

    public CredentialIssuanceException(String message, Throwable cause) {

        super(message, cause);
        this.errorCode = null;
        this.description = null;
    }

    public CredentialIssuanceException(String message, String description) {

        super(message);
        this.errorCode = null;
        this.description = description;
    }

    public CredentialIssuanceException(String message, String description, Throwable cause) {

        super(message, cause);
        this.errorCode = null;
        this.description = description;
    }

    public CredentialIssuanceException(CredentialIssuanceErrorCode errorCode, String message) {

        super(message);
        this.errorCode = errorCode;
        this.description = errorCode != null ? errorCode.getDescription() : null;
    }

    public CredentialIssuanceException(CredentialIssuanceErrorCode errorCode, String message, Throwable cause) {

        super(message, cause);
        this.errorCode = errorCode;
        this.description = errorCode != null ? errorCode.getDescription() : null;
    }

    public CredentialIssuanceException(CredentialIssuanceErrorCode errorCode, String message, String description) {

        super(message);
        this.errorCode = errorCode;
        this.description = description;
    }

    public CredentialIssuanceException(CredentialIssuanceErrorCode errorCode, String message, String description,
                                       Throwable cause) {

        super(message, cause);
        this.errorCode = errorCode;
        this.description = description;
    }

    /**
     * Get the error code associated with this exception.
     *
     * @return CredentialIssuanceErrorCode or null if not set.
     */
    public CredentialIssuanceErrorCode getErrorCode() {

        return errorCode;
    }

    /**
     * Get the internal error code string (e.g., CIS-40001).
     *
     * @return Internal error code string or null if error code is not set.
     */
    public String getCode() {

        return errorCode != null ? errorCode.getCode() : null;
    }

    /**
     * Get the OpenID4VCI/RFC6750 error code (e.g., invalid_credential_request).
     *
     * @return OpenID4VCI/RFC6750 error code or null if error code is not set.
     */
    public String getOAuth2ErrorCode() {

        return errorCode != null ? errorCode.getOAuth2ErrorCode() : null;
    }

    /**
     * Get the error description.
     *
     * @return Error description or null if not set.
     */
    public String getDescription() {

        return description;
    }
}
