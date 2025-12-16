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
 * Exception type for server-side credential issuance errors.
 * This exception should be thrown for errors caused by internal server issues,
 * such as database errors, service unavailability, signing errors, etc.
 * These errors typically result in 5xx HTTP status codes.
 */
public class CredentialIssuanceServerException extends CredentialIssuanceException {

    public CredentialIssuanceServerException(String message) {

        super(message);
    }

    public CredentialIssuanceServerException(String message, Throwable cause) {

        super(message, cause);
    }

    public CredentialIssuanceServerException(String message, String description) {

        super(message, description);
    }

    public CredentialIssuanceServerException(String message, String description, Throwable cause) {

        super(message, description, cause);
    }

    public CredentialIssuanceServerException(CredentialIssuanceErrorCode errorCode, String message) {

        super(errorCode, message);
    }

    public CredentialIssuanceServerException(CredentialIssuanceErrorCode errorCode, String message, Throwable cause) {

        super(errorCode, message, cause);
    }

    public CredentialIssuanceServerException(CredentialIssuanceErrorCode errorCode, String message,
                                             String description) {

        super(errorCode, message, description);
    }

    public CredentialIssuanceServerException(CredentialIssuanceErrorCode errorCode, String message,
                                             String description, Throwable cause) {

        super(errorCode, message, description, cause);
    }
}

