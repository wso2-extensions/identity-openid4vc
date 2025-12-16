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
 * Exception type for client-side credential issuance errors.
 * This exception should be thrown for errors caused by invalid client requests,
 * such as invalid tokens, insufficient scope, invalid credential configuration, etc.
 * These errors typically result in 4xx HTTP status codes.
 */
public class CredentialIssuanceClientException extends CredentialIssuanceException {

    public CredentialIssuanceClientException(String message) {

        super(message);
    }

    public CredentialIssuanceClientException(String message, Throwable cause) {

        super(message, cause);
    }

    public CredentialIssuanceClientException(String message, String description) {

        super(message, description);
    }

    public CredentialIssuanceClientException(String message, String description, Throwable cause) {

        super(message, description, cause);
    }

    public CredentialIssuanceClientException(CredentialIssuanceErrorCode errorCode, String message) {

        super(errorCode, message);
    }

    public CredentialIssuanceClientException(CredentialIssuanceErrorCode errorCode, String message, Throwable cause) {

        super(errorCode, message, cause);
    }

    public CredentialIssuanceClientException(CredentialIssuanceErrorCode errorCode, String message,
                                             String description) {

        super(errorCode, message, description);
    }

    public CredentialIssuanceClientException(CredentialIssuanceErrorCode errorCode, String message,
                                             String description, Throwable cause) {

        super(errorCode, message, description, cause);
    }
}

