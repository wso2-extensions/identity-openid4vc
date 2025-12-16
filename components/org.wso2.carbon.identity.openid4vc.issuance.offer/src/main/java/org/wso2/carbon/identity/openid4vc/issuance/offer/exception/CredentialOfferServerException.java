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

package org.wso2.carbon.identity.openid4vc.issuance.offer.exception;

/**
 * Exception class for server errors (5xx) in credential offer processing.
 * This represents errors caused by server-side failures.
 */
public class CredentialOfferServerException extends CredentialOfferException {

    public CredentialOfferServerException(String message) {

        super(message);
    }

    public CredentialOfferServerException(String message, Throwable cause) {

        super(message, cause);
    }

    public CredentialOfferServerException(String message, String description, String errorCode) {

        super(message, description, errorCode);
    }

    public CredentialOfferServerException(String message, String description, String errorCode, Throwable cause) {

        super(message, description, errorCode, cause);
    }
}

