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

package org.wso2.carbon.identity.openid4vc.issuance.credential.util;

import org.apache.commons.lang.ArrayUtils;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceClientException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceErrorCode;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceServerException;

/**
 * Utility class for Credential Issuance exception handling.
 */
public class CredentialIssuanceExceptionHandler {

    private CredentialIssuanceExceptionHandler() {
    }

    /**
     * Handle Credential Issuance client exceptions.
     *
     * @param errorCode Error code.
     * @param data      Data for formatting the description.
     * @return CredentialIssuanceClientException.
     */
    public static CredentialIssuanceClientException handleClientException(
            CredentialIssuanceErrorCode errorCode, String... data) {

        String description = errorCode.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, (Object[]) data);
        }

        return new CredentialIssuanceClientException(errorCode, errorCode.getMessage(), description);
    }

    /**
     * Handle Credential Issuance server exceptions.
     *
     * @param errorCode Error code.
     * @param e         Throwable.
     * @param data      Data for formatting the description.
     * @return CredentialIssuanceServerException.
     */
    public static CredentialIssuanceServerException handleServerException(
            CredentialIssuanceErrorCode errorCode, Throwable e, String... data) {

        String description = errorCode.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, (Object[]) data);
        }

        return new CredentialIssuanceServerException(errorCode, errorCode.getMessage(), description, e);
    }
}

