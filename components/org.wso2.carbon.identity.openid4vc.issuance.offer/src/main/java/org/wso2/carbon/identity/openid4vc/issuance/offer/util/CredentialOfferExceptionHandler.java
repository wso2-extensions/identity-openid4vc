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

package org.wso2.carbon.identity.openid4vc.issuance.offer.util;

import org.apache.commons.lang.ArrayUtils;
import org.wso2.carbon.identity.openid4vc.issuance.offer.constant.CredentialOfferConstants;
import org.wso2.carbon.identity.openid4vc.issuance.offer.exception.CredentialOfferClientException;
import org.wso2.carbon.identity.openid4vc.issuance.offer.exception.CredentialOfferServerException;

/**
 * Utility class for Credential Offer exception handling.
 */
public class CredentialOfferExceptionHandler {

    private CredentialOfferExceptionHandler() {
    }

    /**
     * Handle Credential Offer client exceptions.
     *
     * @param error Error message.
     * @param data  Data.
     * @return CredentialOfferClientException.
     */
    public static CredentialOfferClientException handleClientException(
            CredentialOfferConstants.ErrorMessages error, Object... data) {

        String description = error.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, data);
        }

        return new CredentialOfferClientException(error.getMessage(), description, error.getCode());
    }

    /**
     * Handle Credential Offer server exceptions.
     *
     * @param error Error message.
     * @param e     Throwable.
     * @param data  Data.
     * @return CredentialOfferServerException.
     */
    public static CredentialOfferServerException handleServerException(
            CredentialOfferConstants.ErrorMessages error, Throwable e, Object... data) {

        String description = error.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, data);
        }

        return new CredentialOfferServerException(error.getMessage(), description, error.getCode(), e);
    }
}

