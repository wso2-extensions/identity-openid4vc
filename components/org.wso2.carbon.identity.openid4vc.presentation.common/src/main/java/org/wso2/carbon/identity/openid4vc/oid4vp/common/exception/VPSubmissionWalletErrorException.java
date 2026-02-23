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

package org.wso2.carbon.identity.openid4vc.oid4vp.common.exception;

/**
 * Exception representing an error response from the wallet.
 * This is thrown when the wallet returns an error instead of a VP token.
 */
public class VPSubmissionWalletErrorException extends VPException {

    private static final long serialVersionUID = 1L;

    /**
     * Default error code.
     */
    private static final String DEFAULT_ERROR_CODE = "WALLET_ERROR";

    /**
     * The wallet error code.
     */
    private String walletError;

    /**
     * The wallet error description.
     */
    private String walletErrorDescription;

    /**
     * Constructor with wallet error.
     *
     * @param error Error code from wallet
     */
    public VPSubmissionWalletErrorException(final String error) {
        super(DEFAULT_ERROR_CODE, "Wallet returned an error: " + error);
        this.walletError = error;
    }

    /**
     * Constructor with wallet error and description.
     *
     * @param error       Error code from wallet
     * @param description Error description from wallet
     */
    public VPSubmissionWalletErrorException(final String error,
            final String description) {

        super(DEFAULT_ERROR_CODE, description != null ? description
                : "Wallet returned an error: " + error);
        this.walletError = error;
        this.walletErrorDescription = description;
    }

    /**
     * Get the wallet error code.
     *
     * @return Wallet error code
     */
    public String getWalletError() {
        return walletError;
    }

    /**
     * Get the wallet error description.
     *
     * @return Wallet error description
     */
    public String getWalletErrorDescription() {
        return walletErrorDescription;
    }
}
