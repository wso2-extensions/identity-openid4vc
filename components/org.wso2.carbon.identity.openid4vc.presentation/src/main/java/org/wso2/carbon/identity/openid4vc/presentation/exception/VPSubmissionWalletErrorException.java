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

package org.wso2.carbon.identity.openid4vc.presentation.exception;

/**
 * Exception representing an error response from the wallet.
 * This is thrown when the wallet returns an error instead of a VP token.
 */
public class VPSubmissionWalletErrorException extends VPException {

    private static final long serialVersionUID = 1L;

    private String walletError;
    private String walletErrorDescription;

    /**
     * Constructor with wallet error.
     *
     * @param walletError Error code from wallet
     */
    public VPSubmissionWalletErrorException(String walletError) {
        super(walletError, "Wallet returned an error: " + walletError);
        this.walletError = walletError;
    }

    /**
     * Constructor with wallet error and description.
     *
     * @param walletError            Error code from wallet
     * @param walletErrorDescription Error description from wallet
     */
    public VPSubmissionWalletErrorException(String walletError, String walletErrorDescription) {
        super(walletError, walletErrorDescription != null ? walletErrorDescription : 
            "Wallet returned an error: " + walletError);
        this.walletError = walletError;
        this.walletErrorDescription = walletErrorDescription;
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
