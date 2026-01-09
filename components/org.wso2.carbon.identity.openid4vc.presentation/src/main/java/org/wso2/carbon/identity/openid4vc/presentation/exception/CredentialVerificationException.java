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

import org.wso2.carbon.identity.openid4vc.presentation.model.VCVerificationStatus;

/**
 * Exception thrown when credential verification fails.
 */
public class CredentialVerificationException extends VPException {

    private static final long serialVersionUID = 1L;
    private static final String DEFAULT_ERROR_CODE = "CREDENTIAL_VERIFICATION_FAILED";

    private VCVerificationStatus verificationStatus;
    private int vcIndex;

    /**
     * Constructor with message.
     *
     * @param message Error message
     */
    public CredentialVerificationException(String message) {
        super(DEFAULT_ERROR_CODE, message);
    }

    /**
     * Constructor with verification status and message.
     *
     * @param verificationStatus The verification status that caused the failure
     * @param message            Error message
     */
    public CredentialVerificationException(VCVerificationStatus verificationStatus, String message) {
        super(DEFAULT_ERROR_CODE, message);
        this.verificationStatus = verificationStatus;
    }

    /**
     * Constructor with verification status, VC index, and message.
     *
     * @param verificationStatus The verification status
     * @param vcIndex            Index of the VC that failed
     * @param message            Error message
     */
    public CredentialVerificationException(VCVerificationStatus verificationStatus, 
                                            int vcIndex, String message) {
        super(DEFAULT_ERROR_CODE, message);
        this.verificationStatus = verificationStatus;
        this.vcIndex = vcIndex;
    }

    /**
     * Constructor with message and cause.
     *
     * @param message Error message
     * @param cause   Underlying cause
     */
    public CredentialVerificationException(String message, Throwable cause) {
        super(DEFAULT_ERROR_CODE, message, cause);
    }

    /**
     * Get the verification status.
     *
     * @return Verification status
     */
    public VCVerificationStatus getVerificationStatus() {
        return verificationStatus;
    }

    /**
     * Get the VC index that failed verification.
     *
     * @return VC index
     */
    public int getVcIndex() {
        return vcIndex;
    }
}
