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
 * Base exception class for OpenID4VP Verifiable Presentation errors.
 */
public class VPException extends Exception {

    private static final long serialVersionUID = 1L;

    private String errorCode;

    /**
     * Constructor with message.
     *
     * @param message Error message
     */
    public VPException(String message) {
        super(message);
    }

    /**
     * Constructor with message and error code.
     *
     * @param errorCode Error code
     * @param message   Error message
     */
    public VPException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Constructor with message and cause.
     *
     * @param message Error message
     * @param cause   Underlying cause
     */
    public VPException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructor with error code, message, and cause.
     *
     * @param errorCode Error code
     * @param message   Error message
     * @param cause     Underlying cause
     */
    public VPException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    /**
     * Get the error code.
     *
     * @return Error code or null
     */
    public String getErrorCode() {
        return errorCode;
    }

    /**
     * Set the error code.
     *
     * @param errorCode Error code
     */
    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }
}
