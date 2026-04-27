/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.did.exception;

/**
 * Base exception type for DID component failures.
 */
public class DIDException extends Exception {

    private final DIDErrorCode errorCode;
    private final String description;

    /**
     * Constructor with message.
     * 
     * @param message Error message.
     */
    public DIDException(String message) {

        super(message);
        this.errorCode = null;
        this.description = null;
    }

    /**
     * Constructor with message and cause.
     * 
     * @param message Error message.
     * @param cause Underlying cause.
     */
    public DIDException(String message, Throwable cause) {

        super(message, cause);
        this.errorCode = null;
        this.description = null;
    }

    /**
     * Constructor with message and description.
     * 
     * @param message Error message.
     * @param description Error description.
     */
    public DIDException(String message, String description) {

        super(message);
        this.errorCode = null;
        this.description = description;
    }

    /**
     * Constructor with message, description and cause.
     * 
     * @param message Error message.
     * @param description Error description.
     * @param cause Underlying cause.
     */
    public DIDException(String message, String description, Throwable cause) {

        super(message, cause);
        this.errorCode = null;
        this.description = description;
    }

    /**
     * Constructor with error code and message.
     * 
     * @param errorCode Error code.
     * @param message Error message.
     */
    public DIDException(DIDErrorCode errorCode, String message) {

        super(message);
        this.errorCode = errorCode;
        this.description = errorCode != null ? errorCode.getDescription() : null;
    }

    /**
     * Constructor with error code, message and cause.
     * 
     * @param errorCode Error code.
     * @param message Error message.
     * @param cause Underlying cause.
     */
    public DIDException(DIDErrorCode errorCode, String message, Throwable cause) {

        super(message, cause);
        this.errorCode = errorCode;
        this.description = errorCode != null ? errorCode.getDescription() : null;
    }

    /**
     * Constructor with error code, message and description.
     * 
     * @param errorCode Error code.
     * @param message Error message.
     * @param description Error description.
     */
    public DIDException(DIDErrorCode errorCode, String message, String description) {

        super(message);
        this.errorCode = errorCode;
        this.description = description;
    }

    /**
     * Constructor with error code, message, description and cause.
     * 
     * @param errorCode Error code.
     * @param message Error message.
     * @param description Error description.
     * @param cause Underlying cause.
     */
    public DIDException(DIDErrorCode errorCode, String message, String description, Throwable cause) {

        super(message, cause);
        this.errorCode = errorCode;
        this.description = description;
    }

    /**
     * Get the error code.
     * 
     * @return The error code
     */
    public DIDErrorCode getErrorCode() {

        return errorCode;
    }

    /**
     * Get the error code string.
     * 
     * @return The error code string
     */
    public String getCode() {

        return errorCode != null ? errorCode.getCode() : null;
    }

    /**
     * Get the error description.
     * 
     * @return The error description
     */
    public String getDescription() {

        return description;
    }
}
