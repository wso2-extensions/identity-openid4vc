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

package org.wso2.carbon.identity.openid4vc.sdjwt.exception;

/**
 * Exception class for SD-JWT related errors.
 */
public class SDJWTException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Constructor with message.
     *
     * @param message Error message
     */
    public SDJWTException(String message) {
        super(message);
    }

    /**
     * Constructor with message and cause.
     *
     * @param message Error message
     * @param cause   Cause of the exception
     */
    public SDJWTException(String message, Throwable cause) {
        super(message, cause);
    }
}
