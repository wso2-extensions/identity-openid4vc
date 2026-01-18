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
 * Exception thrown when DID document operations fail.
 */
public class DIDDocumentException extends Exception {

    private static final long serialVersionUID = 1L;

    public DIDDocumentException(String message) {
        super(message);
    }

    public DIDDocumentException(String message, Throwable cause) {
        super(message, cause);
    }

    public DIDDocumentException(Throwable cause) {
        super(cause);
    }
}
