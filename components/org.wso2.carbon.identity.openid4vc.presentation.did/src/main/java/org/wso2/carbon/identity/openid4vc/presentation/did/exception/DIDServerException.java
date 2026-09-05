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
 * Exception type for server-side DID component failures.
 */
public class DIDServerException extends DIDException {

    private String did;
    private String method;

    /**
     * Constructor with message.
     * 
     * @param message Error message.
     */
    public DIDServerException(String message) {

        super(message);
    }

    /**
     * Constructor with message and cause.
     * 
     * @param message Error message.
     * @param cause Underlying cause.
     */
    public DIDServerException(String message, Throwable cause) {

        super(message, cause);
    }

    /**
     * Constructor with message and description.
     * 
     * @param message Error message.
     * @param description Error description.
     */
    public DIDServerException(String message, String description) {

        super(message, description);
    }

    /**
     * Constructor with message, description and cause.
     * 
     * @param message Error message.
     * @param description Error description.
     * @param cause Underlying cause.
     */
    public DIDServerException(String message, String description, Throwable cause) {

        super(message, description, cause);
    }

    /**
     * Constructor with error code and message.
     * 
     * @param errorCode Error code.
     * @param message Error message.
     */
    public DIDServerException(DIDErrorCode errorCode, String message) {

        super(errorCode, message);
    }

    /**
     * Constructor with error code, message and cause.
     * 
     * @param errorCode Error code.
     * @param message Error message.
     * @param cause Underlying cause.
     */
    public DIDServerException(DIDErrorCode errorCode, String message, Throwable cause) {

        super(errorCode, message, cause);
    }



    /**
     * Constructor with error code, message, DID and cause.
     * 
     * @param errorCode Error code.
     * @param message Error message.
     * @param did The DID related to the exception.
     * @param cause Underlying cause.
     */
    public DIDServerException(DIDErrorCode errorCode, String message, String did, Throwable cause) {

        super(errorCode, message, cause);
        this.did = did;
        this.method = extractMethod(did);
    }

    /**
     * Constructor with error code, message and DID.
     * 
     * @param errorCode Error code.
     * @param message Error message.
     * @param did The DID related to the exception.
     */
    public DIDServerException(DIDErrorCode errorCode, String message, String did) {

        super(errorCode, message);
        this.did = did;
        this.method = extractMethod(did);
    }

    /**
     * Get the DID associated with the exception.
     * 
     * @return The DID
     */
    public String getDid() {

        return did;
    }

    /**
     * Get the DID method associated with the exception.
     * 
     * @return The DID method
     */
    public String getMethod() {

        return method;
    }

    /**
     * Create a DIDServerException for DID document errors.
     * 
     * @param message Error message.
     * @param cause Underlying cause.
     * @return DIDServerException object.
     */
    public static DIDServerException didDocumentError(String message, Throwable cause) {

        return new DIDServerException(DIDErrorCode.DID_DOCUMENT_ERROR, message, cause);
    }

    /**
     * Create a DIDServerException for unsupported DID methods.
     * 
     * @param didValue The DID value.
     * @param method The unsupported method.
     * @return DIDServerException object.
     */
    public static DIDServerException unsupportedMethod(String didValue, String method) {

        return new DIDServerException(DIDErrorCode.UNSUPPORTED_DID_METHOD,
                "Unsupported DID method: " + method, didValue);
    }

    /**
     * Create a DIDServerException for network errors.
     * 
     * @param didValue The DID value.
     * @param cause Underlying cause.
     * @return DIDServerException object.
     */
    public static DIDServerException networkError(String didValue, Throwable cause) {

        return new DIDServerException(DIDErrorCode.NETWORK_ERROR,
                "Network error while resolving DID: " + didValue, didValue, cause);
    }

    /**
     * Create a DIDServerException for invalid DID documents.
     * 
     * @param didValue The DID value.
     * @param message Error message.
     * @return DIDServerException object.
     */
    public static DIDServerException invalidDocument(String didValue, String message) {

        return new DIDServerException(DIDErrorCode.INVALID_DID_DOCUMENT,
                "Invalid DID document for " + didValue + ": " + message, didValue);
    }

    /**
     * Create a DIDServerException when a key is not found in the DID document.
     * 
     * @param didValue The DID value.
     * @param keyId The key ID.
     * @return DIDServerException object.
     */
    public static DIDServerException keyNotFound(String didValue, String keyId) {

        return new DIDServerException(DIDErrorCode.KEY_NOT_FOUND,
                "Key not found in DID document: " + (keyId != null ? keyId : "default key"), didValue);
    }

    /**
     * Create a DIDServerException for invalid DID formats.
     * 
     * @param didValue The DID value.
     * @return DIDServerException object.
     */
    public static DIDServerException invalidFormat(String didValue) {

        return new DIDServerException(DIDErrorCode.INVALID_DID_FORMAT,
                "Invalid DID format: " + didValue, didValue);
    }

    /**
     * Extract the DID method from the DID string.
     * 
     * @param didValue The DID value.
     * @return The DID method string.
     */
    private String extractMethod(String didValue) {

        if (didValue != null && didValue.startsWith("did:")) {
            String[] parts = didValue.split(":");
            if (parts.length >= 2) {
                return parts[1];
            }
        }
        return null;
    }
}
