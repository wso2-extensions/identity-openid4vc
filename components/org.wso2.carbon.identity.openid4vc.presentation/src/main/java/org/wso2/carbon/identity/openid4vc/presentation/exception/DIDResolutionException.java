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
 * Exception thrown when DID resolution fails.
 */
public class DIDResolutionException extends VPException {

    private static final long serialVersionUID = 1L;
    private static final String DEFAULT_ERROR_CODE = "DID_RESOLUTION_FAILED";

    private String did;
    private String method;

    /**
     * Constructor with message.
     *
     * @param message Error message
     */
    public DIDResolutionException(String message) {
        super(DEFAULT_ERROR_CODE, message);
    }

    /**
     * Constructor with DID and message.
     *
     * @param did     The DID that failed resolution
     * @param message Error message
     */
    public DIDResolutionException(String did, String message) {
        super(DEFAULT_ERROR_CODE, message);
        this.did = did;
        extractMethod(did);
    }

    /**
     * Constructor with message and cause.
     *
     * @param message Error message
     * @param cause   Underlying cause
     */
    public DIDResolutionException(String message, Throwable cause) {
        super(DEFAULT_ERROR_CODE, message, cause);
    }

    /**
     * Constructor with DID, message, and cause.
     *
     * @param did     The DID that failed resolution
     * @param message Error message
     * @param cause   Underlying cause
     */
    public DIDResolutionException(String did, String message, Throwable cause) {
        super(DEFAULT_ERROR_CODE, message, cause);
        this.did = did;
        extractMethod(did);
    }

    /**
     * Constructor with error code, DID, and message.
     *
     * @param errorCode Error code
     * @param did       The DID that failed resolution
     * @param message   Error message
     */
    public DIDResolutionException(String errorCode, String did, String message) {
        super(errorCode, message);
        this.did = did;
        extractMethod(did);
    }

    /**
     * Extract the DID method from the DID string.
     *
     * @param did The DID string
     */
    private void extractMethod(String did) {
        if (did != null && did.startsWith("did:")) {
            String[] parts = did.split(":");
            if (parts.length >= 2) {
                this.method = parts[1];
            }
        }
    }

    /**
     * Get the DID that failed resolution.
     *
     * @return The DID
     */
    public String getDid() {
        return did;
    }

    /**
     * Get the DID method.
     *
     * @return The method (e.g., "web", "jwk", "key")
     */
    public String getMethod() {
        return method;
    }

    /**
     * Create an exception for unsupported DID method.
     *
     * @param did    The DID
     * @param method The unsupported method
     * @return DIDResolutionException
     */
    public static DIDResolutionException unsupportedMethod(String did, String method) {
        return new DIDResolutionException("UNSUPPORTED_DID_METHOD", did,
                "Unsupported DID method: " + method);
    }

    /**
     * Create an exception for network errors during resolution.
     *
     * @param did   The DID
     * @param cause The underlying cause
     * @return DIDResolutionException
     */
    public static DIDResolutionException networkError(String did, Throwable cause) {
        return new DIDResolutionException(did, 
                "Network error while resolving DID: " + did, cause);
    }

    /**
     * Create an exception for invalid DID document.
     *
     * @param did     The DID
     * @param message Details about the invalid document
     * @return DIDResolutionException
     */
    public static DIDResolutionException invalidDocument(String did, String message) {
        return new DIDResolutionException("INVALID_DID_DOCUMENT", did,
                "Invalid DID document for " + did + ": " + message);
    }

    /**
     * Create an exception for key not found.
     *
     * @param did   The DID
     * @param keyId The key ID that was not found
     * @return DIDResolutionException
     */
    public static DIDResolutionException keyNotFound(String did, String keyId) {
        return new DIDResolutionException("KEY_NOT_FOUND", did,
                "Key not found in DID document: " + (keyId != null ? keyId : "default key"));
    }

    /**
     * Create an exception for invalid DID format.
     *
     * @param did The invalid DID
     * @return DIDResolutionException
     */
    public static DIDResolutionException invalidFormat(String did) {
        return new DIDResolutionException("INVALID_DID_FORMAT", did,
                "Invalid DID format: " + did);
    }
}
