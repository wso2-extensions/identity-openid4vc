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
 * Exception thrown when VP request has expired.
 */
public class VPRequestExpiredException extends VPException {

    private static final long serialVersionUID = 1L;
    private static final String DEFAULT_ERROR_CODE = "VP_REQUEST_EXPIRED";

    private String requestId;
    private long expiredAt;

    /**
     * Constructor with request ID.
     *
     * @param requestId The request ID that has expired
     */
    public VPRequestExpiredException(String requestId) {
        super(DEFAULT_ERROR_CODE, "VP request has expired: " + requestId);
        this.requestId = requestId;
    }

    /**
     * Constructor with request ID and expiry time.
     *
     * @param requestId Request ID
     * @param expiredAt Expiry timestamp
     */
    public VPRequestExpiredException(String requestId, long expiredAt) {
        super(DEFAULT_ERROR_CODE, "VP request has expired: " + requestId + " at " + expiredAt);
        this.requestId = requestId;
        this.expiredAt = expiredAt;
    }

    /**
     * Get the request ID that has expired.
     *
     * @return Request ID
     */
    public String getRequestId() {
        return requestId;
    }

    /**
     * Get the expiry timestamp.
     *
     * @return Expiry timestamp in milliseconds
     */
    public long getExpiredAt() {
        return expiredAt;
    }
}
