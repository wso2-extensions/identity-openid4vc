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
 * Exception thrown when a VP submission is not found.
 */
public class VPSubmissionNotFoundException extends VPException {

    private static final long serialVersionUID = 1L;

    /**
     * Default error code.
     */
    private static final String DEFAULT_ERROR_CODE = "VP_SUBMISSION_NOT_FOUND";

    /**
     * The transaction ID that was not found.
     */
    private String transactionId;

    /**
     * The request ID that was not found.
     */
    private String requestId;

    /**
     * Constructor with transaction ID.
     *
     * @param txn The transaction ID that was not found
     */
    public VPSubmissionNotFoundException(final String txn) {
        super(DEFAULT_ERROR_CODE,
                "VP submission not found for transaction: " + txn);
        this.transactionId = txn;
    }

    /**
     * Constructor with transaction ID and request ID.
     *
     * @param txn The transaction ID
     * @param req The request ID
     */
    public VPSubmissionNotFoundException(final String txn, final String req) {
        super(DEFAULT_ERROR_CODE,
                "VP submission not found for transaction: " + txn
                        + ", request: " + req);
        this.transactionId = txn;
        this.requestId = req;
    }

    /**
     * Get the transaction ID.
     *
     * @return Transaction ID
     */
    public String getTransactionId() {
        return transactionId;
    }

    /**
     * Get the request ID.
     *
     * @return Request ID
     */
    public String getRequestId() {
        return requestId;
    }
}
