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

package org.wso2.carbon.identity.openid4vc.oid4vp.presentation.polling;

import java.io.Serializable;

/**
 * Result of a polling operation.
 * Contains the current status and any relevant data.
 */
public class PollingResult implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * Polling result status types.
     */
    public enum ResultStatus {
        /**
         * Waiting for VP submission.
         */
        WAITING,

        /**
         * VP has been submitted.
         */
        SUBMITTED,

        /**
         * VP submitted with error from wallet.
         */
        SUBMITTED_WITH_ERROR,

        /**
         * Request has expired.
         */
        EXPIRED,

        /**
         * Request not found.
         */
        NOT_FOUND,

        /**
         * Polling timed out.
         */
        TIMEOUT,

        /**
         * Error occurred.
         */
        ERROR
    }

    private final String requestId;
    private final ResultStatus resultStatus;
    private final String status;
    private final String errorMessage;
    private final boolean complete;

    /**
     * Private constructor - use factory methods.
     */
    private PollingResult(final String requestId,
                          final ResultStatus resultStatus,
                          final String status,
                          final String errorMessage,
                          final boolean complete) {

        this.requestId = requestId;
        this.resultStatus = resultStatus;
        this.status = status;
        this.errorMessage = errorMessage;
        this.complete = complete;
    }

    // Factory methods

    /**
     * Create a result indicating VP submission is still pending.
     *
     * @param requestId Request ID
     * @return PollingResult for waiting state
     */
    public static PollingResult waiting(final String requestId) {

        return new PollingResult(requestId, ResultStatus.WAITING, "ACTIVE", null, false);
    }

    /**
     * Create a result indicating VP has been submitted.
     *
     * @param requestId Request ID
     * @param status    Status string
     * @return PollingResult for submitted state
     */
    public static PollingResult submitted(final String requestId, final String status) {

        return new PollingResult(requestId, ResultStatus.SUBMITTED, status, null, true);
    }

    /**
     * Create a result indicating VP submitted with wallet error.
     *
     * @param requestId Request ID
     * @param status    Status string
     * @return PollingResult for submitted with error state
     */
    public static PollingResult submittedWithError(final String requestId,
                                                    final String status) {

        return new PollingResult(requestId, ResultStatus.SUBMITTED_WITH_ERROR,
                status, null, true);
    }

    /**
     * Create a result indicating request has expired.
     *
     * @param requestId Request ID
     * @return PollingResult for expired state
     */
    public static PollingResult expired(final String requestId) {

        return new PollingResult(requestId, ResultStatus.EXPIRED, "EXPIRED", null, true);
    }

    /**
     * Create a result indicating request was not found.
     *
     * @param requestId Request ID
     * @return PollingResult for not found state
     */
    public static PollingResult notFound(final String requestId) {

        return new PollingResult(requestId, ResultStatus.NOT_FOUND, null,
                "Request not found", true);
    }

    /**
     * Create a result indicating polling timed out.
     *
     * @param requestId Request ID
     * @return PollingResult for timeout state
     */
    public static PollingResult timeout(final String requestId) {

        return new PollingResult(requestId, ResultStatus.TIMEOUT, "ACTIVE", null, false);
    }

    /**
     * Create a result indicating an error occurred.
     *
     * @param requestId    Request ID
     * @param errorMessage Error message
     * @return PollingResult for error state
     */
    public static PollingResult error(final String requestId, final String errorMessage) {

        return new PollingResult(requestId, ResultStatus.ERROR, null, errorMessage, true);
    }

    // Getters

    /**
     * Get the request ID.
     *
     * @return Request ID
     */
    public String getRequestId() {

        return requestId;
    }

    /**
     * Get the result status.
     *
     * @return ResultStatus
     */
    public ResultStatus getResultStatus() {

        return resultStatus;
    }

    /**
     * Get the status string.
     *
     * @return Status string
     */
    public String getStatus() {

        return status;
    }

    /**
     * Get error message if any.
     *
     * @return Error message or null
     */
    public String getErrorMessage() {

        return errorMessage;
    }

    /**
     * Check if polling is complete.
     * Complete means no need to continue polling - either success, error, or expired.
     *
     * @return true if complete
     */
    public boolean isComplete() {

        return complete;
    }

    /**
     * Check if VP token was received (submitted successfully or with error).
     *
     * @return true if submitted
     */
    public boolean isTokenReceived() {

        return resultStatus == ResultStatus.SUBMITTED
                || resultStatus == ResultStatus.SUBMITTED_WITH_ERROR;
    }

    /**
     * Check if result indicates waiting state.
     *
     * @return true if waiting
     */
    public boolean isWaiting() {

        return resultStatus == ResultStatus.WAITING;
    }

    /**
     * Check if result indicates timeout.
     *
     * @return true if timeout
     */
    public boolean isTimeout() {

        return resultStatus == ResultStatus.TIMEOUT;
    }

    /**
     * Check if result indicates expired.
     *
     * @return true if expired
     */
    public boolean isExpired() {

        return resultStatus == ResultStatus.EXPIRED;
    }

    /**
     * Check if result indicates an error.
     *
     * @return true if error
     */
    public boolean isError() {

        return resultStatus == ResultStatus.ERROR
                || resultStatus == ResultStatus.NOT_FOUND;
    }

    /**
     * Check if result indicates submission with wallet error.
     *
     * @return true if submitted with error
     */
    public boolean hasWalletError() {

        return resultStatus == ResultStatus.SUBMITTED_WITH_ERROR;
    }

    @Override
    public String toString() {

        return "PollingResult{"
                + "requestId='" + requestId + '\''
                + ", resultStatus=" + resultStatus
                + ", status='" + status + '\''
                + ", errorMessage='" + errorMessage + '\''
                + ", complete=" + complete
                + '}';
    }
}
