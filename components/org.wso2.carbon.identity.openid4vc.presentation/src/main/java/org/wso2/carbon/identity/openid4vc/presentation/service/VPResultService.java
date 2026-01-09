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

package org.wso2.carbon.identity.openid4vc.presentation.service;

import org.wso2.carbon.identity.openid4vc.presentation.dto.VCVerificationResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPSubmissionNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPSubmission;

import java.util.List;

/**
 * Service interface for formatting and retrieving VP/VC verification results.
 * Provides comprehensive result formatting for API responses.
 */
public interface VPResultService {

    /**
     * Get the comprehensive VP verification result by transaction ID.
     *
     * @param transactionId The transaction identifier
     * @param tenantId      The tenant ID
     * @return VPResultDTO with comprehensive verification results
     * @throws VPRequestNotFoundException    If no request found for the transaction
     * @throws VPSubmissionNotFoundException If no submission found
     * @throws VPException                   If an error occurs
     */
    VPResultDTO getVPResult(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPSubmissionNotFoundException, VPException;

    /**
     * Get the VP verification result by request ID.
     *
     * @param requestId The request identifier
     * @param tenantId  The tenant ID
     * @return VPResultDTO with comprehensive verification results
     * @throws VPRequestNotFoundException    If no request found
     * @throws VPSubmissionNotFoundException If no submission found
     * @throws VPException                   If an error occurs
     */
    VPResultDTO getVPResultByRequestId(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPSubmissionNotFoundException, VPException;

    /**
     * Build a comprehensive VP result from request and submission.
     *
     * @param request    The VP request
     * @param submission The VP submission
     * @param tenantId   The tenant ID
     * @return VPResultDTO with all verification details
     * @throws VPException If an error occurs
     */
    VPResultDTO buildComprehensiveResult(VPRequest request, VPSubmission submission, int tenantId)
            throws VPException;

    /**
     * Build VC verification results from a VP token.
     *
     * @param vpToken  The VP token to analyze
     * @param tenantId The tenant ID
     * @return List of VCVerificationResultDTO for each credential
     * @throws VPException If an error occurs
     */
    List<VCVerificationResultDTO> buildVCVerificationResults(String vpToken, int tenantId)
            throws VPException;

    /**
     * Get a summary of the VP result.
     *
     * @param transactionId The transaction identifier
     * @param tenantId      The tenant ID
     * @return VPResultSummaryDTO with summary information
     * @throws VPRequestNotFoundException    If no request found
     * @throws VPSubmissionNotFoundException If no submission found
     * @throws VPException                   If an error occurs
     */
    VPResultSummaryDTO getVPResultSummary(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPSubmissionNotFoundException, VPException;

    /**
     * Check if all credentials in the VP were verified successfully.
     *
     * @param transactionId The transaction identifier
     * @param tenantId      The tenant ID
     * @return true if all credentials passed verification
     * @throws VPRequestNotFoundException    If no request found
     * @throws VPSubmissionNotFoundException If no submission found
     * @throws VPException                   If an error occurs
     */
    boolean isVerificationSuccessful(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPSubmissionNotFoundException, VPException;

    /**
     * Get the holder information from a VP result.
     *
     * @param transactionId The transaction identifier
     * @param tenantId      The tenant ID
     * @return The holder DID or identifier
     * @throws VPRequestNotFoundException    If no request found
     * @throws VPSubmissionNotFoundException If no submission found
     * @throws VPException                   If an error occurs
     */
    String getHolderFromResult(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPSubmissionNotFoundException, VPException;

    /**
     * Summary DTO for VP result.
     */
    class VPResultSummaryDTO {
        private String transactionId;
        private String requestId;
        private String status;
        private String overallResult;
        private int totalCredentials;
        private int verifiedCredentials;
        private int failedCredentials;
        private Long verificationTimestamp;
        private String holder;

        public String getTransactionId() {
            return transactionId;
        }

        public void setTransactionId(String transactionId) {
            this.transactionId = transactionId;
        }

        public String getRequestId() {
            return requestId;
        }

        public void setRequestId(String requestId) {
            this.requestId = requestId;
        }

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }

        public String getOverallResult() {
            return overallResult;
        }

        public void setOverallResult(String overallResult) {
            this.overallResult = overallResult;
        }

        public int getTotalCredentials() {
            return totalCredentials;
        }

        public void setTotalCredentials(int totalCredentials) {
            this.totalCredentials = totalCredentials;
        }

        public int getVerifiedCredentials() {
            return verifiedCredentials;
        }

        public void setVerifiedCredentials(int verifiedCredentials) {
            this.verifiedCredentials = verifiedCredentials;
        }

        public int getFailedCredentials() {
            return failedCredentials;
        }

        public void setFailedCredentials(int failedCredentials) {
            this.failedCredentials = failedCredentials;
        }

        public Long getVerificationTimestamp() {
            return verificationTimestamp;
        }

        public void setVerificationTimestamp(Long verificationTimestamp) {
            this.verificationTimestamp = verificationTimestamp;
        }

        public String getHolder() {
            return holder;
        }

        public void setHolder(String holder) {
            this.holder = holder;
        }
    }
}
