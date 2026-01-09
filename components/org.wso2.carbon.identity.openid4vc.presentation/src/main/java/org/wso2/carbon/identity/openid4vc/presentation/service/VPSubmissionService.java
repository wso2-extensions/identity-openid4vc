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

import org.wso2.carbon.identity.openid4vc.presentation.dto.VPResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPRequestExpiredException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPSubmissionNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPSubmission;

/**
 * Service interface for handling VP (Verifiable Presentation) submissions.
 * Manages the receipt, storage, and retrieval of VP submissions from wallets.
 */
public interface VPSubmissionService {

    /**
     * Process a VP submission from a wallet.
     * This method handles both successful VP submissions and error responses from the wallet.
     *
     * @param submissionDTO The submission data from the wallet
     * @param tenantId      The tenant ID
     * @return The processed VPSubmission
     * @throws VPRequestNotFoundException If the associated request is not found
     * @throws VPRequestExpiredException  If the associated request has expired
     * @throws VPException                If an error occurs during processing
     */
    VPSubmission processVPSubmission(VPSubmissionDTO submissionDTO, int tenantId) 
            throws VPRequestNotFoundException, VPRequestExpiredException, VPException;

    /**
     * Get a VP submission by its submission ID.
     *
     * @param submissionId The unique submission identifier
     * @param tenantId     The tenant ID
     * @return The VP submission
     * @throws VPSubmissionNotFoundException If the submission is not found
     * @throws VPException                   If an error occurs
     */
    VPSubmission getVPSubmissionById(String submissionId, int tenantId) 
            throws VPSubmissionNotFoundException, VPException;

    /**
     * Get a VP submission by its associated request ID.
     *
     * @param requestId The request identifier
     * @param tenantId  The tenant ID
     * @return The VP submission
     * @throws VPSubmissionNotFoundException If the submission is not found
     * @throws VPException                   If an error occurs
     */
    VPSubmission getVPSubmissionByRequestId(String requestId, int tenantId) 
            throws VPSubmissionNotFoundException, VPException;

    /**
     * Get the verification result for a transaction.
     *
     * @param transactionId The transaction identifier
     * @param tenantId      The tenant ID
     * @return VPResultDTO containing the verification result
     * @throws VPRequestNotFoundException    If the associated request is not found
     * @throws VPSubmissionNotFoundException If no submission exists for the request
     * @throws VPException                   If an error occurs
     */
    VPResultDTO getVPResult(String transactionId, int tenantId) 
            throws VPRequestNotFoundException, VPSubmissionNotFoundException, VPException;

    /**
     * Check if a submission exists for a given request.
     *
     * @param requestId The request identifier
     * @param tenantId  The tenant ID
     * @return true if a submission exists
     * @throws VPException If an error occurs
     */
    boolean hasSubmission(String requestId, int tenantId) throws VPException;

    /**
     * Delete a VP submission.
     *
     * @param submissionId The submission identifier
     * @param tenantId     The tenant ID
     * @throws VPSubmissionNotFoundException If the submission is not found
     * @throws VPException                   If an error occurs
     */
    void deleteVPSubmission(String submissionId, int tenantId) 
            throws VPSubmissionNotFoundException, VPException;

    /**
     * Delete all submissions for a given request.
     *
     * @param requestId The request identifier
     * @param tenantId  The tenant ID
     * @throws VPException If an error occurs
     */
    void deleteSubmissionsForRequest(String requestId, int tenantId) throws VPException;
}
