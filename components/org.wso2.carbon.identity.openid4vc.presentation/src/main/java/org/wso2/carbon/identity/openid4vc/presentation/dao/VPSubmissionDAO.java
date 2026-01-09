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

package org.wso2.carbon.identity.openid4vc.presentation.dao;

import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.model.VCVerificationStatus;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPSubmission;

import java.util.List;

/**
 * Data Access Object interface for VP Submission operations.
 */
public interface VPSubmissionDAO {

    /**
     * Create a new VP submission.
     *
     * @param vpSubmission VP submission to create
     * @throws VPException if creation fails
     */
    void createVPSubmission(VPSubmission vpSubmission) throws VPException;

    /**
     * Get VP submission by submission ID.
     *
     * @param submissionId Submission ID
     * @param tenantId     Tenant ID
     * @return VP submission or null if not found
     * @throws VPException if retrieval fails
     */
    VPSubmission getVPSubmissionById(String submissionId, int tenantId) throws VPException;

    /**
     * Get VP submission by request ID.
     *
     * @param requestId Request ID
     * @param tenantId  Tenant ID
     * @return VP submission or null if not found
     * @throws VPException if retrieval fails
     */
    VPSubmission getVPSubmissionByRequestId(String requestId, int tenantId) throws VPException;

    /**
     * Get VP submissions by request IDs.
     *
     * @param requestIds List of request IDs
     * @param tenantId   Tenant ID
     * @return List of VP submissions
     * @throws VPException if retrieval fails
     */
    List<VPSubmission> getVPSubmissionsByRequestIds(List<String> requestIds, int tenantId) 
            throws VPException;

    /**
     * Update verification status for a submission.
     *
     * @param submissionId       Submission ID
     * @param verificationStatus New verification status
     * @param verificationResult Verification result JSON
     * @param tenantId           Tenant ID
     * @throws VPException if update fails
     */
    void updateVerificationStatus(String submissionId, VCVerificationStatus verificationStatus,
                                   String verificationResult, int tenantId) throws VPException;

    /**
     * Delete VP submission.
     *
     * @param submissionId Submission ID
     * @param tenantId     Tenant ID
     * @throws VPException if deletion fails
     */
    void deleteVPSubmission(String submissionId, int tenantId) throws VPException;

    /**
     * Delete VP submissions by request ID.
     *
     * @param requestId Request ID
     * @param tenantId  Tenant ID
     * @throws VPException if deletion fails
     */
    void deleteVPSubmissionsByRequestId(String requestId, int tenantId) throws VPException;

    /**
     * Check if a submission exists for a request.
     *
     * @param requestId Request ID
     * @param tenantId  Tenant ID
     * @return true if submission exists
     * @throws VPException if check fails
     */
    boolean hasSubmissionForRequest(String requestId, int tenantId) throws VPException;
}
