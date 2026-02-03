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

package org.wso2.carbon.identity.openid4vc.presentation.service.impl;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.cache.VPRequestCache;
import org.wso2.carbon.identity.openid4vc.presentation.dao.VPRequestDAO;
import org.wso2.carbon.identity.openid4vc.presentation.dao.VPSubmissionDAO;
import org.wso2.carbon.identity.openid4vc.presentation.dao.impl.VPRequestDAOImpl;
import org.wso2.carbon.identity.openid4vc.presentation.dao.impl.VPSubmissionDAOImpl;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VCVerificationResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.dto.VPSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPRequestExpiredException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.exception.VPSubmissionNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.model.VCVerificationStatus;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.service.VPSubmissionService;
import org.wso2.carbon.identity.openid4vc.presentation.util.OpenID4VPUtil;

import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of VPSubmissionService for handling VP submissions from
 * wallets.
 */
public class VPSubmissionServiceImpl implements VPSubmissionService {

    private final VPSubmissionDAO vpSubmissionDAO;
    private final VPRequestDAO vpRequestDAO;
    private final VPRequestCache vpRequestCache;

    /**
     * Default constructor.
     */
    public VPSubmissionServiceImpl() {
        this.vpSubmissionDAO = new VPSubmissionDAOImpl();
        this.vpRequestDAO = new VPRequestDAOImpl();
        this.vpRequestCache = VPRequestCache.getInstance();
    }

    /**
     * Constructor for dependency injection.
     */
    public VPSubmissionServiceImpl(VPSubmissionDAO vpSubmissionDAO, VPRequestDAO vpRequestDAO) {
        this.vpSubmissionDAO = vpSubmissionDAO;
        this.vpRequestDAO = vpRequestDAO;
        this.vpRequestCache = VPRequestCache.getInstance();
    }

    @Override
    public VPSubmission processVPSubmission(VPSubmissionDTO submissionDTO, int tenantId)
            throws VPRequestNotFoundException, VPRequestExpiredException, VPException {

        // Get the request ID from state parameter
        String requestId = submissionDTO.getState();
        if (StringUtils.isBlank(requestId)) {
            throw new VPException("State parameter (request ID) is required");
        }

        // Fetch the VP request
        VPRequest vpRequest = vpRequestDAO.getVPRequestById(requestId, tenantId);
        if (vpRequest == null) {
            throw new VPRequestNotFoundException(requestId);
        }

        // Check if request has expired
        if (OpenID4VPUtil.isExpired(vpRequest.getExpiresAt())) {
            // Mark as expired in database
            // Mark as expired in database
            vpRequestDAO.updateVPRequestStatus(requestId, VPRequestStatus.EXPIRED, tenantId);
            // INVALIDATE CACHE
            if (vpRequestCache != null) {
                vpRequestCache.remove(requestId);
            }
            throw new VPRequestExpiredException(requestId);
        }

        // Check if request is still active
        if (vpRequest.getStatus() != VPRequestStatus.ACTIVE) {
            throw new VPException("Request is no longer active: " + requestId +
                    ", current status: " + vpRequest.getStatus());
        }

        // Check if it's an error response from wallet
        if (StringUtils.isNotBlank(submissionDTO.getError())) {
            return processErrorSubmission(submissionDTO, vpRequest, tenantId);
        }

        // Validate required fields for successful submission
        if (StringUtils.isBlank(submissionDTO.getVpToken())) {
            throw new VPException("vp_token is required for successful submission");
        }

        // Create submission record
        // Use the transaction ID from the request for consistency
        String transactionId = vpRequest.getTransactionId();
        if (StringUtils.isBlank(transactionId)) {
            transactionId = OpenID4VPUtil.generateTransactionId();
        }

        String submissionId = OpenID4VPUtil.generateSubmissionId();
        long submittedAt = System.currentTimeMillis();

        // Convert presentation submission JsonObject to String for storage
        String presentationSubmissionJson = submissionDTO.getPresentationSubmission() != null
                ? submissionDTO.getPresentationSubmission().toString()
                : null;

        if (presentationSubmissionJson != null) {
        }

        VPSubmission vpSubmission = new VPSubmission.Builder()
                .submissionId(submissionId)
                .requestId(requestId)
                .transactionId(transactionId)
                .vpToken(submissionDTO.getVpToken())
                .presentationSubmission(presentationSubmissionJson)
                .verificationStatus(VCVerificationStatus.PENDING)
                .submittedAt(submittedAt)
                .tenantId(tenantId)
                .build();

        // Persist submission
        vpSubmissionDAO.createVPSubmission(vpSubmission);

        // Update request status to VP_SUBMITTED
        vpRequestDAO.updateVPRequestStatus(requestId, VPRequestStatus.VP_SUBMITTED, tenantId);
        // INVALIDATE CACHE: Ensure subsequent reads pick up the new status
        if (vpRequestCache != null) {
            vpRequestCache.remove(requestId);
        }

        return vpSubmission;
    }

    /**
     * Process an error response from the wallet.
     */
    private VPSubmission processErrorSubmission(VPSubmissionDTO submissionDTO,
            VPRequest vpRequest, int tenantId)
            throws VPException {

        String requestId = vpRequest.getRequestId();

        String submissionId = OpenID4VPUtil.generateSubmissionId();
        String transactionId = OpenID4VPUtil.generateTransactionId();
        long submittedAt = System.currentTimeMillis();

        // Create submission record with error
        VPSubmission vpSubmission = new VPSubmission.Builder()
                .submissionId(submissionId)
                .requestId(requestId)
                .transactionId(transactionId)
                .error(submissionDTO.getError())
                .errorDescription(submissionDTO.getErrorDescription())
                .verificationStatus(VCVerificationStatus.ERROR)
                .submittedAt(submittedAt)
                .tenantId(tenantId)
                .build();

        // Persist submission
        vpSubmissionDAO.createVPSubmission(vpSubmission);

        // Update request status - still VP_SUBMITTED but with error
        vpRequestDAO.updateVPRequestStatus(requestId, VPRequestStatus.VP_SUBMITTED, tenantId);
        // INVALIDATE CACHE
        if (vpRequestCache != null) {
            vpRequestCache.remove(requestId);
        }

        return vpSubmission;
    }

    @Override
    public VPSubmission getVPSubmissionById(String submissionId, int tenantId)
            throws VPSubmissionNotFoundException, VPException {

        VPSubmission submission = vpSubmissionDAO.getVPSubmissionById(submissionId, tenantId);

        if (submission == null) {
            throw new VPSubmissionNotFoundException(null, submissionId);
        }

        return submission;
    }

    @Override
    public VPSubmission getVPSubmissionByRequestId(String requestId, int tenantId)
            throws VPSubmissionNotFoundException, VPException {

        VPSubmission submission = vpSubmissionDAO.getVPSubmissionByRequestId(requestId, tenantId);

        if (submission == null) {
            throw new VPSubmissionNotFoundException(null, requestId);
        }

        return submission;
    }

    @Override
    public VPResultDTO getVPResult(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPSubmissionNotFoundException, VPException {

        // Find request by transaction ID
        VPRequest vpRequest = vpRequestDAO.getVPRequestByTransactionId(transactionId, tenantId);
        if (vpRequest == null) {
            throw new VPRequestNotFoundException("Transaction not found: " + transactionId);
        }

        // Get all request IDs for this transaction (in case of multiple)
        List<String> requestIds = vpRequestDAO.getRequestIdsByTransactionId(transactionId, tenantId);

        // Get submissions for these requests
        List<VPSubmission> submissions = vpSubmissionDAO.getVPSubmissionsByRequestIds(
                requestIds, tenantId);

        if (submissions.isEmpty()) {
            throw new VPSubmissionNotFoundException(transactionId, null);
        }

        // Build result DTO
        VPResultDTO resultDTO = new VPResultDTO();
        resultDTO.setTransactionId(transactionId);

        // Check for wallet errors
        for (VPSubmission submission : submissions) {
            if (StringUtils.isNotBlank(submission.getError())) {
                resultDTO.setError(submission.getError());
                resultDTO.setErrorDescription(submission.getErrorDescription());
                return resultDTO;
            }
        }

        // Build verification results
        List<VCVerificationResultDTO> vcResults = new ArrayList<>();
        int vcIndex = 0;

        for (VPSubmission submission : submissions) {
            VCVerificationResultDTO vcResult = new VCVerificationResultDTO();
            vcResult.setVcIndex(vcIndex++);
            vcResult.setVerificationStatus(submission.getVerificationStatus());

            // Parse verification result if available
            if (StringUtils.isNotBlank(submission.getVerificationResult())) {
                // TODO: Parse JSON and extract details
                vcResult.setCredentialType("VerifiableCredential");
            }

            vcResults.add(vcResult);
        }

        resultDTO.setVcVerificationResults(vcResults);

        return resultDTO;
    }

    @Override
    public boolean hasSubmission(String requestId, int tenantId) throws VPException {
        return vpSubmissionDAO.hasSubmissionForRequest(requestId, tenantId);
    }

    @Override
    public void deleteVPSubmission(String submissionId, int tenantId)
            throws VPSubmissionNotFoundException, VPException {

        // Verify exists
        getVPSubmissionById(submissionId, tenantId);

        // Delete
        vpSubmissionDAO.deleteVPSubmission(submissionId, tenantId);

    }

    @Override
    public void deleteSubmissionsForRequest(String requestId, int tenantId) throws VPException {
        vpSubmissionDAO.deleteVPSubmissionsByRequestId(requestId, tenantId);

    }

    /**
     * Update the verification status and result for a submission.
     */
    public void updateVerificationResult(String submissionId, VCVerificationStatus status,
            String verificationResult, int tenantId)
            throws VPSubmissionNotFoundException, VPException {

        // Verify exists
        getVPSubmissionById(submissionId, tenantId);

        // Update status
        vpSubmissionDAO.updateVerificationStatus(submissionId, status, verificationResult, tenantId);

    }
}
