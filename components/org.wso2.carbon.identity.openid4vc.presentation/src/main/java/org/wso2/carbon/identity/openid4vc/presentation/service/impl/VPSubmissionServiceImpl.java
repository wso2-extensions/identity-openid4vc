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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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

    private static final Log log = LogFactory.getLog(VPSubmissionServiceImpl.class);

    private final VPSubmissionDAO vpSubmissionDAO;
    private final VPRequestDAO vpRequestDAO;

    /**
     * Default constructor.
     */
    public VPSubmissionServiceImpl() {
        this.vpSubmissionDAO = new VPSubmissionDAOImpl();
        this.vpRequestDAO = new VPRequestDAOImpl();
    }

    /**
     * Constructor for dependency injection.
     */
    public VPSubmissionServiceImpl(VPSubmissionDAO vpSubmissionDAO, VPRequestDAO vpRequestDAO) {
        this.vpSubmissionDAO = vpSubmissionDAO;
        this.vpRequestDAO = vpRequestDAO;
    }

    @Override
    public VPSubmission processVPSubmission(VPSubmissionDTO submissionDTO, int tenantId)
            throws VPRequestNotFoundException, VPRequestExpiredException, VPException {

        log.info("[VP_SUBMISSION] ========== Processing VP Submission ==========");
        log.info("[VP_SUBMISSION] State (Request ID): " + submissionDTO.getState());
        log.info("[VP_SUBMISSION] Tenant ID: " + tenantId);
        log.info("[VP_SUBMISSION] Has VP Token: " + (StringUtils.isNotBlank(submissionDTO.getVpToken())));
        log.info("[VP_SUBMISSION] Has Error: " + (StringUtils.isNotBlank(submissionDTO.getError())));

        // Get the request ID from state parameter
        String requestId = submissionDTO.getState();
        if (StringUtils.isBlank(requestId)) {
            log.error("[VP_SUBMISSION] VALIDATION FAILED: State parameter (request ID) is required");
            throw new VPException("State parameter (request ID) is required");
        }

        log.info("[VP_SUBMISSION] Fetching VP request from database...");
        // Fetch the VP request
        VPRequest vpRequest = vpRequestDAO.getVPRequestById(requestId, tenantId);
        if (vpRequest == null) {
            log.error("[VP_SUBMISSION] VP REQUEST NOT FOUND: " + requestId);
            throw new VPRequestNotFoundException(requestId);
        }

        log.info("[VP_SUBMISSION] VP Request found - Status: " + vpRequest.getStatus());
        log.info("[VP_SUBMISSION] VP Request Expires At: " + vpRequest.getExpiresAt());

        // Check if request has expired
        if (OpenID4VPUtil.isExpired(vpRequest.getExpiresAt())) {
            log.warn("[VP_SUBMISSION] VP REQUEST EXPIRED: " + requestId);
            // Mark as expired in database
            vpRequestDAO.updateVPRequestStatus(requestId, VPRequestStatus.EXPIRED, tenantId);
            log.info("[VP_SUBMISSION] Updated request status to EXPIRED");
            throw new VPRequestExpiredException(requestId);
        }

        // Check if request is still active
        if (vpRequest.getStatus() != VPRequestStatus.ACTIVE) {
            log.error("[VP_SUBMISSION] REQUEST NOT ACTIVE: " + requestId +
                    ", current status: " + vpRequest.getStatus());
            throw new VPException("Request is no longer active: " + requestId +
                    ", current status: " + vpRequest.getStatus());
        }

        log.info("[VP_SUBMISSION] VP Request validation passed");

        // Check if it's an error response from wallet
        if (StringUtils.isNotBlank(submissionDTO.getError())) {
            log.warn("[VP_SUBMISSION] Wallet returned error: " + submissionDTO.getError());
            log.warn("[VP_SUBMISSION] Error description: " + submissionDTO.getErrorDescription());
            return processErrorSubmission(submissionDTO, vpRequest, tenantId);
        }

        // Validate required fields for successful submission
        if (StringUtils.isBlank(submissionDTO.getVpToken())) {
            log.error("[VP_SUBMISSION] VALIDATION FAILED: vp_token is required for successful submission");
            throw new VPException("vp_token is required for successful submission");
        }

        log.info("[VP_SUBMISSION] Creating submission record...");
        // Create submission record
        String submissionId = OpenID4VPUtil.generateSubmissionId();
        String transactionId = OpenID4VPUtil.generateTransactionId();
        long submittedAt = System.currentTimeMillis();

        log.info("[VP_SUBMISSION] Generated Submission ID: " + submissionId);
        log.info("[VP_SUBMISSION] Generated Transaction ID: " + transactionId);

        // Convert presentation submission JsonObject to String for storage
        String presentationSubmissionJson = submissionDTO.getPresentationSubmission() != null
                ? submissionDTO.getPresentationSubmission().toString()
                : null;

        if (presentationSubmissionJson != null) {
            log.info("[VP_SUBMISSION] Presentation submission included (length: " +
                    presentationSubmissionJson.length() + " chars)");
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

        log.info("[VP_SUBMISSION] Persisting submission to database...");
        // Persist submission
        vpSubmissionDAO.createVPSubmission(vpSubmission);
        log.info("[VP_SUBMISSION] Submission persisted successfully");

        log.info("[VP_SUBMISSION] Updating request status to VP_SUBMITTED...");
        // Update request status to VP_SUBMITTED
        vpRequestDAO.updateVPRequestStatus(requestId, VPRequestStatus.VP_SUBMITTED, tenantId);
        log.info("[VP_SUBMISSION] Request status updated successfully");

        log.info("[VP_SUBMISSION] ========== VP Submission Processed Successfully ==========");
        log.info("[VP_SUBMISSION] Submission ID: " + submissionId);
        log.info("[VP_SUBMISSION] Request ID: " + requestId);
        log.info("[VP_SUBMISSION] Transaction ID: " + transactionId);
        log.info("[VP_SUBMISSION] Verification Status: " + VCVerificationStatus.PENDING);
        log.info("[VP_SUBMISSION] ============================================================");

        return vpSubmission;
    }

    /**
     * Process an error response from the wallet.
     */
    private VPSubmission processErrorSubmission(VPSubmissionDTO submissionDTO,
            VPRequest vpRequest, int tenantId)
            throws VPException {

        log.info("[VP_ERROR_SUBMISSION] ========== Processing Wallet Error Submission ==========");
        String requestId = vpRequest.getRequestId();
        log.info("[VP_ERROR_SUBMISSION] Request ID: " + requestId);
        log.info("[VP_ERROR_SUBMISSION] Error Code: " + submissionDTO.getError());
        log.info("[VP_ERROR_SUBMISSION] Error Description: " + submissionDTO.getErrorDescription());

        String submissionId = OpenID4VPUtil.generateSubmissionId();
        String transactionId = OpenID4VPUtil.generateTransactionId();
        long submittedAt = System.currentTimeMillis();

        log.info("[VP_ERROR_SUBMISSION] Generated Submission ID: " + submissionId);
        log.info("[VP_ERROR_SUBMISSION] Generated Transaction ID: " + transactionId);

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

        log.info("[VP_ERROR_SUBMISSION] Persisting error submission to database...");
        // Persist submission
        vpSubmissionDAO.createVPSubmission(vpSubmission);
        log.info("[VP_ERROR_SUBMISSION] Error submission persisted successfully");

        log.info("[VP_ERROR_SUBMISSION] Updating request status to VP_SUBMITTED...");
        // Update request status - still VP_SUBMITTED but with error
        vpRequestDAO.updateVPRequestStatus(requestId, VPRequestStatus.VP_SUBMITTED, tenantId);
        log.info("[VP_ERROR_SUBMISSION] Request status updated successfully");

        log.info("[VP_ERROR_SUBMISSION] ========== Wallet Error Submission Processed ==========");
        log.info("[VP_ERROR_SUBMISSION] Submission ID: " + submissionId);
        log.info("[VP_ERROR_SUBMISSION] Verification Status: " + VCVerificationStatus.ERROR);
        log.info("[VP_ERROR_SUBMISSION] ================================================================");

        return vpSubmission;
    }

    @Override
    public VPSubmission getVPSubmissionById(String submissionId, int tenantId)
            throws VPSubmissionNotFoundException, VPException {

        if (log.isDebugEnabled()) {
            log.debug("[VP_SUBMISSION_QUERY] Fetching VP submission by ID: " + submissionId);
        }

        VPSubmission submission = vpSubmissionDAO.getVPSubmissionById(submissionId, tenantId);

        if (submission == null) {
            log.warn("[VP_SUBMISSION_QUERY] VP submission not found: " + submissionId);
            throw new VPSubmissionNotFoundException(null, submissionId);
        }

        if (log.isDebugEnabled()) {
            log.debug("[VP_SUBMISSION_QUERY] VP submission found - Status: " + submission.getVerificationStatus());
        }

        return submission;
    }

    @Override
    public VPSubmission getVPSubmissionByRequestId(String requestId, int tenantId)
            throws VPSubmissionNotFoundException, VPException {

        if (log.isDebugEnabled()) {
            log.debug("[VP_SUBMISSION_QUERY] Fetching VP submission by request ID: " + requestId);
        }

        VPSubmission submission = vpSubmissionDAO.getVPSubmissionByRequestId(requestId, tenantId);

        if (submission == null) {
            log.warn("[VP_SUBMISSION_QUERY] No VP submission found for request: " + requestId);
            throw new VPSubmissionNotFoundException(null, requestId);
        }

        if (log.isDebugEnabled()) {
            log.debug("[VP_SUBMISSION_QUERY] VP submission found - Submission ID: " + submission.getSubmissionId());
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

        if (log.isDebugEnabled()) {
            log.debug("Deleted VP submission: " + submissionId);
        }
    }

    @Override
    public void deleteSubmissionsForRequest(String requestId, int tenantId) throws VPException {
        vpSubmissionDAO.deleteVPSubmissionsByRequestId(requestId, tenantId);

        if (log.isDebugEnabled()) {
            log.debug("Deleted VP submissions for request: " + requestId);
        }
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

        if (log.isDebugEnabled()) {
            log.debug("Updated verification status for submission: " + submissionId +
                    " to " + status);
        }
    }
}
