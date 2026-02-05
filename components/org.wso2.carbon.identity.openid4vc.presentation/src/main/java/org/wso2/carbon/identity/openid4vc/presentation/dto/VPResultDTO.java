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

package org.wso2.carbon.identity.openid4vc.presentation.dto;

import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
import java.util.List;

/**
 * Data Transfer Object for VP verification result.
 * Provides comprehensive verification results for a verifiable presentation.
 */
public class VPResultDTO {

    @SerializedName("transactionId")
    private String transactionId;

    @SerializedName("requestId")
    private String requestId;

    @SerializedName("status")
    private String status;

    @SerializedName("overallResult")
    private String overallResult;

    @SerializedName("verificationTimestamp")
    private Long verificationTimestamp;

    @SerializedName("holder")
    private String holder;

    @SerializedName("presentationDefinitionId")
    private String presentationDefinitionId;

    @SerializedName("vcCount")
    private Integer vcCount;

    @SerializedName("vcVerificationResults")
    private List<VCVerificationResultDTO> vcVerificationResults;

    @SerializedName("error")
    private String error;

    @SerializedName("errorDescription")
    private String errorDescription;

    /**
     * Default constructor.
     */
    public VPResultDTO() {
        this.vcVerificationResults = new ArrayList<>();
    }

    /**
     * Constructor with transaction ID.
     *
     * @param transactionId Transaction ID
     */
    public VPResultDTO(String transactionId) {
        this.transactionId = transactionId;
        this.vcVerificationResults = new ArrayList<>();
    }

    /**
     * Constructor for error result.
     *
     * @param transactionId    Transaction ID
     * @param error            Error code
     * @param errorDescription Error description
     */
    public VPResultDTO(String transactionId, String error, String errorDescription) {
        this.transactionId = transactionId;
        this.error = error;
        this.errorDescription = errorDescription;
        this.vcVerificationResults = new ArrayList<>();
    }

    // Getters and Setters

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

    public String getPresentationDefinitionId() {
        return presentationDefinitionId;
    }

    public void setPresentationDefinitionId(String presentationDefinitionId) {
        this.presentationDefinitionId = presentationDefinitionId;
    }

    public Integer getVcCount() {
        return vcCount;
    }

    public void setVcCount(Integer vcCount) {
        this.vcCount = vcCount;
    }

    public List<VCVerificationResultDTO> getVcVerificationResults() {
        if (vcVerificationResults == null) {
            return new ArrayList<>();
        }
        return new ArrayList<>(vcVerificationResults);
    }

    public void setVcVerificationResults(List<VCVerificationResultDTO> vcVerificationResults) {
        if (vcVerificationResults == null) {
            this.vcVerificationResults = new ArrayList<>();
        } else {
            this.vcVerificationResults = new ArrayList<>(vcVerificationResults);
        }
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
    }

    /**
     * Add a VC verification result.
     *
     * @param result VC verification result to add
     */
    public void addVcVerificationResult(VCVerificationResultDTO result) {
        if (this.vcVerificationResults == null) {
            this.vcVerificationResults = new ArrayList<>();
        }
        this.vcVerificationResults.add(result);
    }

    /**
     * Check if this result contains an error.
     *
     * @return true if error is present
     */
    public boolean hasError() {
        return error != null && !error.trim().isEmpty();
    }

    /**
     * Check if all VC verifications were successful.
     *
     * @return true if all VCs verified successfully
     */
    public boolean isAllSuccess() {
        if (hasError() || vcVerificationResults == null || vcVerificationResults.isEmpty()) {
            return false;
        }
        return vcVerificationResults.stream()
                .allMatch(VCVerificationResultDTO::isSuccess);
    }

    @Override
    public String toString() {
        return "VPResultDTO{" +
                "transactionId='" + transactionId + '\'' +
                ", vcVerificationResultsCount=" +
                (vcVerificationResults != null ? vcVerificationResults.size() : 0) +
                ", hasError=" + hasError() +
                '}';
    }
}
