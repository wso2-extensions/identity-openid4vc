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
import org.wso2.carbon.identity.openid4vc.presentation.model.VCVerificationStatus;

/**
 * Data Transfer Object for individual VC verification result.
 */
public class VCVerificationResultDTO {

    @SerializedName("vcIndex")
    private int vcIndex;

    @SerializedName("verificationStatus")
    private String verificationStatus;

    @SerializedName("credentialType")
    private String credentialType;

    @SerializedName("issuer")
    private String issuer;

    @SerializedName("error")
    private String error;

    /**
     * Default constructor.
     */
    public VCVerificationResultDTO() {
    }

    /**
     * Constructor for successful verification.
     *
     * @param vcIndex            Index of the VC in the VP
     * @param verificationStatus Verification status
     * @param credentialType     Type of the credential
     * @param issuer             Issuer of the credential
     */
    public VCVerificationResultDTO(int vcIndex, VCVerificationStatus verificationStatus,
                                    String credentialType, String issuer) {
        this.vcIndex = vcIndex;
        this.verificationStatus = verificationStatus.getValue();
        this.credentialType = credentialType;
        this.issuer = issuer;
    }

    /**
     * Constructor for failed verification.
     *
     * @param vcIndex            Index of the VC in the VP
     * @param verificationStatus Verification status
     * @param error              Error message
     */
    public VCVerificationResultDTO(int vcIndex, VCVerificationStatus verificationStatus, String error) {
        this.vcIndex = vcIndex;
        this.verificationStatus = verificationStatus.getValue();
        this.error = error;
    }

    // Getters and Setters

    public int getVcIndex() {
        return vcIndex;
    }

    public void setVcIndex(int vcIndex) {
        this.vcIndex = vcIndex;
    }

    public String getVerificationStatus() {
        return verificationStatus;
    }

    public void setVerificationStatus(String verificationStatus) {
        this.verificationStatus = verificationStatus;
    }

    public void setVerificationStatus(VCVerificationStatus status) {
        this.verificationStatus = status != null ? status.getValue() : null;
    }

    public String getCredentialType() {
        return credentialType;
    }

    public void setCredentialType(String credentialType) {
        this.credentialType = credentialType;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    /**
     * Get verification status as enum.
     *
     * @return VCVerificationStatus enum or null
     */
    public VCVerificationStatus getVerificationStatusEnum() {
        return VCVerificationStatus.fromValue(verificationStatus);
    }

    /**
     * Check if verification was successful.
     *
     * @return true if SUCCESS
     */
    public boolean isSuccess() {
        VCVerificationStatus status = getVerificationStatusEnum();
        return status != null && status.isSuccess();
    }

    @Override
    public String toString() {
        return "VCVerificationResultDTO{" +
                "vcIndex=" + vcIndex +
                ", verificationStatus='" + verificationStatus + '\'' +
                ", credentialType='" + credentialType + '\'' +
                ", issuer='" + issuer + '\'' +
                ", error='" + error + '\'' +
                '}';
    }
}
