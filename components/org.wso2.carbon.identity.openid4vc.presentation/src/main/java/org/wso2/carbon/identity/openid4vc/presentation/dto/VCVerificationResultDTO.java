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
 * Provides comprehensive information about each credential's verification
 * status.
 */
public class VCVerificationResultDTO {

    private static final long serialVersionUID = 1L;

    @SerializedName("vcIndex")
    private int vcIndex;

    @SerializedName("verificationStatus")
    private String verificationStatus;

    @SerializedName("credentialType")
    private String credentialType;

    @SerializedName("credentialTypes")
    private String[] credentialTypes;

    @SerializedName("issuer")
    private String issuer;

    @SerializedName("issuerId")
    private String issuerId;

    @SerializedName("subject")
    private String subject;

    @SerializedName("issuanceDate")
    private String issuanceDate;

    @SerializedName("expirationDate")
    private String expirationDate;

    @SerializedName("credentialId")
    private String credentialId;

    @SerializedName("format")
    private String format;

    @SerializedName("signatureValid")
    private Boolean signatureValid;

    @SerializedName("expired")
    private Boolean expired;

    @SerializedName("revoked")
    private Boolean revoked;

    @SerializedName("error")
    private String error;

    @SerializedName("errorDetails")
    private String errorDetails;

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

    public String[] getCredentialTypes() {
        return credentialTypes;
    }

    public void setCredentialTypes(String[] credentialTypes) {
        this.credentialTypes = credentialTypes;
    }

    public String getIssuerId() {
        return issuerId;
    }

    public void setIssuerId(String issuerId) {
        this.issuerId = issuerId;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getIssuanceDate() {
        return issuanceDate;
    }

    public void setIssuanceDate(String issuanceDate) {
        this.issuanceDate = issuanceDate;
    }

    public String getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(String expirationDate) {
        this.expirationDate = expirationDate;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public Boolean getSignatureValid() {
        return signatureValid;
    }

    public void setSignatureValid(Boolean signatureValid) {
        this.signatureValid = signatureValid;
    }

    public Boolean getExpired() {
        return expired;
    }

    public void setExpired(Boolean expired) {
        this.expired = expired;
    }

    public Boolean getRevoked() {
        return revoked;
    }

    public void setRevoked(Boolean revoked) {
        this.revoked = revoked;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getErrorDetails() {
        return errorDetails;
    }

    public void setErrorDetails(String errorDetails) {
        this.errorDetails = errorDetails;
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

    /**
     * Builder class for comprehensive result construction.
     */
    public static class Builder {

        private final VCVerificationResultDTO dto = new VCVerificationResultDTO();

        public Builder vcIndex(int vcIndex) {
            dto.vcIndex = vcIndex;
            return this;
        }

        public Builder verificationStatus(VCVerificationStatus status) {
            dto.verificationStatus = status != null ? status.getValue() : null;
            return this;
        }

        public Builder credentialType(String credentialType) {
            dto.credentialType = credentialType;
            return this;
        }

        public Builder credentialTypes(String[] credentialTypes) {
            dto.credentialTypes = credentialTypes;
            return this;
        }

        public Builder issuer(String issuer) {
            dto.issuer = issuer;
            return this;
        }

        public Builder issuerId(String issuerId) {
            dto.issuerId = issuerId;
            return this;
        }

        public Builder subject(String subject) {
            dto.subject = subject;
            return this;
        }

        public Builder issuanceDate(String issuanceDate) {
            dto.issuanceDate = issuanceDate;
            return this;
        }

        public Builder expirationDate(String expirationDate) {
            dto.expirationDate = expirationDate;
            return this;
        }

        public Builder credentialId(String credentialId) {
            dto.credentialId = credentialId;
            return this;
        }

        public Builder format(String format) {
            dto.format = format;
            return this;
        }

        public Builder signatureValid(Boolean signatureValid) {
            dto.signatureValid = signatureValid;
            return this;
        }

        public Builder expired(Boolean expired) {
            dto.expired = expired;
            return this;
        }

        public Builder revoked(Boolean revoked) {
            dto.revoked = revoked;
            return this;
        }

        public Builder error(String error) {
            dto.error = error;
            return this;
        }

        public Builder errorDetails(String errorDetails) {
            dto.errorDetails = errorDetails;
            return this;
        }

        public VCVerificationResultDTO build() {
            return dto;
        }
    }

    @Override
    public String toString() {
        return "VCVerificationResultDTO{" +
                "vcIndex=" + vcIndex +
                ", verificationStatus='" + verificationStatus + '\'' +
                ", credentialType='" + credentialType + '\'' +
                ", issuer='" + issuer + '\'' +
                ", format='" + format + '\'' +
                ", signatureValid=" + signatureValid +
                ", expired=" + expired +
                ", revoked=" + revoked +
                ", error='" + error + '\'' +
                '}';
    }
}
