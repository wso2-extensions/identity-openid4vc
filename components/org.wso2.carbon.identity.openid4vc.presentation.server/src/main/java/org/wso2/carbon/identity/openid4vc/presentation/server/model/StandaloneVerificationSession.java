/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.server.model;

import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;

import java.io.Serializable;

/**
 * Session model for a standalone (API-initiated) VP verification request.
 */
public class StandaloneVerificationSession implements Serializable {

    private static final long serialVersionUID = 1L;

    private String txnId;
    private String presentationDefinitionId;
    private String tenantDomain;
    private int tenantId;
    private VPRequestStatus status;
    private VerificationResult verificationResult;
    private String nonce;
    private String ephemeralPrivateKeyJwk;
    private long expiresAt;
    private String clientId;
    private String clientIdScheme;
    private String responseUri;
    private String responseMode;
    private String registrationCert;

    public String getTxnId() { return txnId; }
    public void setTxnId(String txnId) { this.txnId = txnId; }

    public String getPresentationDefinitionId() { return presentationDefinitionId; }
    public void setPresentationDefinitionId(String presentationDefinitionId) {
        this.presentationDefinitionId = presentationDefinitionId;
    }

    public String getTenantDomain() { return tenantDomain; }
    public void setTenantDomain(String tenantDomain) { this.tenantDomain = tenantDomain; }

    public int getTenantId() { return tenantId; }
    public void setTenantId(int tenantId) { this.tenantId = tenantId; }

    public VPRequestStatus getStatus() { return status; }
    public void setStatus(VPRequestStatus status) { this.status = status; }

    public VerificationResult getVerificationResult() { return verificationResult; }
    public void setVerificationResult(VerificationResult verificationResult) {
        this.verificationResult = verificationResult;
    }

    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }

    public String getEphemeralPrivateKeyJwk() { return ephemeralPrivateKeyJwk; }
    public void setEphemeralPrivateKeyJwk(String ephemeralPrivateKeyJwk) {
        this.ephemeralPrivateKeyJwk = ephemeralPrivateKeyJwk;
    }

    public long getExpiresAt() { return expiresAt; }
    public void setExpiresAt(long expiresAt) { this.expiresAt = expiresAt; }

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getClientIdScheme() { return clientIdScheme; }
    public void setClientIdScheme(String clientIdScheme) { this.clientIdScheme = clientIdScheme; }

    public String getResponseUri() { return responseUri; }
    public void setResponseUri(String responseUri) { this.responseUri = responseUri; }

    public String getResponseMode() { return responseMode; }
    public void setResponseMode(String responseMode) { this.responseMode = responseMode; }

    public String getRegistrationCert() { return registrationCert; }
    public void setRegistrationCert(String registrationCert) { this.registrationCert = registrationCert; }
}
