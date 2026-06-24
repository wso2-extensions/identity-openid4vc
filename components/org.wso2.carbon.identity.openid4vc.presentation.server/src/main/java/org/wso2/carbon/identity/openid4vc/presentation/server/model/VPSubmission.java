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

/**
 * Model class representing a Verifiable Presentation Submission.
 * This stores the VP token submitted by the wallet for transient handoff to the poller.
 */
public class VPSubmission {

    private String state;
    private String vpToken;
    private String presentationSubmission;
    private String error;
    private String errorDescription;

    public VPSubmission() { }

    public String getRequestId() { return state; }
    public void setRequestId(String requestId) { this.state = requestId; }

    public String getVpToken() { return vpToken; }
    public void setVpToken(String vpToken) { this.vpToken = vpToken; }

    public String getPresentationSubmission() { return presentationSubmission; }
    public void setPresentationSubmission(String presentationSubmission) {
        this.presentationSubmission = presentationSubmission;
    }

    public String getError() { return error; }
    public void setError(String error) { this.error = error; }

    public String getErrorDescription() { return errorDescription; }
    public void setErrorDescription(String errorDescription) { this.errorDescription = errorDescription; }

    @Override
    public String toString() {
        return "VPSubmission{state='" + state + '\''
                + ", hasVpToken=" + (vpToken != null && !vpToken.isEmpty())
                + ", hasPresentationSubmission=" + (presentationSubmission != null && !presentationSubmission.isEmpty())
                + '}';
    }
}
