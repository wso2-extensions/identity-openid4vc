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

package org.wso2.carbon.identity.openid4vc.issuance.credential.dto;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

/**
 * DTO for credential issuance request.
 */
public class CredentialIssuanceReqDTO {

    private String tenantDomain;
    private String credentialConfigurationId;
    private String token;
    AuthenticatedUser authenticatedUser;

    public String getTenantDomain() {

        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {

        this.tenantDomain = tenantDomain;
    }

    public String getCredentialConfigurationId() {

        return credentialConfigurationId;
    }

    public void setCredentialConfigurationId(String credentialConfigurationId) {

        this.credentialConfigurationId = credentialConfigurationId;
    }

    public String getToken() {

        return token;
    }

    public void setToken(String token) {

        this.token = token;
    }

    public AuthenticatedUser getAuthenticatedUser() {

        return authenticatedUser;
    }

    public void setAuthenticatedUser(AuthenticatedUser authenticatedUser) {

        this.authenticatedUser = authenticatedUser;
    }
}
