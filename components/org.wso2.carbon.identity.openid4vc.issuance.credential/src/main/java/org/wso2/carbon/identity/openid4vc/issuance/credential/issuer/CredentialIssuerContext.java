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

package org.wso2.carbon.identity.openid4vc.issuance.credential.issuer;

import org.wso2.carbon.identity.openid4vc.template.management.model.VCTemplate;

import java.util.HashMap;
import java.util.Map;

/**
 * Context holder for credential issuance process.
 */
public class CredentialIssuerContext {

    private VCTemplate vcTemplate;
    private String configurationId;
    private String tenantDomain;
    private Map<String, String> claims;

    public CredentialIssuerContext() {
        this.claims = new HashMap<>();
    }

    public VCTemplate getVCTemplate() {
        return vcTemplate;
    }

    public void setVCTemplate(VCTemplate vcTemplate) {
        this.vcTemplate = vcTemplate;
    }

    public String getConfigurationId() {
        return configurationId;
    }

    public void setConfigurationId(String configurationId) {
        this.configurationId = configurationId;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    public Map<String, String> getClaims() {
        return claims;
    }

    public void setClaims(Map<String, String> claims) {
        this.claims = claims;
    }
}
