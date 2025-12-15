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

package org.wso2.carbon.identity.openid4vc.issuance.metadata.internal;

import org.wso2.carbon.identity.openid4vc.template.management.VCTemplateManager;

/**
 * Data holder for OID4VCI Credential Issuer Metadata.
 */
public class CredentialIssuerMetadataDataHolder {

    private static CredentialIssuerMetadataDataHolder instance = new CredentialIssuerMetadataDataHolder();
    public static CredentialIssuerMetadataDataHolder getInstance() {
        return instance;
    }
    private VCTemplateManager vcTemplateManager;


    public void setVCTemplateManager(VCTemplateManager vcTemplateManager) {
        this.vcTemplateManager = vcTemplateManager;
    }

    public VCTemplateManager getVCCredentialConfigManager() {
        return vcTemplateManager;
    }
}
