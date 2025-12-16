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

package org.wso2.carbon.identity.openid4vc.issuance.credential.internal;

import org.wso2.carbon.identity.oauth.tokenprocessor.DefaultTokenProvider;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenProvider;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.handlers.CredentialFormatHandler;
import org.wso2.carbon.identity.openid4vc.template.management.VCTemplateManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.List;

/**
 * Data holder for OID4VCI credential issuance component.
 */
public class CredentialIssuanceDataHolder {

    private static final CredentialIssuanceDataHolder instance = new CredentialIssuanceDataHolder();
    private VCTemplateManager vcTemplateManager;
    private final List<CredentialFormatHandler> credentialFormatHandlers = new ArrayList<>();
    private TokenProvider tokenProvider;
    private RealmService realmService;

    private CredentialIssuanceDataHolder() {

    }

    public static CredentialIssuanceDataHolder getInstance() {

        return instance;
    }

    public VCTemplateManager getVCTemplateManager() {

        return vcTemplateManager;
    }

    public void setVCTemplateManager(VCTemplateManager vcTemplateManager) {

        this.vcTemplateManager = vcTemplateManager;
    }

    public List<CredentialFormatHandler> getCredentialFormatHandlers() {

        return credentialFormatHandlers;
    }

    public void addCredentialFormatHandler(CredentialFormatHandler handler) {

        this.credentialFormatHandlers.add(handler);
    }

    public void removeCredentialFormatHandler(CredentialFormatHandler handler) {

        this.credentialFormatHandlers.remove(handler);
    }

    public TokenProvider getTokenProvider() {

        if (tokenProvider == null) {
            tokenProvider = new DefaultTokenProvider();
        }
        return tokenProvider;
    }

    public void setTokenProvider(TokenProvider tokenProvider) {

        this.tokenProvider = tokenProvider;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }
}
