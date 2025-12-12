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

package org.wso2.carbon.identity.openid4vc.issuance.endpoint.credential.factories;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.openid4vc.issuance.credential.CredentialIssuanceService;

/**
 * Factory for retrieving the credential issuance processor instance.
 */
public class CredentialIssuanceServiceFactory {

    private static final CredentialIssuanceService SERVICE;

    static {
        CredentialIssuanceService credentialIssuanceService = (CredentialIssuanceService) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(CredentialIssuanceService.class, null);

        if (credentialIssuanceService == null) {
            throw new IllegalStateException("CredentialIssuanceService is not available from OSGI context.");
        }
        SERVICE = credentialIssuanceService;
    }

    public static CredentialIssuanceService getCredentialIssuanceService() {

        return SERVICE;
    }
}
