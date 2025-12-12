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

package org.wso2.carbon.identity.openid4vc.issuance.endpoint.metadata.factories;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.CredentialIssuerMetadataProcessor;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.DefaultCredentialIssuerMetadataProcessor;

/**
 * Factory for retrieving the credential issuer metadata processor instance.
 */
public class CredentialIssuerMetadataServiceFactory {

    private static final DefaultCredentialIssuerMetadataProcessor METADATA_PROCESSOR;

    static {
        DefaultCredentialIssuerMetadataProcessor defaultCredentialIssuerMetadataProcessor
                = (DefaultCredentialIssuerMetadataProcessor) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(CredentialIssuerMetadataProcessor.class, null);

        if (defaultCredentialIssuerMetadataProcessor == null) {
            throw new IllegalStateException("DefaultCredentialIssuerMetadataProcessor is not available from " +
                    "OSGI context.");
        }
        METADATA_PROCESSOR = defaultCredentialIssuerMetadataProcessor;
    }

    public static CredentialIssuerMetadataProcessor getMetadataProcessor() {

        return METADATA_PROCESSOR;
    }
}
