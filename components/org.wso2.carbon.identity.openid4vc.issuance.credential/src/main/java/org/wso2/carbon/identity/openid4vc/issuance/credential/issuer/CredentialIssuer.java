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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceServerException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.internal.CredentialIssuanceDataHolder;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.handlers.CredentialFormatHandler;

import java.util.List;

/**
 * Credential issuer that delegates to format-specific handlers.
 */
public class CredentialIssuer {

    private static final Log LOG = LogFactory.getLog(CredentialIssuer.class);

    /**
     * Issue a credential based on the format.
     *
     * @param credentialIssuerContext the credential issuer context containing necessary data
     * @return the issued credential
     * @throws CredentialIssuanceException if issuance fails or format is not supported
     */
    public String issueCredential(CredentialIssuerContext credentialIssuerContext)
            throws CredentialIssuanceException {

        String format = credentialIssuerContext.getVCTemplate().getFormat();
        List<CredentialFormatHandler> formatHandlers = CredentialIssuanceDataHolder.getInstance()
                .getCredentialFormatHandlers();
        CredentialFormatHandler handler = formatHandlers.stream()
                .filter(h -> format.equals(h.getFormat()))
                .findFirst()
                .orElseThrow(() -> new CredentialIssuanceServerException("Unsupported credential format: " + format));
        if (LOG.isDebugEnabled()) {
            LOG.debug("Issuing credential with format: " + format +
                     " for configuration: " + credentialIssuerContext.getConfigurationId());
        }

        return handler.issueCredential(credentialIssuerContext);
    }
}

