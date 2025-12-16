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

package org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.handlers;

import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.issuer.CredentialIssuerContext;

/**
 * Interface for handling different credential formats.
 */
public interface CredentialFormatHandler {

    /**
     * Get the format identifier supported by this handler.
     *
     * @return format identifier (e.g., "jwt_vc_json", "ldp_vc", "vc+sd-jwt")
     */
    String getFormat();

    /**
     * Issue a credential in the specific format.
     *
     * @param credentialIssuerContext the credential issuer context containing necessary data
     * @return the formatted credential as a string
     * @throws CredentialIssuanceException if credential issuance fails
     */
    String issueCredential(CredentialIssuerContext credentialIssuerContext)
            throws CredentialIssuanceException;
}

