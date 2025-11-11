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

package org.wso2.carbon.identity.openid4vci.metadata.response.builder.impl;

import com.google.gson.Gson;
import org.wso2.carbon.identity.openid4vci.metadata.exception.CredentialIssuerMetadataException;
import org.wso2.carbon.identity.openid4vci.metadata.response.CredentialIssuerMetadataResponse;
import org.wso2.carbon.identity.openid4vci.metadata.response.builder.CredentialIssuerMetadataResponseBuilder;

import java.util.Map;

/**
 * Build JSON responses for credential issuer metadata.
 */
public class CredentialIssuerMetadataJSONResponseBuilder implements CredentialIssuerMetadataResponseBuilder {

    private static final Gson GSON = new Gson();

    @Override
    public String build(CredentialIssuerMetadataResponse metadataResponse) throws CredentialIssuerMetadataException {

        if (metadataResponse == null) {
            throw new CredentialIssuerMetadataException("Metadata response is null");
        }
        Map<String, Object> metadata = metadataResponse.getMetadata();
        return GSON.toJson(metadata);
    }
}
