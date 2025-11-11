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

package org.wso2.carbon.identity.openid4vci.metadata.response;

import java.util.Collections;
import java.util.Map;

/**
 * Response wrapper containing credential issuer metadata values.
 */
public class CredentialIssuerMetadataResponse {

    private final Map<String, Object> metadata;

    public CredentialIssuerMetadataResponse(Map<String, Object> metadata) {

        this.metadata = metadata == null ? Collections.emptyMap() : metadata;
    }

    public Map<String, Object> getMetadata() {

        return Collections.unmodifiableMap(metadata);
    }
}
