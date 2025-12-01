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

package org.wso2.carbon.identity.openid4vci.metadata.model;

import org.wso2.carbon.identity.openid4vci.common.constant.Constants;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Builder for creating OpenID4VCI Credential Configuration metadata structures.
 * This builder follows the OpenID for Verifiable Credential Issuance specification.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OpenID4VCI Specification</a>
 */
public class CredentialConfigurationMetadataBuilder {

    private String id;
    private String format;
    private String scope;
    private List<String> signingAlgorithms = new ArrayList<>();
    private Object display = Collections.emptyList();
    private List<String> claims;

    /**
     * Set the credential configuration identifier.
     *
     * @param id the configuration identifier
     * @return this builder
     */
    public CredentialConfigurationMetadataBuilder id(String id) {
        this.id = id;
        return this;
    }

    /**
     * Set the credential format (e.g., "jwt_vc_json").
     *
     * @param format the credential format
     * @return this builder
     */
    public CredentialConfigurationMetadataBuilder format(String format) {
        this.format = format;
        return this;
    }

    /**
     * Set the scope required to request this credential.
     *
     * @param scope the scope
     * @return this builder
     */
    public CredentialConfigurationMetadataBuilder scope(String scope) {
        this.scope = scope;
        return this;
    }

    /**
     * Add a signing algorithm to the supported algorithms list.
     *
     * @param algorithm the signing algorithm (e.g., "RS256")
     * @return this builder
     */
    public CredentialConfigurationMetadataBuilder signingAlgorithm(String algorithm) {
        if (algorithm != null && !algorithm.isEmpty()) {
            this.signingAlgorithms.add(algorithm);
        }
        return this;
    }

    /**
     * Set the display metadata (parsed from JSON).
     *
     * @param display the display object
     * @return this builder
     */
    public CredentialConfigurationMetadataBuilder display(Object display) {
        this.display = display != null ? display : Collections.emptyList();
        return this;
    }

    /**
     * Set the claims list.
     *
     * @param claims the list of claim names
     * @return this builder
     */
    public CredentialConfigurationMetadataBuilder claims(List<String> claims) {
        this.claims = claims;
        return this;
    }

    /**
     * Build the credential configuration metadata as a Map according to OpenID4VCI specification.
     *
     * @return the credential configuration metadata structure
     */
    public Map<String, Object> build() {
        Map<String, Object> config = new LinkedHashMap<>();

        // Basic fields
        if (id != null) {
            config.put(Constants.W3CVCDataModel.ID, id);
        }
        if (format != null) {
            config.put(Constants.CredentialIssuerMetadata.FORMAT, format);
        }
        if (scope != null) {
            config.put(Constants.CredentialIssuerMetadata.SCOPE, scope);
        }

        // Signing algorithms
        config.put(Constants.CredentialIssuerMetadata.CREDENTIAL_SIGNING_ALG_VALUES_SUPPORTED,
                signingAlgorithms);

        // Credential metadata with display and claims
        Map<String, Object> credentialMetadata = new LinkedHashMap<>();
        credentialMetadata.put(Constants.CredentialIssuerMetadata.DISPLAY, display);
        credentialMetadata.put(Constants.CredentialIssuerMetadata.CLAIMS, buildClaimsList(claims));
        config.put(Constants.CredentialIssuerMetadata.CREDENTIAL_METADATA, credentialMetadata);

        return config;
    }

    /**
     * Convert a list of claim names to the OpenID4VCI claims structure.
     *
     * @param claims the list of claim names
     * @return the list of claim objects with path
     */
    private List<Map<String, Object>> buildClaimsList(List<String> claims) {
        if (claims == null) {
            return Collections.emptyList();
        }
        return claims.stream().map(claim -> {
            Map<String, Object> claimMap = new LinkedHashMap<>();
            claimMap.put(Constants.CredentialIssuerMetadata.PATH, Collections.singletonList(claim));
            return claimMap;
        }).collect(Collectors.toList());
    }
}

