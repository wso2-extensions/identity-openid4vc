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

package org.wso2.carbon.identity.openid4vc.issuance.metadata.model;

import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Builder for creating OpenID4VCI template metadata structures.
 * This builder follows the OpenID for Verifiable Credential Issuance specification.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OpenID4VCI Specification</a>
 */
public class CredentialConfigurationMetadataBuilder {

    private String id;
    private String format;
    private String scope;
    private List<String> signingAlgorithms = new ArrayList<>();
    private List<String> types = new ArrayList<>();
    private Object display = Collections.emptyList();
    private List<String> claims;

    /**
     * Set the template identifier.
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
     * Add a credential type to the type array.
     *
     * @param type the credential type (e.g., "VerifiableCredential", "EmployeeBadge")
     * @return this builder
     */
    public CredentialConfigurationMetadataBuilder type(String type) {

        if (type != null && !type.isEmpty()) {
            this.types.add(type);
        }
        return this;
    }

    /**
     * Set the display.
     *
     * @param displayName the display name
     * @return this builder
     */
    public CredentialConfigurationMetadataBuilder display(String displayName) {

        if (displayName != null && !displayName.isEmpty()) {
            Map<String, Object> displayObject = new LinkedHashMap<>();
            displayObject.put(Constants.CredentialIssuerMetadata.NAME, displayName);
            this.display = Collections.singletonList(displayObject);
        } else {
            this.display = Collections.emptyList();
        }
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
     * Build the template metadata as a Map according to OpenID4VCI specification.
     *
     * @return the template metadata structure
     */
    public Map<String, Object> build() {

        Map<String, Object> config = new LinkedHashMap<>();

        if (id != null) {
            config.put(Constants.W3CVCDataModel.ID, id);
        }
        if (format != null) {
            config.put(Constants.CredentialIssuerMetadata.FORMAT, format);
        }
        if (scope != null) {
            config.put(Constants.CredentialIssuerMetadata.SCOPE, scope);
        }

        config.put(Constants.CredentialIssuerMetadata.CREDENTIAL_SIGNING_ALG_VALUES_SUPPORTED,
                signingAlgorithms);

        if (!types.isEmpty()) {
            Map<String, Object> credentialDefinition = new LinkedHashMap<>();
            credentialDefinition.put(Constants.W3CVCDataModel.TYPE, types);
            config.put(Constants.CredentialIssuerMetadata.CREDENTIAL_DEFINITION, credentialDefinition);
        }

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
            List<String> path = new ArrayList<>();
            path.add(Constants.W3CVCDataModel.CREDENTIAL_SUBJECT);
            path.add(claim);
            claimMap.put(Constants.CredentialIssuerMetadata.PATH, path);
            return claimMap;
        }).collect(Collectors.toList());
    }


}

