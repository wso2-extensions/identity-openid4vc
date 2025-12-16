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

package org.wso2.carbon.identity.openid4vc.issuance.common.constant;

/**
 * Constants related to OpenID for Verifiable Credential Issuance (OID4VCI).
 */
public class Constants {
    public static final String CONTEXT_OPENID4VCI = "oid4vci";
    public static final String SEGMENT_CREDENTIAL = "credential";
    public static final String SEGMENT_OAUTH2 = "oauth2";
    public static final String SEGMENT_TOKEN = "token";
    public static final String VC_CLAIM = "vc";
    public static final String JWT_VC_JSON_FORMAT = "jwt_vc_json";
    public static final String CREDENTIAL_CONFIGURATION_ID = "credential_configuration_id";

    /**
     * W3C Verifiable Credential Data Model related constants.
     * These constants are specific to the W3C Verifiable Credentials Data Model specification.
     * @see <a href="https://www.w3.org/TR/vc-data-model/">W3C Verifiable Credentials Data Model</a>
     */
    public static class W3CVCDataModel {
        public static final String CONTEXT = "@context";
        public static final String ID = "id";
        public static final String TYPE = "type";
        public static final String ISSUER = "issuer";
        public static final String VALID_FROM = "validFrom";
        public static final String VALID_UNTIL = "validUntil";
        public static final String CREDENTIAL_SUBJECT = "credentialSubject";

        public static final String W3C_CREDENTIALS_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2";
        public static final String VERIFIABLE_CREDENTIAL_TYPE = "VerifiableCredential";
    }

    /**
     * OpenID4VCI Credential Issuer Metadata related constants.
     * These constants are specific to the OpenID for Verifiable Credential Issuance specification.
     */
    public static class CredentialIssuerMetadata {
        public static final String CREDENTIAL_ISSUER = "credential_issuer";
        public static final String CREDENTIAL_ENDPOINT = "credential_endpoint";
        public static final String AUTHORIZATION_SERVERS = "authorization_servers";
        public static final String CREDENTIAL_CONFIGURATIONS_SUPPORTED = "credential_configurations_supported";

        public static final String FORMAT = "format";
        public static final String SCOPE = "scope";
        public static final String CREDENTIAL_SIGNING_ALG_VALUES_SUPPORTED = "credential_signing_alg_values_supported";
        public static final String CREDENTIAL_DEFINITION = "credential_definition";
        public static final String CREDENTIAL_METADATA = "credential_metadata";
        public static final String DISPLAY = "display";
        public static final String CLAIMS = "claims";
        public static final String NAME = "name";
        public static final String PATH = "path";
        public static final String SUBJECT_IDENTIFIER = "sub";
    }

    /**
     * OpenID4VCI Credential Offer related constants.
     * These constants are specific to the OpenID for Verifiable Credential Issuance credential offer structure.
     */
    public static class CredentialOffer {
        public static final String CREDENTIAL_ISSUER = "credential_issuer";
        public static final String CREDENTIAL_CONFIGURATION_IDS = "credential_configuration_ids";
        public static final String GRANTS = "grants";
        public static final String AUTHORIZATION_CODE = "authorization_code";
        public static final String AUTHORIZATION_SERVER = "authorization_server";
    }
}
