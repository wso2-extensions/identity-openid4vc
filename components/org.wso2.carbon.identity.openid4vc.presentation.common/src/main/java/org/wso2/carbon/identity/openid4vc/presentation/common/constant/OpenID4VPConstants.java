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

package org.wso2.carbon.identity.openid4vc.presentation.common.constant;

/**
 * Constants for OpenID4VP (OpenID for Verifiable Presentations) implementation.
 */
public class OpenID4VPConstants {

    private OpenID4VPConstants() {
        // Prevent instantiation
    }

    /**
     * OpenID4VP Protocol constants.
     */
    public static class Protocol {
        public static final String RESPONSE_TYPE_VP_TOKEN = "vp_token";
        public static final String RESPONSE_MODE_DIRECT_POST = "direct_post";
        public static final String OPENID4VP_SCHEME = "openid4vp://";
        public static final String PRESENTATION_DEFINITION = "presentation_definition";

    }

    /**
     * Request parameter constants.
     */
    public static class RequestParams {
        public static final String CLIENT_ID = "client_id";
        public static final String RESPONSE_TYPE = "response_type";
        public static final String RESPONSE_MODE = "response_mode";
        public static final String RESPONSE_URI = "response_uri";
        public static final String NONCE = "nonce";
        public static final String STATE = "state";
        public static final String REQUEST_URI = "request_uri";

        private RequestParams() {
        }
    }

    /**
     * Response parameter constants.
     */
    public static class ResponseParams {
        public static final String VP_TOKEN = "vp_token";
        public static final String PRESENTATION_SUBMISSION = "presentation_submission";
        public static final String ERROR = "error";
        public static final String ERROR_DESCRIPTION = "error_description";
        public static final String STATE = "state";

        private ResponseParams() {
        }
    }

    /**
     * Error codes as defined in OpenID4VP specification.
     */
    public static class ErrorCodes {
        // OAuth 2.0 Error Codes
        public static final String INVALID_REQUEST = "invalid_request";
        public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
        public static final String ACCESS_DENIED = "access_denied";
        public static final String SERVER_ERROR = "server_error";

        // OpenID4VP Specific Error Codes
        public static final String VP_FORMATS_NOT_SUPPORTED = "vp_formats_not_supported";


        // Wallet Error Codes
        public static final String USER_CANCELLED = "user_cancelled";
        public static final String CREDENTIAL_NOT_AVAILABLE = "credential_not_available";

        private ErrorCodes() {
        }
    }

    /**
     * Verifiable Credential format constants.
     */
    public static class VCFormats {
        public static final String JWT_VP = "jwt_vp";
        public static final String JWT_VP_JSON = "jwt_vp_json";
        public static final String JWT_VC = "jwt_vc";
        public static final String JWT_VC_JSON = "jwt_vc_json";
        public static final String LDP_VP = "ldp_vp";
        public static final String LDP_VC = "ldp_vc";
        public static final String VC_SD_JWT = "vc+sd-jwt";
        public static final String MSO_MDOC = "mso_mdoc";

        private VCFormats() {
        }
    }

    /**
     * HTTP and API constants.
     */
    public static class HTTP {
        public static final String CONTENT_TYPE_JSON = "application/json";
        public static final String CONTENT_TYPE_FORM = "application/x-www-form-urlencoded";

        private HTTP() {
        }
    }

    /**
     * API endpoint paths.
     */
    public static class Endpoints {

        public static final String VP_RESPONSE = "/response";
        public static final String REQUEST_URI = "/request-uri";

        private Endpoints() {
        }
    }

    /**
     * Configuration property keys.
     */
    public static class ConfigKeys {
        public static final String VP_REQUEST_EXPIRY_SECONDS = "OpenID4VP.VPRequestExpirySeconds";
        public static final String DEFAULT_PRESENTATION_DEFINITION_ID = "OpenID4VP.DefaultPresentationDefinitionId";
        public static final String ENABLE_REQUEST_URI = "OpenID4VP.EnableRequestUri";
        public static final String ENABLE_REQUEST_JWT = "OpenID4VP.EnableRequestJWT";
        public static final String SIGNING_ALGORITHM = "OpenID4VP.SigningAlgorithm";
        public static final String VERIFICATION_ENABLED = "OpenID4VP.VerificationEnabled";
        public static final String REVOCATION_CHECK_ENABLED = "OpenID4VP.RevocationCheckEnabled";
        // Credential verification config keys
        public static final String BASE_URL = "OpenID4VP.BaseUrl";

        private ConfigKeys() {
        }
    }

    /**
     * Default configuration values.
     */
    public static class Defaults {
        public static final int VP_REQUEST_EXPIRY_SECONDS = 300; // 5 minutes
        public static final int CACHE_ENTRY_EXPIRY_SECONDS = 300; // 5 minutes
        public static final int MAX_CACHE_ENTRIES = 1000;
        public static final String SIGNING_ALGORITHM = "EdDSA";

        private Defaults() {
        }
    }

    /**
     * Presentation Definition constants.
     */
    public static class PresentationDef {
        public static final String ID = "id";
        public static final String NAME = "name";
        public static final String PURPOSE = "purpose";
        public static final String INPUT_DESCRIPTORS = "input_descriptors";
        public static final String FORMAT = "format";
        public static final String CONSTRAINTS = "constraints";
        public static final String FIELDS = "fields";
        public static final String PATH = "path";
        public static final String FILTER = "filter";

        private PresentationDef() {
        }
    }

    /**
     * Presentation Submission constants.
     */
    public static class PresentationSubmission {
        public static final String ID = "id";
        public static final String DEFINITION_ID = "definition_id";
        public static final String DESCRIPTOR_MAP = "descriptor_map";
        public static final String INPUT_DESCRIPTOR_ID = "id";

        private PresentationSubmission() {
        }
    }

    /**
     * Credential verification constants.
     */
    public static class Verification {
        // Content types for verification requests
        public static final String ALG_EDDSA = "EdDSA";

        private Verification() {
        }
    }

    /**
     * DID (Decentralized Identifier) constants.
     */
    public static class DID {
        // DID methods
        public static final String METHOD_WEB = "web";
        public static final String METHOD_JWK = "jwk";
        public static final String METHOD_KEY = "key";

        // DID document properties
        public static final String DOC_CONTEXT = "@context";
        public static final String DOC_ID = "id";
        public static final String DOC_CONTROLLER = "controller";
        public static final String DOC_VERIFICATION_METHOD = "verificationMethod";
        public static final String DOC_AUTHENTICATION = "authentication";
        public static final String DOC_ASSERTION_METHOD = "assertionMethod";
        public static final String DOC_KEY_AGREEMENT = "keyAgreement";
        public static final String DOC_SERVICE = "service";

        // Verification method properties
        public static final String VM_TYPE = "type";
        public static final String VM_PUBLIC_KEY_JWK = "publicKeyJwk";
        public static final String VM_PUBLIC_KEY_MULTIBASE = "publicKeyMultibase";
        public static final String VM_PUBLIC_KEY_BASE58 = "publicKeyBase58";

        // Verification method types
        public static final String VM_TYPE_JSON_WEB_KEY_2020 = "JsonWebKey2020";
        public static final String VM_TYPE_ED25519_2020 = "Ed25519VerificationKey2020";
        public static final String VM_TYPE_ED25519_2018 = "Ed25519VerificationKey2018";
        public static final String VM_TYPE_ECDSA_SECP256K1_2019 = "EcdsaSecp256k1VerificationKey2019";

        // Default TTL for DID document cache (1 hour)
        public static final long DID_CACHE_TTL_MS = 3600000;

        private DID() {
        }
    }

}
