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

package org.wso2.carbon.identity.openid4vc.presentation.constant;

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
        public static final String RESPONSE_MODE_DIRECT_POST_JWT = "direct_post.jwt";
        public static final String CLIENT_ID_SCHEME_DID = "did";
        public static final String CLIENT_ID_SCHEME_X509 = "x509_san_dns";
        public static final String CLIENT_ID_SCHEME_PRE_REGISTERED = "pre-registered";
        public static final String OPENID4VP_SCHEME = "openid4vp://";
        public static final String PRESENTATION_DEFINITION = "presentation_definition";
        public static final String PRESENTATION_DEFINITION_URI = "presentation_definition_uri";
        
        private Protocol() {
        }
    }

    /**
     * Request parameter constants.
     */
    public static class RequestParams {
        public static final String CLIENT_ID = "client_id";
        public static final String CLIENT_ID_SCHEME = "client_id_scheme";
        public static final String RESPONSE_TYPE = "response_type";
        public static final String RESPONSE_MODE = "response_mode";
        public static final String RESPONSE_URI = "response_uri";
        public static final String REDIRECT_URI = "redirect_uri";
        public static final String NONCE = "nonce";
        public static final String STATE = "state";
        public static final String REQUEST = "request";
        public static final String REQUEST_URI = "request_uri";
        public static final String SCOPE = "scope";
        public static final String VP_TOKEN = "vp_token";
        public static final String PRESENTATION_SUBMISSION = "presentation_submission";
        public static final String ID_TOKEN = "id_token";
        public static final String TRANSACTION_ID = "transaction_id";
        
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
        public static final String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
        public static final String INVALID_SCOPE = "invalid_scope";
        public static final String SERVER_ERROR = "server_error";
        
        // OpenID4VP Specific Error Codes
        public static final String VP_FORMATS_NOT_SUPPORTED = "vp_formats_not_supported";
        public static final String INVALID_PRESENTATION_DEFINITION_URI = "invalid_presentation_definition_uri";
        public static final String INVALID_PRESENTATION_DEF_REF = "invalid_presentation_definition_reference";

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
     * JWT claim constants.
     */
    public static class JWTClaims {
        public static final String ISS = "iss";
        public static final String SUB = "sub";
        public static final String AUD = "aud";
        public static final String IAT = "iat";
        public static final String EXP = "exp";
        public static final String NBF = "nbf";
        public static final String JTI = "jti";
        public static final String NONCE = "nonce";
        public static final String VP = "vp";
        public static final String VC = "vc";
        
        private JWTClaims() {
        }
    }

    /**
     * HTTP and API constants.
     */
    public static class HTTP {
        public static final String CONTENT_TYPE_JSON = "application/json";
        public static final String CONTENT_TYPE_JWT = "application/jwt";
        public static final String CONTENT_TYPE_FORM = "application/x-www-form-urlencoded";
        public static final String AUTHORIZATION_HEADER = "Authorization";
        public static final String BEARER_PREFIX = "Bearer ";
        
        private HTTP() {
        }
    }

    /**
     * API endpoint paths.
     */
    public static class Endpoints {
        public static final String AUTHORIZE = "/authorize";
        public static final String VP_REQUEST = "/vp-request";
        public static final String VP_RESPONSE = "/vp-response";
        public static final String VP_STATUS = "/vp-status";
        public static final String VP_RESULT = "/vp-result";
        public static final String PRESENTATION_DEFINITIONS = "/presentation-definitions";
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
        public static final String SUPPORTED_VC_FORMATS = "OpenID4VP.SupportedVCFormats";
        public static final String ENABLE_REQUEST_URI = "OpenID4VP.EnableRequestUri";
        public static final String ENABLE_REQUEST_JWT = "OpenID4VP.EnableRequestJWT";
        public static final String SIGNING_ALGORITHM = "OpenID4VP.SigningAlgorithm";
        public static final String VERIFICATION_ENABLED = "OpenID4VP.VerificationEnabled";
        public static final String REVOCATION_CHECK_ENABLED = "OpenID4VP.RevocationCheckEnabled";
        public static final String TRUSTED_ISSUERS = "OpenID4VP.TrustedIssuers";
        
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
        public static final String SIGNING_ALGORITHM = "RS256";
        public static final String[] SUPPORTED_VC_FORMATS = {
            VCFormats.JWT_VP_JSON,
            VCFormats.JWT_VC_JSON,
            VCFormats.LDP_VP,
            VCFormats.LDP_VC,
            VCFormats.VC_SD_JWT
        };
        
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
        public static final String LIMIT_DISCLOSURE = "limit_disclosure";
        public static final String SUBMISSION_REQUIREMENTS = "submission_requirements";
        
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
        public static final String FORMAT = "format";
        public static final String PATH = "path";
        public static final String PATH_NESTED = "path_nested";
        
        private PresentationSubmission() {
        }
    }

    /**
     * Cache key prefixes.
     */
    public static class CacheKeys {
        public static final String VP_REQUEST_PREFIX = "VP_REQUEST_";
        public static final String VP_SUBMISSION_PREFIX = "VP_SUBMISSION_";
        public static final String PRESENTATION_DEF_PREFIX = "PRES_DEF_";
        public static final String TRANSACTION_PREFIX = "TXN_";
        
        private CacheKeys() {
        }
    }

    /**
     * Logging constants.
     */
    public static class Logging {
        public static final String COMPONENT_ID = "openid4vp";
        public static final String LOG_PREFIX = "[OpenID4VP] ";
        
        private Logging() {
        }
    }
}
