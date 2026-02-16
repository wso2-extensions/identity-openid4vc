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
        
        // Context storage keys
        public static final String OPENID4VP_VP_TOKEN = "openid4vp_vp_token";
        public static final String OPENID4VP_PRESENTATION_SUBMISSION = "openid4vp_presentation_submission";

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
        public static final String VP_RESPONSE = "/response";
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
        public static final String LONG_POLLING_TIMEOUT_SECONDS = "OpenID4VP.LongPollingTimeoutSeconds";
        public static final String LONG_POLLING_ENABLED = "OpenID4VP.LongPollingEnabled";
        // Credential verification config keys
        public static final String SIGNATURE_VERIFICATION_ENABLED = 
        "OpenID4VP.Verification.SignatureVerificationEnabled";
        public static final String EXPIRATION_CHECK_ENABLED = "OpenID4VP.Verification.ExpirationCheckEnabled";
        public static final String SUPPORTED_PROOF_TYPES = "OpenID4VP.Verification.SupportedProofTypes";
        public static final String SUPPORTED_ALGORITHMS = "OpenID4VP.Verification.SupportedAlgorithms";
        // DID resolution config keys
        public static final String DID_RESOLUTION_ENABLED = "OpenID4VP.DID.ResolutionEnabled";
        public static final String DID_SUPPORTED_METHODS = "OpenID4VP.DID.SupportedMethods";
        public static final String DID_CACHE_TTL_SECONDS = "OpenID4VP.DID.CacheTTLSeconds";
        public static final String DID_UNIVERSAL_RESOLVER_URL = "OpenID4VP.DID.UniversalResolverUrl";
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
        public static final int LONG_POLLING_TIMEOUT_SECONDS = 60; // 1 minute
        public static final int MAX_LONG_POLLING_TIMEOUT_SECONDS = 120; // 2 minutes
        public static final int MIN_LONG_POLLING_TIMEOUT_SECONDS = 5;
        public static final java.util.List<String> SUPPORTED_VC_FORMATS = java.util.Collections.unmodifiableList(
                java.util.Arrays.asList(
                        VCFormats.JWT_VP_JSON,
                        VCFormats.JWT_VC_JSON,
                        VCFormats.LDP_VP,
                        VCFormats.LDP_VC,
                        VCFormats.VC_SD_JWT));

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
        public static final String DID_DOCUMENT_PREFIX = "DID_DOC_";

        private CacheKeys() {
        }
    }

    /**
     * Credential verification constants.
     */
    public static class Verification {
        // Content types for verification requests
        public static final String CONTENT_TYPE_VC_LD_JSON = "application/vc+ld+json";
        public static final String CONTENT_TYPE_VC_JWT = "application/vc+jwt";
        public static final String CONTENT_TYPE_VC_SD_JWT = "application/vc+sd-jwt";
        public static final String CONTENT_TYPE_JWT = "application/jwt";

        // Proof types for JSON-LD credentials
        public static final String PROOF_TYPE_ED25519_2020 = "Ed25519Signature2020";
        public static final String PROOF_TYPE_ED25519_2018 = "Ed25519Signature2018";
        public static final String PROOF_TYPE_JSON_WEB_SIG_2020 = "JsonWebSignature2020";
        public static final String PROOF_TYPE_ECDSA_SECP256K1_2019 = "EcdsaSecp256k1Signature2019";

        // JWT algorithms
        public static final String ALG_RS256 = "RS256";
        public static final String ALG_RS384 = "RS384";
        public static final String ALG_RS512 = "RS512";
        public static final String ALG_ES256 = "ES256";
        public static final String ALG_ES384 = "ES384";
        public static final String ALG_ES512 = "ES512";
        public static final String ALG_ES256K = "ES256K";
        public static final String ALG_EDDSA = "EdDSA";
        public static final String ALG_PS256 = "PS256";

        // Credential status types
        public static final String STATUS_TYPE_STATUS_LIST_2021 = "StatusList2021Entry";
        public static final String STATUS_TYPE_REVOCATION_LIST_2020 = "RevocationList2020Status";

        // Credential subject fields
        public static final String CREDENTIAL_SUBJECT_ID = "id";

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

    /**
     * Revocation constants for credential status checking.
     */
    public static class Revocation {
        // Status list types
        public static final String STATUS_LIST_2021 = "StatusList2021";
        public static final String STATUS_LIST_2021_ENTRY = "StatusList2021Entry";
        public static final String BITSTRING_STATUS_LIST = "BitstringStatusList";
        public static final String BITSTRING_STATUS_LIST_ENTRY = "BitstringStatusListEntry";
        public static final String REVOCATION_LIST_2020 = "RevocationList2020";
        public static final String REVOCATION_LIST_2020_STATUS = "RevocationList2020Status";

        // Status purposes
        public static final String PURPOSE_REVOCATION = "revocation";
        public static final String PURPOSE_SUSPENSION = "suspension";
        public static final String PURPOSE_MESSAGE = "message";

        // Status list credential properties
        public static final String ENCODED_LIST = "encodedList";
        public static final String STATUS_PURPOSE = "statusPurpose";
        public static final String STATUS_LIST_INDEX = "statusListIndex";
        public static final String STATUS_LIST_CREDENTIAL = "statusListCredential";

        // Cache settings
        public static final long STATUS_LIST_CACHE_TTL_MS = 300000; // 5 minutes
        public static final int HTTP_TIMEOUT_MS = 10000;

        // Minimum bitstring size per spec (16KB = 131,072 bits)
        public static final int MIN_BITSTRING_SIZE = 16 * 1024;

        private Revocation() {
        }
    }

    /**
     * Trusted verifier constants.
     */
    public static class TrustedVerifier {
        // Trust levels
        public static final String TRUST_LEVEL_BASIC = "BASIC";
        public static final String TRUST_LEVEL_STANDARD = "STANDARD";
        public static final String TRUST_LEVEL_ELEVATED = "ELEVATED";
        public static final String TRUST_LEVEL_FULL = "FULL";

        // Verifier status
        public static final String STATUS_ACTIVE = "ACTIVE";
        public static final String STATUS_SUSPENDED = "SUSPENDED";
        public static final String STATUS_REVOKED = "REVOKED";
        public static final String STATUS_PENDING = "PENDING";

        // Redirect URI validation modes
        public static final String REDIRECT_URI_MODE_STRICT = "STRICT";
        public static final String REDIRECT_URI_MODE_RELAXED = "RELAXED";
        public static final String REDIRECT_URI_MODE_DISABLED = "DISABLED";

        private TrustedVerifier() {
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
