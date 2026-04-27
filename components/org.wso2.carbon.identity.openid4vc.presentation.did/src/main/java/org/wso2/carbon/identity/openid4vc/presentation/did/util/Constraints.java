/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.did.util;

/**
 * Utility class for constants used in the DID component.
 */
public final class Constraints {

    private Constraints() {
    }

    // DID Methods
    public static final String METHOD_WEB = "web";

    // DID Prefixes
    public static final String DID_WEB_PREFIX = "did:web:";

    // URLs
    public static final String UNIVERSAL_RESOLVER_URL = "https://dev.uniresolver.io/1.0/identifiers/";
    public static final String DID_V1_CONTEXT = "https://www.w3.org/ns/did/v1";
    public static final String ED25519_2020_CONTEXT = "https://w3id.org/security/suites/ed25519-2020/v1";

    // Verification Method Types
    public static final String ED25519_VERIFICATION_KEY_2020 = "Ed25519VerificationKey2020";

    // Key Fragments
    public static final String ED25519_KEY_ID_FRAGMENT = "#ed25519";

    // Cache Settings
    public static final long DEFAULT_CACHE_TTL_MS = 3600000;

    // HTTP Settings
    public static final int CONNECTION_TIMEOUT_MS = 10000;
    public static final int READ_TIMEOUT_MS = 10000;
}
