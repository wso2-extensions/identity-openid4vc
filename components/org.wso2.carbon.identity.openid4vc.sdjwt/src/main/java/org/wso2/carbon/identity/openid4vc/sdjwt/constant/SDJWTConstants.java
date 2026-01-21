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

package org.wso2.carbon.identity.openid4vc.sdjwt.constant;

/**
 * Constants for SD-JWT specification.
 * Based on RFC 9901.
 */
public final class SDJWTConstants {

    private SDJWTConstants() {
        // Private constructor to prevent instantiation
    }

    /**
     * The claim name for the array of digests of selectively disclosable claims.
     */
    public static final String CLAIM_SD = "_sd";

    /**
     * The claim name for the hash algorithm used to compute digests.
     */
    public static final String CLAIM_SD_ALG = "_sd_alg";

    /**
     * The key used in array element placeholders for selectively disclosable array elements.
     */
    public static final String ARRAY_ELEMENT_KEY = "...";

    /**
     * SHA-256 hash algorithm identifier as defined in IANA Named Information Hash Algorithm Registry.
     */
    public static final String HASH_ALG_SHA256 = "sha-256";

    /**
     * SHA-384 hash algorithm identifier.
     */
    public static final String HASH_ALG_SHA384 = "sha-384";

    /**
     * SHA-512 hash algorithm identifier.
     */
    public static final String HASH_ALG_SHA512 = "sha-512";

    /**
     * Default hash algorithm to use for SD-JWT.
     */
    public static final String DEFAULT_HASH_ALGORITHM = HASH_ALG_SHA256;

    /**
     * OpenID4VCI format identifier for SD-JWT Verifiable Credentials.
     */
    public static final String FORMAT_VC_SD_JWT = "vc+sd-jwt";

    /**
     * JWT typ header value for SD-JWT VCs (Issuer-signed JWT).
     */
    public static final String TYP_VC_SD_JWT = "vc+sd-jwt";

    /**
     * JWT typ header value for Key Binding JWT.
     */
    public static final String TYP_KB_JWT = "kb+jwt";

    /**
     * Separator character used between JWT and Disclosures in SD-JWT string representation.
     */
    public static final String DISCLOSURE_SEPARATOR = "~";

    /**
     * Default salt length in bytes (128 bits as recommended by spec).
     */
    public static final int DEFAULT_SALT_LENGTH_BYTES = 16;

    /**
     * The claim name for Verifiable Credential Type in SD-JWT VC.
     */
    public static final String CLAIM_VCT = "vct";
}
