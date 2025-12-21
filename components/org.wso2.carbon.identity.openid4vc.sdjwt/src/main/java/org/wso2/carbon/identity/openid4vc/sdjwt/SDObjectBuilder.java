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

package org.wso2.carbon.identity.openid4vc.sdjwt;

import org.wso2.carbon.identity.openid4vc.sdjwt.constant.SDJWTConstants;
import org.wso2.carbon.identity.openid4vc.sdjwt.exception.SDJWTException;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builder class for creating an SD-JWT payload with the "_sd" array.
 * <p>
 * This builder helps construct a Map that can be used as the payload of an SD-JWT.
 * It handles:
 * - Normal (always visible) claims
 * - Selectively disclosable claims (added to "_sd" array)
 * - Decoy digests for privacy enhancement
 */
public class SDObjectBuilder {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final String hashAlgorithm;
    private final Map<String, Object> claims;
    private final List<String> sdDigests;
    private final List<Disclosure> disclosures;

    /**
     * Create an SDObjectBuilder with the default hash algorithm (SHA-256).
     */
    public SDObjectBuilder() {

        this(SDJWTConstants.DEFAULT_HASH_ALGORITHM);
    }

    /**
     * Create an SDObjectBuilder with a specified hash algorithm.
     *
     * @param hashAlgorithm The hash algorithm to use for computing digests
     */
    public SDObjectBuilder(String hashAlgorithm) {

        this.hashAlgorithm = hashAlgorithm;
        this.claims = new LinkedHashMap<>();
        this.sdDigests = new ArrayList<>();
        this.disclosures = new ArrayList<>();
    }

    /**
     * Add a normal (always visible) claim to the payload.
     *
     * @param name  The claim name
     * @param value The claim value
     * @return This builder for chaining
     */
    public SDObjectBuilder putClaim(String name, Object value) {

        claims.put(name, value);
        return this;
    }

    /**
     * Add a selectively disclosable claim using an existing Disclosure.
     *
     * @param disclosure The disclosure to add
     * @return This builder for chaining
     * @throws SDJWTException If digest computation fails
     */
    public SDObjectBuilder putSDClaim(Disclosure disclosure) throws SDJWTException {

        String digest = disclosure.digest(hashAlgorithm);
        sdDigests.add(digest);
        disclosures.add(disclosure);
        return this;
    }

    /**
     * Add a selectively disclosable claim by name and value.
     * A new Disclosure will be created with an auto-generated salt.
     *
     * @param claimName  The claim name
     * @param claimValue The claim value
     * @return This builder for chaining
     * @throws SDJWTException If digest computation fails
     */
    public SDObjectBuilder putSDClaim(String claimName, Object claimValue) throws SDJWTException {

        return putSDClaim(new Disclosure(claimName, claimValue));
    }

    /**
     * Add a selectively disclosable claim with explicit salt.
     *
     * @param salt       The salt value
     * @param claimName  The claim name
     * @param claimValue The claim value
     * @return This builder for chaining
     * @throws SDJWTException If digest computation fails
     */
    public SDObjectBuilder putSDClaim(String salt, String claimName, Object claimValue) throws SDJWTException {

        return putSDClaim(new Disclosure(salt, claimName, claimValue));
    }

    /**
     * Add a decoy digest for privacy enhancement.
     * Decoy digests make it harder for verifiers to determine the number of actual claims.
     *
     * @return This builder for chaining
     */
    public SDObjectBuilder putDecoyDigest() {

        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        String decoy = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        sdDigests.add(decoy);
        return this;
    }

    /**
     * Add multiple decoy digests.
     *
     * @param count The number of decoy digests to add
     * @return This builder for chaining
     */
    public SDObjectBuilder putDecoyDigests(int count) {

        for (int i = 0; i < count; i++) {
            putDecoyDigest();
        }
        return this;
    }

    /**
     * Build the payload Map with the "_sd" array and optionally the "_sd_alg" claim.
     *
     * @param includeHashAlgorithm If true, includes the "_sd_alg" claim in the result
     * @return The constructed payload Map
     */
    public Map<String, Object> build(boolean includeHashAlgorithm) {

        Map<String, Object> result = new LinkedHashMap<>(claims);

        if (!sdDigests.isEmpty()) {
            // Shuffle digests to prevent correlation based on order
            List<String> shuffled = new ArrayList<>(sdDigests);
            Collections.shuffle(shuffled, SECURE_RANDOM);
            result.put(SDJWTConstants.CLAIM_SD, shuffled);
        }

        if (includeHashAlgorithm) {
            result.put(SDJWTConstants.CLAIM_SD_ALG, hashAlgorithm);
        }

        return result;
    }

    /**
     * Build the payload Map with the "_sd" array and "_sd_alg" claim.
     *
     * @return The constructed payload Map
     */
    public Map<String, Object> build() {

        return build(true);
    }

    /**
     * Get all disclosures created during building.
     * Does not include decoy digests.
     *
     * @return List of Disclosure objects
     */
    public List<Disclosure> getDisclosures() {

        return new ArrayList<>(disclosures);
    }

    /**
     * Get the hash algorithm used by this builder.
     *
     * @return The hash algorithm
     */
    public String getHashAlgorithm() {

        return hashAlgorithm;
    }

    /**
     * Get the number of SD claims added (excluding decoys).
     *
     * @return Number of SD claims
     */
    public int getSDClaimCount() {

        return disclosures.size();
    }

    /**
     * Get the total number of digests in the _sd array (including decoys).
     *
     * @return Total digest count
     */
    public int getTotalDigestCount() {

        return sdDigests.size();
    }
}
