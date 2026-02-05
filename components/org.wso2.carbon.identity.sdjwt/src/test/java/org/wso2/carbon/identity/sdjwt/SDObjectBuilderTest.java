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

package org.wso2.carbon.identity.sdjwt;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.sdjwt.constant.SDJWTConstants;
import org.wso2.carbon.identity.sdjwt.exception.SDJWTException;

import java.util.List;
import java.util.Map;

/**
 * Test class for SDObjectBuilder.
 * Tests building SD-JWT payloads with selectively disclosable claims.
 */
public class SDObjectBuilderTest {

    @Test(priority = 1, description = "Test building payload with normal and SD claims")
    public void testBuildPayloadWithMixedClaims() throws SDJWTException {
        SDObjectBuilder builder = new SDObjectBuilder();

        // Add normal claims
        builder.putClaim("iss", "https://example.com");
        builder.putClaim("iat", 1234567890);

        // Add SD claims
        builder.putSDClaim("email", "user@example.com");
        builder.putSDClaim("name", "John Doe");

        Map<String, Object> payload = builder.build();

        // Verify normal claims are present
        Assert.assertEquals(payload.get("iss"), "https://example.com");
        Assert.assertEquals(payload.get("iat"), 1234567890);

        // Verify _sd array exists
        Assert.assertTrue(payload.containsKey(SDJWTConstants.CLAIM_SD));
        List<?> sdArray = (List<?>) payload.get(SDJWTConstants.CLAIM_SD);
        Assert.assertEquals(sdArray.size(), 2);

        // Verify _sd_alg is included
        Assert.assertEquals(payload.get(SDJWTConstants.CLAIM_SD_ALG), SDJWTConstants.HASH_ALG_SHA256);

        // Verify disclosures
        List<Disclosure> disclosures = builder.getDisclosures();
        Assert.assertEquals(disclosures.size(), 2);
    }

    @Test(priority = 2, description = "Test adding decoy digests")
    public void testDecoyDigests() throws SDJWTException {
        SDObjectBuilder builder = new SDObjectBuilder();

        builder.putSDClaim("email", "user@example.com");
        builder.putDecoyDigests(3);

        Map<String, Object> payload = builder.build();

        // Should have 4 digests total (1 real + 3 decoys)
        List<?> sdArray = (List<?>) payload.get(SDJWTConstants.CLAIM_SD);
        Assert.assertEquals(sdArray.size(), 4);

        // But only 1 real disclosure
        Assert.assertEquals(builder.getSDClaimCount(), 1);
        Assert.assertEquals(builder.getTotalDigestCount(), 4);
    }

    @Test(priority = 3, description = "Test custom hash algorithm")
    public void testCustomHashAlgorithm() throws SDJWTException {
        SDObjectBuilder builder = new SDObjectBuilder(SDJWTConstants.HASH_ALG_SHA512);

        builder.putSDClaim("email", "user@example.com");

        Map<String, Object> payload = builder.build();

        Assert.assertEquals(payload.get(SDJWTConstants.CLAIM_SD_ALG), SDJWTConstants.HASH_ALG_SHA512);
    }

    @Test(priority = 4, description = "Test method chaining")
    public void testMethodChaining() throws SDJWTException {
        Map<String, Object> payload = new SDObjectBuilder()
                .putClaim("iss", "https://example.com")
                .putSDClaim("email", "user@example.com")
                .putDecoyDigests(2)
                .build();

        Assert.assertNotNull(payload);
        Assert.assertTrue(payload.containsKey("iss"));
        Assert.assertTrue(payload.containsKey(SDJWTConstants.CLAIM_SD));
    }

    @Test(priority = 5, description = "Test building empty payload")
    public void testEmptyPayload() {
        SDObjectBuilder builder = new SDObjectBuilder();

        Map<String, Object> payload = builder.build();

        // Should only contain _sd_alg
        Assert.assertTrue(payload.containsKey(SDJWTConstants.CLAIM_SD_ALG));
        Assert.assertFalse(payload.containsKey(SDJWTConstants.CLAIM_SD));
    }
}

