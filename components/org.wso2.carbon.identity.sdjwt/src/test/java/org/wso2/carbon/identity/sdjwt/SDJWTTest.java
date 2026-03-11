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

import java.util.Arrays;
import java.util.List;

/**
 * Test class for SDJWT.
 * Tests SD-JWT creation, serialization, and parsing.
 */
public class SDJWTTest {

    private static final String TEST_ISSUER_SIGNED_JWT =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIn0.signature";
    private static final String TEST_KEY_BINDING_JWT =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJub25jZSI6IjEyMzQ1In0.signature";

    @Test(priority = 1, description = "Test creating and serializing SD-JWT without Key Binding")
    public void testCreateAndSerializeWithoutKeyBinding() {
        List<Disclosure> disclosures = createTestDisclosures();
        SDJWT sdJwt = new SDJWT(TEST_ISSUER_SIGNED_JWT, disclosures);

        // Verify properties
        Assert.assertEquals(sdJwt.getIssuerSignedJwt(), TEST_ISSUER_SIGNED_JWT);
        Assert.assertEquals(sdJwt.getDisclosureCount(), 2);
        Assert.assertFalse(sdJwt.hasKeyBinding());

        // Verify serialization format: JWT~disc1~disc2~
        String serialized = sdJwt.serialize();
        Assert.assertTrue(serialized.startsWith(TEST_ISSUER_SIGNED_JWT));
        Assert.assertTrue(serialized.endsWith(SDJWTConstants.DISCLOSURE_SEPARATOR));
        Assert.assertEquals(serialized.split(SDJWTConstants.DISCLOSURE_SEPARATOR, -1).length - 1, 3);
    }

    @Test(priority = 2, description = "Test creating and serializing SD-JWT with Key Binding")
    public void testCreateAndSerializeWithKeyBinding() {
        List<Disclosure> disclosures = createTestDisclosures();
        SDJWT sdJwt = new SDJWT(TEST_ISSUER_SIGNED_JWT, disclosures, TEST_KEY_BINDING_JWT);

        // Verify properties
        Assert.assertTrue(sdJwt.hasKeyBinding());
        Assert.assertEquals(sdJwt.getKeyBindingJwt(), TEST_KEY_BINDING_JWT);

        // Verify serialization format: JWT~disc1~disc2~KB-JWT
        String serialized = sdJwt.serialize();
        Assert.assertTrue(serialized.endsWith(TEST_KEY_BINDING_JWT));
    }

    @Test(priority = 3, description = "Test parsing SD-JWT without Key Binding")
    public void testParseWithoutKeyBinding() throws SDJWTException {
        String disc1 = new Disclosure("salt1", "email", "user@example.com").getDisclosure();
        String disc2 = new Disclosure("salt2", "name", "John").getDisclosure();
        String sdJwtString = TEST_ISSUER_SIGNED_JWT + SDJWTConstants.DISCLOSURE_SEPARATOR +
                disc1 + SDJWTConstants.DISCLOSURE_SEPARATOR +
                disc2 + SDJWTConstants.DISCLOSURE_SEPARATOR;

        SDJWT parsed = SDJWT.parse(sdJwtString);

        Assert.assertEquals(parsed.getIssuerSignedJwt(), TEST_ISSUER_SIGNED_JWT);
        Assert.assertEquals(parsed.getDisclosureCount(), 2);
        Assert.assertFalse(parsed.hasKeyBinding());
    }

    @Test(priority = 4, description = "Test round-trip serialization and parsing")
    public void testRoundTrip() throws SDJWTException {
        List<Disclosure> originalDisclosures = createTestDisclosures();
        SDJWT original = new SDJWT(TEST_ISSUER_SIGNED_JWT, originalDisclosures, TEST_KEY_BINDING_JWT);

        String serialized = original.serialize();
        SDJWT parsed = SDJWT.parse(serialized);

        Assert.assertEquals(parsed.getIssuerSignedJwt(), original.getIssuerSignedJwt());
        Assert.assertEquals(parsed.getDisclosureCount(), original.getDisclosureCount());
        Assert.assertEquals(parsed.getKeyBindingJwt(), original.getKeyBindingJwt());
    }

    @Test(priority = 5, description = "Test creating SD-JWT with null JWT",
            expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = ".*Issuer-signed JWT cannot be null or empty.*")
    public void testCreateWithNullJWT() {
        new SDJWT(null, createTestDisclosures());
    }

    @Test(priority = 6, description = "Test parsing invalid SD-JWT",
            expectedExceptions = SDJWTException.class,
            expectedExceptionsMessageRegExp = ".*must contain at least JWT and trailing separator.*")
    public void testParseInvalidFormat() throws SDJWTException {
        SDJWT.parse(TEST_ISSUER_SIGNED_JWT); // Missing separator
    }

    /**
     * Helper method to create test disclosures.
     */
    private List<Disclosure> createTestDisclosures() {
        return Arrays.asList(
                new Disclosure("salt1", "email", "user@example.com"),
                new Disclosure("salt2", "name", "John Doe")
        );
    }
}

