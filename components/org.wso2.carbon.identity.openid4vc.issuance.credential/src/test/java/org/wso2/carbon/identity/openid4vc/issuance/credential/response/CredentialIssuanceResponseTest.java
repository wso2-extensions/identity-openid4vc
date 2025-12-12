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

package org.wso2.carbon.identity.openid4vc.issuance.credential.response;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;

/**
 * Test class for CredentialIssuanceResponse.
 * Tests the builder pattern, validation, and JSON serialization.
 */
public class CredentialIssuanceResponseTest {

    private static final String SAMPLE_JWT_CREDENTIAL =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature";

    @Test(priority = 1, description = "Test successful response creation and JSON serialization")
    public void testBuildSuccess() throws CredentialIssuanceException {
        // Build response with valid credential
        CredentialIssuanceResponse response = CredentialIssuanceResponse.builder()
                .credential(SAMPLE_JWT_CREDENTIAL)
                .build();

        // Verify response is created
        Assert.assertNotNull(response, "Response should not be null");

        // Get JSON output
        String json = response.toJson();

        // Verify JSON is not null and not empty
        Assert.assertNotNull(json, "JSON should not be null");
        Assert.assertFalse(json.isEmpty(), "JSON should not be empty");

        // Parse and verify JSON structure
        JsonObject jsonObject = JsonParser.parseString(json).getAsJsonObject();
        Assert.assertTrue(jsonObject.has("credential"), "JSON should contain 'credential' field");
        Assert.assertEquals(jsonObject.get("credential").getAsString(), SAMPLE_JWT_CREDENTIAL,
                "Credential value should match");
    }

    @Test(priority = 2, description = "Test building without setting credential",
            expectedExceptions = CredentialIssuanceException.class,
            expectedExceptionsMessageRegExp = ".*Credential is required.*")
    public void testBuildFailure() throws CredentialIssuanceException {
        // Attempt to build without setting credential - should throw CredentialIssuanceException
        CredentialIssuanceResponse.builder()
                .build();
    }
}
