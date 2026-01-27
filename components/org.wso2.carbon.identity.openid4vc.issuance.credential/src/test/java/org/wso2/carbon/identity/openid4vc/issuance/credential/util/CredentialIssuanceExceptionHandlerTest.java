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

package org.wso2.carbon.identity.openid4vc.issuance.credential.util;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceClientException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceErrorCode;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceServerException;

/**
 * Test class for CredentialIssuanceExceptionHandler.
 */
public class CredentialIssuanceExceptionHandlerTest {

    @Test(description = "Test handleClientException without data parameters")
    public void testHandleClientException() {

        CredentialIssuanceErrorCode errorCode = CredentialIssuanceErrorCode.INVALID_CREDENTIAL_REQUEST;

        CredentialIssuanceClientException exception =
                CredentialIssuanceExceptionHandler.handleClientException(errorCode);

        Assert.assertNotNull(exception, "Exception should not be null");
        Assert.assertEquals(exception.getErrorCode(), errorCode, "Error code should match");
        Assert.assertEquals(exception.getMessage(), errorCode.getMessage(), "Message should match");
        Assert.assertEquals(exception.getDescription(), errorCode.getDescription(),
                "Description should match");
    }

    @Test(description = "Test handleClientException with data parameters")
    public void testHandleClientExceptionWithData() {

        CredentialIssuanceErrorCode errorCode = CredentialIssuanceErrorCode.INVALID_TOKEN;
        String testData = "test_token_value";

        CredentialIssuanceClientException exception =
                CredentialIssuanceExceptionHandler.handleClientException(errorCode, testData);

        Assert.assertNotNull(exception, "Exception should not be null");
        Assert.assertEquals(exception.getErrorCode(), errorCode, "Error code should match");
        Assert.assertEquals(exception.getMessage(), errorCode.getMessage(), "Message should match");
        Assert.assertNotNull(exception.getDescription(), "Description should not be null");
    }

    @Test(description = "Test handleServerException without data parameters")
    public void testHandleServerException() {

        CredentialIssuanceErrorCode errorCode = CredentialIssuanceErrorCode.INTERNAL_SERVER_ERROR;
        Throwable cause = new RuntimeException("Test server error");

        CredentialIssuanceServerException exception =
                CredentialIssuanceExceptionHandler.handleServerException(errorCode, cause);

        Assert.assertNotNull(exception, "Exception should not be null");
        Assert.assertEquals(exception.getErrorCode(), errorCode, "Error code should match");
        Assert.assertEquals(exception.getMessage(), errorCode.getMessage(), "Message should match");
        Assert.assertEquals(exception.getDescription(), errorCode.getDescription(),
                "Description should match");
        Assert.assertEquals(exception.getCause(), cause, "Cause should match");
    }

    @Test(description = "Test handleServerException with data parameters")
    public void testHandleServerExceptionWithData() {

        CredentialIssuanceErrorCode errorCode = CredentialIssuanceErrorCode.CREDENTIAL_SIGNING_ERROR;
        Throwable cause = new RuntimeException("Signing failed");
        String testData = "RSA256";

        CredentialIssuanceServerException exception =
                CredentialIssuanceExceptionHandler.handleServerException(errorCode, cause, testData);

        Assert.assertNotNull(exception, "Exception should not be null");
        Assert.assertEquals(exception.getErrorCode(), errorCode, "Error code should match");
        Assert.assertEquals(exception.getMessage(), errorCode.getMessage(), "Message should match");
        Assert.assertNotNull(exception.getDescription(), "Description should not be null");
        Assert.assertEquals(exception.getCause(), cause, "Cause should match");
    }
}
