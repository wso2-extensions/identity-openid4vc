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

package org.wso2.carbon.identity.openid4vc.presentation.did.exception;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Unit tests for DID exceptions.
 */
public class DIDExceptionsTest {

    /**
     * Tests DIDServerException constructor with DID error code.
     */
    @Test
    public void testDIDServerExceptionWithErrorCode() {

        RuntimeException cause = new RuntimeException("cause");
        DIDServerException exception = new DIDServerException(DIDErrorCode.DID_DOCUMENT_ERROR,
                "message", cause);

        Assert.assertEquals(exception.getMessage(), "message");
        Assert.assertEquals(exception.getCause(), cause);
        Assert.assertEquals(exception.getCode(), "DID-50001");
    }

    /**
     * Tests DIDServerException factory methods used in DID resolution.
     */
    @Test
    public void testDIDServerExceptionFactoryMethods() {

        DIDServerException unsupported = DIDServerException.unsupportedMethod("did:foo:123", "foo");
        DIDServerException network = DIDServerException.networkError("did:web:example.com",
                new RuntimeException("io"));
        DIDServerException invalidDoc = DIDServerException.invalidDocument("did:web:example.com",
                "missing id");
        DIDServerException notFound = DIDServerException.keyNotFound("did:web:example.com", null);
        DIDServerException invalidFormat = DIDServerException.invalidFormat("bad-did");

        Assert.assertTrue(unsupported.getMessage().contains("Unsupported DID method"));
        Assert.assertTrue(network.getMessage().contains("Network error while resolving DID"));
        Assert.assertTrue(invalidDoc.getMessage().contains("Invalid DID document"));
        Assert.assertTrue(notFound.getMessage().contains("default key"));
        Assert.assertTrue(invalidFormat.getMessage().contains("Invalid DID format"));
        Assert.assertEquals(network.getMethod(), "web");
    }
}
