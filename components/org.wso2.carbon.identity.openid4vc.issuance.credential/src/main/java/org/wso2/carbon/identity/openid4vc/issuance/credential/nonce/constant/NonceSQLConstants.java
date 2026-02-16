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

package org.wso2.carbon.identity.openid4vc.issuance.credential.nonce.constant;

/**
 * SQL constants for the nonce store.
 */
public class NonceSQLConstants {

    private NonceSQLConstants() {
    }

    public static final String STORE_NONCE =
            "INSERT INTO IDN_VC_NONCE (TENANT_ID, NONCE_VALUE, TIME_CREATED, EXPIRY_TIME) " +
            "VALUES (?, ?, ?, ?)";

    public static final String VALIDATE_AND_CONSUME_NONCE =
            "DELETE FROM IDN_VC_NONCE WHERE NONCE_VALUE = ? AND TENANT_ID = ? AND EXPIRY_TIME > ?";

    public static final String DELETE_EXPIRED_NONCES =
            "DELETE FROM IDN_VC_NONCE WHERE EXPIRY_TIME < ?";
}
