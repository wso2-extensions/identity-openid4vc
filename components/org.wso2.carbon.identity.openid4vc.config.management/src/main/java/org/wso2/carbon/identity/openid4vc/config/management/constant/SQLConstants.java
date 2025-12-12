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

package org.wso2.carbon.identity.openid4vc.config.management.constant;

/**
 * SQL queries used by VC Config DAO.
 */
public final class SQLConstants {

    private SQLConstants() {}

    // DB types.
    public static final String MICROSOFT = "Microsoft";
    public static final String ORACLE = "Oracle";

    // Column names.
    public static final String CURSOR_KEY_COLUMN_NAME = "CURSOR_KEY";
    public static final String IDENTIFIER_COLUMN_NAME = "IDENTIFIER";
    public static final String DISPLAY_NAME_COLUMN_NAME = "DISPLAY_NAME";
    public static final String FORMAT_COLUMN_NAME = "FORMAT";

    // VC_CONFIG
    public static final String LIST_CONFIGS =
            "SELECT ID, IDENTIFIER, DISPLAY_NAME " +
            "FROM VC_CONFIG WHERE TENANT_ID = ? ORDER BY CURSOR_KEY";

    public static final String GET_CONFIG_BY_ID =
            "SELECT ID, IDENTIFIER, DISPLAY_NAME, FORMAT, SIGNING_ALG, " +
            "EXPIRES_IN, OFFER_ID " +
            "FROM VC_CONFIG WHERE ID = ? AND TENANT_ID = ?";

    public static final String GET_CONFIG_BY_IDENTIFIER =
            "SELECT ID, IDENTIFIER, DISPLAY_NAME, FORMAT, SIGNING_ALG, " +
            "EXPIRES_IN, OFFER_ID " +
            "FROM VC_CONFIG WHERE IDENTIFIER = ? AND TENANT_ID = ?";

    public static final String GET_CONFIG_BY_OFFER_ID =
            "SELECT ID, IDENTIFIER, DISPLAY_NAME, FORMAT, SIGNING_ALG, " +
            "EXPIRES_IN, OFFER_ID " +
            "FROM VC_CONFIG WHERE OFFER_ID = ? AND TENANT_ID = ?";

    public static final String EXISTS_BY_IDENTIFIER =
            "SELECT 1 FROM VC_CONFIG WHERE TENANT_ID = ? AND IDENTIFIER = ?";

    public static final String INSERT_CONFIG =
            "INSERT INTO VC_CONFIG (ID, TENANT_ID, IDENTIFIER, DISPLAY_NAME, FORMAT, " +
            "SIGNING_ALG, EXPIRES_IN, OFFER_ID) VALUES " +
            "(?,?,?,?,?,?,?,?)";

    public static final String UPDATE_CONFIG =
            "UPDATE VC_CONFIG SET IDENTIFIER = ?, DISPLAY_NAME = ?, FORMAT = ?, " +
            "SIGNING_ALG = ?, EXPIRES_IN = ?, OFFER_ID = ? " +
            "WHERE TENANT_ID = ? AND ID = ?";

    public static final String DELETE_CONFIG =
            "DELETE FROM VC_CONFIG WHERE TENANT_ID = ? AND ID = ?";

    public static final String UPDATE_OFFER_ID =
            "UPDATE VC_CONFIG SET OFFER_ID = ? WHERE TENANT_ID = ? AND ID = ?";

    // VC_CONFIG_CLAIM
    public static final String LIST_CLAIMS_BY_CONFIG_PK =
            "SELECT CLAIM_URI FROM VC_CONFIG_CLAIM WHERE CONFIG_ID = ?";

    public static final String INSERT_CLAIM =
            "INSERT INTO VC_CONFIG_CLAIM (CONFIG_ID, CLAIM_URI) VALUES (?,?)";

    public static final String DELETE_CLAIMS_BY_CONFIG_PK =
            "DELETE FROM VC_CONFIG_CLAIM WHERE CONFIG_ID = ?";

    public static final String GET_VC_CONFIGS = "SELECT ID, CURSOR_KEY, IDENTIFIER, DISPLAY_NAME " +
            "FROM VC_CONFIG WHERE ";
    public static final String GET_VC_CONFIGS_MSSQL = "SELECT TOP(%d) ID, CURSOR_KEY, IDENTIFIER, DISPLAY_NAME, " +
            "FROM VC_CONFIG WHERE ";
    public static final String GET_VC_CONFIGS_TAIL = " TENANT_ID = %d ORDER BY CURSOR_KEY %s LIMIT %d";
    public static final String GET_VC_CONFIGS_TAIL_MSSQL = " TENANT_ID = %d ORDER BY CURSOR_KEY %s";
    public static final String GET_VC_CONFIGS_TAIL_ORACLE = " TENANT_ID = %d ORDER BY CURSOR_KEY %s " +
            "FETCH FIRST %d ROWS ONLY";
    public static final String GET_VC_CONFIGS_COUNT = "SELECT COUNT(DISTINCT(ID)) FROM VC_CONFIG WHERE ";
    public static final String GET_VC_CONFIGS_COUNT_TAIL = " TENANT_ID = ?";

}
