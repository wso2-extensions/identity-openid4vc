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

package org.wso2.carbon.identity.openid4vc.template.management.constant;

/**
 * SQL queries used by VC Template DAO.
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
    public static final String DESCRIPTION_COLUMN_NAME = "DESCRIPTION";
    public static final String FORMAT_COLUMN_NAME = "FORMAT";

    // IDN_VC_TEMPLATE
    public static final String LIST_TEMPLATES =
            "SELECT ID, IDENTIFIER, DISPLAY_NAME, DESCRIPTION " +
            "FROM IDN_VC_TEMPLATE WHERE TENANT_ID = ? ORDER BY CURSOR_KEY";

    public static final String GET_TEMPLATE_BY_ID =
            "SELECT ID, IDENTIFIER, DISPLAY_NAME, DESCRIPTION, FORMAT, SIGNING_ALG, " +
            "EXPIRES_IN, OFFER_ID " +
            "FROM IDN_VC_TEMPLATE WHERE ID = ? AND TENANT_ID = ?";

    public static final String GET_TEMPLATE_BY_IDENTIFIER =
            "SELECT ID, IDENTIFIER, DISPLAY_NAME, DESCRIPTION, FORMAT, SIGNING_ALG, " +
            "EXPIRES_IN, OFFER_ID " +
            "FROM IDN_VC_TEMPLATE WHERE IDENTIFIER = ? AND TENANT_ID = ?";

    public static final String GET_TEMPLATE_BY_OFFER_ID =
            "SELECT ID, IDENTIFIER, DISPLAY_NAME, DESCRIPTION, FORMAT, SIGNING_ALG, " +
            "EXPIRES_IN, OFFER_ID " +
            "FROM IDN_VC_TEMPLATE WHERE OFFER_ID = ? AND TENANT_ID = ?";

    public static final String EXISTS_BY_IDENTIFIER =
            "SELECT 1 FROM IDN_VC_TEMPLATE WHERE TENANT_ID = ? AND IDENTIFIER = ?";

    public static final String INSERT_TEMPLATE =
            "INSERT INTO IDN_VC_TEMPLATE (ID, TENANT_ID, IDENTIFIER, DISPLAY_NAME, DESCRIPTION, FORMAT, " +
            "SIGNING_ALG, EXPIRES_IN, OFFER_ID) VALUES " +
            "(?,?,?,?,?,?,?,?,?)";

    public static final String UPDATE_TEMPLATE =
            "UPDATE IDN_VC_TEMPLATE SET IDENTIFIER = ?, DISPLAY_NAME = ?, DESCRIPTION = ?, FORMAT = ?, " +
            "SIGNING_ALG = ?, EXPIRES_IN = ?, OFFER_ID = ? " +
            "WHERE TENANT_ID = ? AND ID = ?";

    public static final String DELETE_TEMPLATE =
            "DELETE FROM IDN_VC_TEMPLATE WHERE TENANT_ID = ? AND ID = ?";

    public static final String UPDATE_OFFER_ID =
            "UPDATE IDN_VC_TEMPLATE SET OFFER_ID = ? WHERE TENANT_ID = ? AND ID = ?";

    // IDN_VC_CLAIMS
    public static final String LIST_CLAIMS_BY_TEMPLATE_ID =
            "SELECT CLAIM_URI FROM IDN_VC_CLAIMS WHERE TEMPLATE_ID = ?";

    public static final String INSERT_CLAIM =
            "INSERT INTO IDN_VC_CLAIMS (TEMPLATE_ID, CLAIM_URI) VALUES (?,?)";

    public static final String DELETE_CLAIMS_BY_TEMPLATE_ID =
            "DELETE FROM IDN_VC_CLAIMS WHERE TEMPLATE_ID = ?";

    public static final String GET_VC_TEMPLATES = "SELECT ID, CURSOR_KEY, IDENTIFIER, DISPLAY_NAME, DESCRIPTION " +
            "FROM IDN_VC_TEMPLATE WHERE ";
    public static final String GET_VC_TEMPLATES_MSSQL = "SELECT TOP(%d) ID, CURSOR_KEY, IDENTIFIER, DISPLAY_NAME, " +
            "DESCRIPTION FROM IDN_VC_TEMPLATE WHERE ";
    public static final String GET_VC_TEMPLATES_TAIL = " TENANT_ID = %d ORDER BY CURSOR_KEY %s LIMIT %d";
    public static final String GET_VC_TEMPLATES_TAIL_MSSQL = " TENANT_ID = %d ORDER BY CURSOR_KEY %s";
    public static final String GET_VC_TEMPLATES_TAIL_ORACLE = " TENANT_ID = %d ORDER BY CURSOR_KEY %s " +
            "FETCH FIRST %d ROWS ONLY";
    public static final String GET_VC_TEMPLATES_COUNT = "SELECT COUNT(DISTINCT(ID)) FROM IDN_VC_TEMPLATE WHERE ";
    public static final String GET_VC_TEMPLATES_COUNT_TAIL = " TENANT_ID = ?";
}
