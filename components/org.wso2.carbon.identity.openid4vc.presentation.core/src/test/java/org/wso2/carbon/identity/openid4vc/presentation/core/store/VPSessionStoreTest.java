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

package org.wso2.carbon.identity.openid4vc.presentation.core.store;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.openid4vc.presentation.core.constant.SQLConstants;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link VPSessionStore}.
 * Verifies that VP sessions are persisted through the identity database connection.
 */
public class VPSessionStoreTest {

    private static final String REQUEST_ID = "2468f943-bd86-40bd-bad8-0b14ee7b6d1f";

    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtilMock;
    private Connection connection;
    private PreparedStatement statement;

    @BeforeMethod
    public void setUp() throws Exception {

        connection = mock(Connection.class);
        statement = mock(PreparedStatement.class);
        when(connection.prepareStatement(SQLConstants.SELECT)).thenReturn(statement);
        when(connection.prepareStatement(SQLConstants.DELETE)).thenReturn(statement);
        when(connection.prepareStatement(SQLConstants.DELETE_EXPIRED)).thenReturn(statement);
        when(connection.prepareStatement(SQLConstants.DELETE_BY_TENANT)).thenReturn(statement);

        identityDatabaseUtilMock = mockStatic(IdentityDatabaseUtil.class);
        identityDatabaseUtilMock.when(() -> IdentityDatabaseUtil.getDBConnection(anyBoolean())).thenReturn(connection);
    }

    @AfterMethod
    public void tearDown() {

        identityDatabaseUtilMock.close();
    }

    @Test(description = "Test get reads the VP session through the identity database connection")
    public void testGetUsesIdentityDatabase() throws Exception {

        ResultSet resultSet = mock(ResultSet.class);
        when(resultSet.next()).thenReturn(false);
        when(statement.executeQuery()).thenReturn(resultSet);

        Assert.assertNull(VPSessionStore.getInstance().get(REQUEST_ID),
                "A missing VP session should be returned as null");

        identityDatabaseUtilMock.verify(() -> IdentityDatabaseUtil.getDBConnection(false));
        assertSessionDatabaseNotUsed();
    }

    @Test(description = "Test remove deletes the VP session through the identity database connection")
    public void testRemoveUsesIdentityDatabase() throws Exception {

        VPSessionStore.getInstance().remove(REQUEST_ID);

        identityDatabaseUtilMock.verify(() -> IdentityDatabaseUtil.getDBConnection(true));
        verify(statement).setString(1, REQUEST_ID);
        verify(statement).executeUpdate();
        assertSessionDatabaseNotUsed();
    }

    @Test(description = "Test removeExpired deletes expired VP sessions through the identity database connection")
    public void testRemoveExpiredUsesIdentityDatabase() throws Exception {

        VPSessionStore.getInstance().removeExpired();

        identityDatabaseUtilMock.verify(() -> IdentityDatabaseUtil.getDBConnection(true));
        verify(statement).executeUpdate();
        assertSessionDatabaseNotUsed();
    }

    @Test(description = "Test removeByTenant deletes tenant VP sessions through the identity database connection")
    public void testRemoveByTenantUsesIdentityDatabase() throws Exception {

        VPSessionStore.getInstance().removeByTenant(1);

        identityDatabaseUtilMock.verify(() -> IdentityDatabaseUtil.getDBConnection(true));
        verify(statement).setInt(1, 1);
        verify(statement).executeUpdate();
        assertSessionDatabaseNotUsed();
    }

    private void assertSessionDatabaseNotUsed() {

        identityDatabaseUtilMock.verify(() -> IdentityDatabaseUtil.getSessionDBConnection(anyBoolean()), never());
    }
}
