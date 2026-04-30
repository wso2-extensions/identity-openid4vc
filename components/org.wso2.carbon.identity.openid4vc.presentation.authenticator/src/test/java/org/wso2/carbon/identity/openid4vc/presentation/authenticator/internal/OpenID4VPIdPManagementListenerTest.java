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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.lang.reflect.Method;

/**
 * Unit tests for {@link OpenID4VPIdPManagementListener}.
 */
public class OpenID4VPIdPManagementListenerTest {

    @DataProvider(name = "tenantDomainProvider")
    public Object[][] tenantDomainProvider() {
        return new Object[][]{
                {MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, true},
                {"example.com", false}
        };
    }

    @Test(dataProvider = "tenantDomainProvider")
    public void testResolveKeyStoreName(String tenantDomain, boolean isSuperTenant) throws Exception {
        OpenID4VPIdPManagementListener listener = new OpenID4VPIdPManagementListener();
        Method method = OpenID4VPIdPManagementListener.class.getDeclaredMethod("resolveKeyStoreName", String.class);
        method.setAccessible(true);

        String keyStoreName;
        if (isSuperTenant) {
            try (MockedStatic<KeyStoreUtil> keyStoreUtil = Mockito.mockStatic(KeyStoreUtil.class)) {
                keyStoreUtil.when(() -> KeyStoreUtil.getKeyStoreFileName(null)).thenReturn("wso2carbon.jks");
                keyStoreName = (String) method.invoke(listener, tenantDomain);
                Assert.assertEquals(keyStoreName, "wso2carbon.jks", "Super tenant should use primary keystore name");
            }
        } else {
            keyStoreName = (String) method.invoke(listener, tenantDomain);
            Assert.assertEquals(keyStoreName, tenantDomain + 
                ".jks", "Regular tenant should use <domain>.jks convention");
        }
    }
}
