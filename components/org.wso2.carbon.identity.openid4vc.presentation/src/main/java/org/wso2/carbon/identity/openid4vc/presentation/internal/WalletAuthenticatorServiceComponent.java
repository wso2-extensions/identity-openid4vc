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

package org.wso2.carbon.identity.openid4vc.presentation.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.WalletAuthenticator;
import org.wso2.carbon.identity.openid4vc.presentation.servlet.WalletResponseServlet;
import org.wso2.carbon.identity.openid4vc.presentation.servlet.WalletStatusServlet;

/**
 * OSGi service component for Wallet Authenticator.
 * DISABLED: This component is disabled to avoid conflicts with OpenID4VPAuthenticator.
 * The servlets are now registered in WalletServletRegistrationComponent.
 */
/*
@Component(
        name = "org.wso2.carbon.identity.openid4vc.presentation",
        immediate = true
)
*/
public class WalletAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(WalletAuthenticatorServiceComponent.class);
    private static final String WALLET_CALLBACK_URL = "/wallet/callback";
    private static final String WALLET_STATUS_URL = "/wallet/status";

    @Activate
    protected void activate(ComponentContext context) {
        try {
            // Register Wallet Authenticator
            WalletAuthenticator walletAuthenticator = new WalletAuthenticator();
            context.getBundleContext().registerService(
                ApplicationAuthenticator.class.getName(),
                walletAuthenticator,
                null
            );

            log.info("Wallet Authenticator activated successfully");

        } catch (Exception e) {
            log.error("Error activating Wallet Authenticator service component", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("Wallet Authenticator deactivated");
        }
    }

    @Reference(
            name = "osgi.httpservice",
            service = HttpService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetHttpService"
    )
    protected void setHttpService(HttpService httpService) {
        try {
            // Register callback servlet
            httpService.registerServlet(WALLET_CALLBACK_URL, new WalletResponseServlet(),
                null, null);

            if (log.isDebugEnabled()) {
                log.debug("Wallet Response Servlet registered at: " + WALLET_CALLBACK_URL);
            }

            // Register status polling servlet
            httpService.registerServlet(WALLET_STATUS_URL, new WalletStatusServlet(),
                null, null);

            if (log.isDebugEnabled()) {
                log.debug("Wallet Status Servlet registered at: " + WALLET_STATUS_URL);
            }

        } catch (Exception e) {
            log.error("Error registering Wallet Servlets", e);
        }
    }

    protected void unsetHttpService(HttpService httpService) {
        try {
            httpService.unregister(WALLET_CALLBACK_URL);
            httpService.unregister(WALLET_STATUS_URL);
            if (log.isDebugEnabled()) {
                log.debug("Wallet Servlets unregistered");
            }
        } catch (Exception e) {
            log.error("Error unregistering Wallet Servlets", e);
        }
    }
}

