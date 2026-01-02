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
import org.wso2.carbon.identity.openid4vc.presentation.servlet.WalletResponseServlet;
import org.wso2.carbon.identity.openid4vc.presentation.servlet.WalletStatusServlet;
import org.wso2.carbon.identity.openid4vc.presentation.servlet.WalletTemplateServlet;

/**
 * OSGi component to register the Wallet Response Servlet for handling wallet callback requests.
 */
@Component(
        name = "org.wso2.carbon.identity.openid4vc.presentation.servlet.registration",
        immediate = true
)
public class WalletServletRegistrationComponent {

    private static final Log log = LogFactory.getLog(WalletServletRegistrationComponent.class);
    private static final String SERVLET_URL_PATTERN = "/wallet-callback";
    private static final String STATUS_SERVLET_URL_PATTERN = "/wallet-callback/status";
    private static final String TEMPLATE_SERVLET_URL_PATTERN = "/wallet-callback/template";

    private HttpService httpService;

    @Activate
    protected void activate(ComponentContext context) {
        try {
            // Register the wallet callback servlet
            httpService.registerServlet(SERVLET_URL_PATTERN, new WalletResponseServlet(), null, null);
            log.info("Wallet Response Servlet registered successfully at: " + SERVLET_URL_PATTERN);

            // Register the wallet status servlet
            httpService.registerServlet(STATUS_SERVLET_URL_PATTERN, new WalletStatusServlet(), null, null);
            log.info("Wallet Status Servlet registered successfully at: " + STATUS_SERVLET_URL_PATTERN);

            // Register the wallet template servlet
            httpService.registerServlet(TEMPLATE_SERVLET_URL_PATTERN, new WalletTemplateServlet(), null, null);
            log.info("Wallet Template Servlet registered successfully at: " + TEMPLATE_SERVLET_URL_PATTERN);
        } catch (Exception e) {
            log.error("Error occurred while registering Wallet servlets", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        try {
            // Unregister the servlets
            httpService.unregister(SERVLET_URL_PATTERN);
            httpService.unregister(STATUS_SERVLET_URL_PATTERN);
            httpService.unregister(TEMPLATE_SERVLET_URL_PATTERN);
            log.info("Wallet servlets unregistered successfully");
        } catch (Exception e) {
            log.error("Error occurred while unregistering Wallet servlets", e);
        }
    }

    @Reference(
            name = "http.service",
            service = HttpService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetHttpService"
    )
    protected void setHttpService(HttpService httpService) {
        this.httpService = httpService;
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service set successfully");
        }
    }

    protected void unsetHttpService(HttpService httpService) {
        this.httpService = null;
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service unset");
        }
    }
}
