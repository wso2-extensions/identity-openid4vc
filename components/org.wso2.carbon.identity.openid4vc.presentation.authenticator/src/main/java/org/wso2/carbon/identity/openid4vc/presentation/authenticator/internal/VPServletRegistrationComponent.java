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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.http.HttpService;
import org.osgi.service.http.NamespaceException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet.RequestUriServlet;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet.VCVerificationServlet;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet.VPDefinitionServlet;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet.VPRequestServlet;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet.VPStatusPollingServlet;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet.VPSubmissionServlet;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet.WalletStatusServlet;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet.WellKnownDIDServlet;
import org.wso2.carbon.user.core.service.RealmService;

import javax.servlet.ServletException;

/**
 * OSGi component for registering OpenID4VP servlets.
 * 
 * Registers the following servlets:
 * - /openid4vp/v1/vp-request - VP request management
 * - /openid4vp/v1/response - VP submission handling
 * - /openid4vp/v1/vp-result - VP verification results
 * - /openid4vp/v1/presentation-definitions - Definition management
 */
@Component(name = "org.wso2.carbon.identity.openid4vc.presentation.servlet.component", immediate = true)
public class VPServletRegistrationComponent {

    private static final String API_BASE_PATH = "/openid4vp/v1";
    private static final String VP_REQUEST_PATH = API_BASE_PATH + "/vp-request";
    private static final String REQUEST_URI_PATH = API_BASE_PATH + "/request-uri";
    private static final String VP_RESPONSE_PATH = API_BASE_PATH + "/response";
    private static final String PRESENTATION_DEFINITIONS_PATH = API_BASE_PATH + "/presentation-definitions";
    private static final String VC_VERIFICATION_PATH = API_BASE_PATH + "/vc-verification";
    private static final String VP_STATUS_PATH = API_BASE_PATH + "/vp-status";
    private static final String WALLET_STATUS_PATH = API_BASE_PATH + "/wallet-status";
    private static final String WELL_KNOWN_DID_PATH = "/.well-known/did.json";

    private HttpService httpService;

    @Activate
    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
    protected void activate(ComponentContext context) {
        try {
            registerServlets();
        } catch (Exception e) {
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        try {
            unregisterServlets();
        } catch (Exception e) {
        }
    }

    /**
     * Register all OpenID4VP servlets.
     */
    private void registerServlets() throws ServletException, NamespaceException {
        if (httpService == null) {
            return;
        }

        // Register VP Request Servlet
        httpService.registerServlet(VP_REQUEST_PATH, new VPRequestServlet(), null, null);

        // Register Request URI Servlet (for wallet to fetch authorization request)
        httpService.registerServlet(REQUEST_URI_PATH, new RequestUriServlet(), null, null);

        // Register VP Submission Servlet
        httpService.registerServlet(VP_RESPONSE_PATH, new VPSubmissionServlet(), null, null);

        // Register Presentation Definition Servlet
        httpService.registerServlet(PRESENTATION_DEFINITIONS_PATH, new VPDefinitionServlet(), null, null);

        // Register VC Verification Servlet
        httpService.registerServlet(VC_VERIFICATION_PATH, new VCVerificationServlet(), null, null);

        // Register VP Status Polling Servlet
        httpService.registerServlet(VP_STATUS_PATH, new VPStatusPollingServlet(), null, null);

        // Register Wallet Status Servlet (used by login page polling)
        httpService.registerServlet(WALLET_STATUS_PATH, new WalletStatusServlet(), null, null);

        // Register Well-Known DID Servlet
        httpService.registerServlet(WELL_KNOWN_DID_PATH, new WellKnownDIDServlet(), null, null);
    }

    /**
     * Unregister all OpenID4VP servlets.
     */
    @SuppressFBWarnings({ "DE_MIGHT_IGNORE", "REC_CATCH_EXCEPTION" })
    private void unregisterServlets() {
        if (httpService == null) {
            return;
        }

        try {
            httpService.unregister(VP_REQUEST_PATH);
        } catch (Exception e) {
        }

        try {
            httpService.unregister(REQUEST_URI_PATH);
        } catch (Exception e) {
        }

        try {
            httpService.unregister(VP_RESPONSE_PATH);
        } catch (Exception e) {
        }

        try {
            httpService.unregister(PRESENTATION_DEFINITIONS_PATH);
        } catch (Exception e) {
        }

        try {
            httpService.unregister(VC_VERIFICATION_PATH);
        } catch (Exception e) {
        }

        try {
            httpService.unregister(VP_STATUS_PATH);
        } catch (Exception e) {
        }

        try {
            httpService.unregister(WALLET_STATUS_PATH);
        } catch (Exception e) {
        }

        try {
            httpService.unregister(WELL_KNOWN_DID_PATH);
        } catch (Exception e) {
        }
    }

    @Reference(name = "osgi.http.service", service = HttpService.class, cardinality = 
    ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetHttpService")
    protected void setHttpService(HttpService httpService) {
        this.httpService = httpService;

    }

    protected void unsetHttpService(HttpService httpService) {
        this.httpService = null;

    }

    @Reference(name = "user.realm.service", service = RealmService.class, cardinality = 
    ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {
        VPServiceDataHolder.getInstance().setRealmService(realmService);

    }

    protected void unsetRealmService(RealmService realmService) {
        VPServiceDataHolder.getInstance().setRealmService(null);

    }
}
