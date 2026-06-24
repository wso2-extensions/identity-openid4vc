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

package org.wso2.carbon.identity.openid4vc.presentation.server.internal;

import org.wso2.carbon.identity.openid4vc.presentation.common.config.OpenID4VPConfigService;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.server.service.StandaloneVerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.server.service.impl.VPRequestServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Data holder for the OpenID4VP presentation server.
 * Provides access to OSGi services across the server components.
 */
public final class VPServerDataHolder {

    private static final AtomicReference<VPRequestServiceImpl> VP_REQUEST_SERVICE = new AtomicReference<>();
    private static final AtomicReference<PresentationDefinitionService> PRESENTATION_DEFINITION_SERVICE =
            new AtomicReference<>();
    private static final AtomicReference<VerificationService> VERIFICATION_SERVICE = new AtomicReference<>();
    private static final AtomicReference<OpenID4VPConfigService> OPENID4VP_CONFIG_SERVICE = new AtomicReference<>();
    private static final AtomicReference<StandaloneVerificationService> STANDALONE_VERIFICATION_SERVICE =
            new AtomicReference<>();

    private VPServerDataHolder() { }

    public static VPRequestServiceImpl getVPRequestService() { return VP_REQUEST_SERVICE.get(); }
    public static void setVPRequestService(VPRequestServiceImpl service) { VP_REQUEST_SERVICE.set(service); }

    public static PresentationDefinitionService getPresentationDefinitionService() {
        return PRESENTATION_DEFINITION_SERVICE.get();
    }
    public static void setPresentationDefinitionService(PresentationDefinitionService service) {
        PRESENTATION_DEFINITION_SERVICE.set(service);
    }

    public static VerificationService getVerificationService() { return VERIFICATION_SERVICE.get(); }
    public static void setVerificationService(VerificationService service) { VERIFICATION_SERVICE.set(service); }

    public static OpenID4VPConfigService getOpenID4VPConfigService() { return OPENID4VP_CONFIG_SERVICE.get(); }
    public static void setOpenID4VPConfigService(OpenID4VPConfigService service) {
        OPENID4VP_CONFIG_SERVICE.set(service);
    }

    public static StandaloneVerificationService getStandaloneVerificationService() {
        return STANDALONE_VERIFICATION_SERVICE.get();
    }
    public static void setStandaloneVerificationService(StandaloneVerificationService service) {
        STANDALONE_VERIFICATION_SERVICE.set(service);
    }
}
