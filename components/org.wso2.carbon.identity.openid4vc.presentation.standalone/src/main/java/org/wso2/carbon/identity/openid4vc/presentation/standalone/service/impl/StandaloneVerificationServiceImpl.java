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

package org.wso2.carbon.identity.openid4vc.presentation.standalone.service.impl;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.server.cache.StandaloneVerificationCache;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.StandaloneVerificationInitiation;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.StandaloneVerificationSession;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.server.service.StandaloneVerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.server.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints;
import org.wso2.carbon.identity.openid4vc.presentation.server.util.VPAuthenticatorUtil;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Implementation of {@link StandaloneVerificationService}.
 * Creates and manages VP verification sessions outside the WSO2 login flow.
 */
public class StandaloneVerificationServiceImpl implements StandaloneVerificationService {

    private static final long SESSION_TTL_MS = 5 * 60 * 1000L; // 5 minutes

    private final VPRequestService vpRequestService;

    public StandaloneVerificationServiceImpl(VPRequestService vpRequestService) {

        this.vpRequestService = vpRequestService;
    }

    @Override
    public StandaloneVerificationInitiation initiate(String presentationDefinitionId, String tenantDomain)
            throws VPAuthenticatorException {

        if (StringUtils.isBlank(presentationDefinitionId)) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "presentationDefinitionId is required.");
        }
        if (StringUtils.isBlank(tenantDomain)) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "tenantDomain is required.");
        }

        String txnId = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        long expiresAt = System.currentTimeMillis() + SESSION_TTL_MS;

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        String baseUrl = VPAuthenticatorUtil.resolveBaseUrl();
        String responseUri = baseUrl + Constraints.RESPONSE_URI_ENDPOINT;
        String scheme = VPAuthenticatorUtil.resolveClientIdScheme(tenantDomain);
        String resolvedResponseMode = VPAuthenticatorUtil.resolveResponseMode(tenantDomain);
        String registrationCert = VPAuthenticatorUtil.resolveRegistrationCertificate(tenantDomain);
        String clientId = VPAuthenticatorUtil.resolveClientIdForScheme(scheme, baseUrl, tenantDomain);

        // Generate ephemeral EC key for direct_post.jwt encryption.
        ECKey ephemeralPublicKey = null;
        String ephemeralPrivateKeyJwk = null;
        if (Constraints.RESPONSE_MODE_DIRECT_POST_JWT.equals(resolvedResponseMode)) {
            try {
                ECKey keyPair = new ECKeyGenerator(Curve.P_256).keyID(txnId).generate();
                ephemeralPrivateKeyJwk = keyPair.toJSONString();
                ephemeralPublicKey = keyPair.toPublicJWK();
            } catch (com.nimbusds.jose.JOSEException e) {
                throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "Failed to generate ephemeral key for direct_post.jwt.", e);
            }
        }

        StandaloneVerificationSession session = new StandaloneVerificationSession();
        session.setTxnId(txnId);
        session.setPresentationDefinitionId(presentationDefinitionId);
        session.setTenantDomain(tenantDomain);
        session.setTenantId(tenantId);
        session.setStatus(VPRequestStatus.ACTIVE);
        session.setNonce(nonce);
        session.setEphemeralPrivateKeyJwk(ephemeralPrivateKeyJwk);
        session.setExpiresAt(expiresAt);
        session.setClientId(clientId);
        session.setClientIdScheme(scheme);
        session.setResponseUri(responseUri);
        session.setResponseMode(resolvedResponseMode);
        session.setRegistrationCert(registrationCert);

        StandaloneVerificationCache.getInstance().put(txnId, session);

        String requestUri = baseUrl + Constraints.REQUEST_URI_ENDPOINT + txnId;
        String walletUrl = buildWalletUrl(clientId, requestUri);

        return new StandaloneVerificationInitiation(txnId, walletUrl, requestUri, expiresAt);
    }

    @Override
    public String generateRequestJwt(String txnId) throws VPAuthenticatorException {

        StandaloneVerificationSession session = StandaloneVerificationCache.getInstance().get(txnId);
        if (session == null) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND,
                    "Standalone verification session not found: " + txnId);
        }

        VPRequest vpRequest = new VPRequest.Builder()
                .requestId(txnId)
                .clientId(session.getClientId())
                .nonce(session.getNonce())
                .presentationDefinitionId(session.getPresentationDefinitionId())
                .responseUri(session.getResponseUri())
                .responseMode(session.getResponseMode())
                .status(VPRequestStatus.ACTIVE)
                .expiresAt(session.getExpiresAt())
                .tenantId(session.getTenantId())
                .build();

        ECKey ephemeralPublicKey = null;
        if (StringUtils.isNotBlank(session.getEphemeralPrivateKeyJwk())) {
            try {
                ECKey keyPair = ECKey.parse(session.getEphemeralPrivateKeyJwk());
                ephemeralPublicKey = keyPair.toPublicJWK();
            } catch (Exception e) {
                throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "Failed to parse ephemeral key from session.", e);
            }
        }

        return vpRequestService.buildRequestJwt(vpRequest, session.getTenantDomain(), ephemeralPublicKey,
                session.getClientIdScheme(), session.getRegistrationCert());
    }

    @Override
    public StandaloneVerificationSession getSession(String txnId) {
        return StandaloneVerificationCache.getInstance().get(txnId);
    }

    private String buildWalletUrl(String clientId, String requestUri) {

        try {
            String encodedClientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8.name());
            String encodedRequestUri = URLEncoder.encode(requestUri, StandardCharsets.UTF_8.name());
            return OpenID4VPConstants.Protocol.OPENID4VP_SCHEME + "?client_id=" + encodedClientId
                    + "&request_uri=" + encodedRequestUri;
        } catch (Exception e) {
            return OpenID4VPConstants.Protocol.OPENID4VP_SCHEME + "?client_id=" + clientId
                    + "&request_uri=" + requestUri;
        }
    }
}
