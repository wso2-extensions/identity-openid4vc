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

package org.wso2.carbon.identity.openid4vc.presentation.registration.executor;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.flow.execution.engine.graph.AuthenticationExecutor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.openid4vc.presentation.server.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.StandaloneVerificationInitiation;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.StandaloneVerificationSession;
import org.wso2.carbon.identity.openid4vc.presentation.server.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.server.service.StandaloneVerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.server.util.Constraints;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationMetadata;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.flow.execution.engine.Constants.CLAIM_URI_PREFIX;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.REDIRECT_URL;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.USERNAME_CLAIM_URI;

/**
 * Flow executor for wallet-based self-registration via OpenID4VP.
 *
 * <p>Plugs into the flow orchestration framework as an {@link AuthenticationExecutor}
 * registered under the name {@code OpenID4VPRegistrationExecutor}.
 * The executor references a "Digital Credentials" IdP connection configured in WSO2 IS,
 * which supplies all authenticator properties (presentationDefinitionId, clientIdScheme,
 * responseMode, registrationCert) and the IdP claim mappings used to translate credential
 * claims to local WSO2 claim URIs.</p>
 *
 * <p><b>Two-phase flow:</b>
 * <ol>
 *   <li><b>Initiation</b>: no {@code vp_txnId} in context → calls
 *       {@link StandaloneVerificationService#initiate} → returns
 *       {@code STATUS_EXTERNAL_REDIRECTION} with {@code walletUrl} and {@code vp_txnId}
 *       in {@code additionalInfo}.</li>
 *   <li><b>Completion</b>: {@code vp_txnId} present in context → fetches the session →
 *       if {@code VERIFIED}, maps claims and returns {@code STATUS_COMPLETE};
 *       if {@code ACTIVE}, re-issues the redirection; if {@code FAILED}, returns
 *       {@code STATUS_USER_ERROR}.</li>
 * </ol>
 * </p>
 */
public class OpenID4VPRegistrationExecutor extends AuthenticationExecutor {

    private static final Log LOG = LogFactory.getLog(OpenID4VPRegistrationExecutor.class);

    private static final String EXECUTOR_NAME = "OpenID4VPRegistrationExecutor";

    private final StandaloneVerificationService standaloneVerificationService;

    public OpenID4VPRegistrationExecutor(StandaloneVerificationService standaloneVerificationService) {

        this.standaloneVerificationService = standaloneVerificationService;
    }
    private static final String AMR_VALUE = "openid4vp";

    static final String VP_TXN_ID = "vp_txnId";
    static final String WALLET_URL = "walletUrl";

    @Override
    public String getName() {

        return EXECUTOR_NAME;
    }

    @Override
    public String getAMRValue() {

        return AMR_VALUE;
    }

    @Override
    public List<String> getInitiationData() {

        return Collections.emptyList();
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext context) {

        try {
            if (isInitiation(context)) {
                return initiateVPFlow(context);
            }
            return processVPResponse(context);
        } catch (VPAuthenticatorException e) {
            LOG.error("OpenID4VP registration executor failed for tenant: " + context.getTenantDomain(), e);
            ExecutorResponse response = new ExecutorResponse();
            response.setResult(STATUS_ERROR);
            response.setErrorMessage("VP registration failed: " + e.getMessage());
            return response;
        }
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext context) {

        // VP sessions expire on their own; no active cleanup needed.
        return new ExecutorResponse(STATUS_COMPLETE);
    }

    private boolean isInitiation(FlowExecutionContext context) {

        return context.getProperty(VP_TXN_ID) == null;
    }

    private ExecutorResponse initiateVPFlow(FlowExecutionContext context) throws VPAuthenticatorException {

        Map<String, String> props = context.getAuthenticatorProperties();
        String presentationDefinitionId = props.get(Constraints.PROP_PRESENTATION_DEFINITION_ID);

        StandaloneVerificationInitiation initiation = standaloneVerificationService.initiate(
                presentationDefinitionId,
                context.getTenantDomain());

        Map<String, Object> contextProperties = new HashMap<>();
        contextProperties.put(VP_TXN_ID, initiation.getTxnId());
        contextProperties.put(WALLET_URL, initiation.getWalletUrl());

        Map<String, String> additionalInfo = new HashMap<>();
        additionalInfo.put(REDIRECT_URL, initiation.getWalletUrl());
        additionalInfo.put(VP_TXN_ID, initiation.getTxnId());
        additionalInfo.put(WALLET_URL, initiation.getWalletUrl());

        ExecutorResponse response = new ExecutorResponse();
        response.setResult(STATUS_EXTERNAL_REDIRECTION);
        response.setContextProperty(contextProperties);
        response.setAdditionalInfo(additionalInfo);
        response.setRequiredData(Collections.singletonList(VP_TXN_ID));
        return response;
    }

    private ExecutorResponse processVPResponse(FlowExecutionContext context) {

        String txnId = (String) context.getProperty(VP_TXN_ID);
        StandaloneVerificationSession session = standaloneVerificationService.getSession(txnId);

        if (session == null) {
            return userError("VP session expired or not found.");
        }

        VPRequestStatus status = session.getStatus();
        if (status == null) {
            return userError("VP session has no status.");
        }

        switch (status) {
            case VERIFIED:
                return buildCompleteResponse(context, session);

            case FAILED:
                VerificationResult result = session.getVerificationResult();
                String reason = (result != null && result.getErrors() != null && !result.getErrors().isEmpty())
                        ? result.getErrors().get(0)
                        : "Wallet verification failed.";
                return userError(reason);

            default:
                String walletUrl = (String) context.getProperty(WALLET_URL);
                Map<String, String> additionalInfo = new HashMap<>();
                additionalInfo.put(REDIRECT_URL, StringUtils.defaultString(walletUrl));
                additionalInfo.put(VP_TXN_ID, txnId);
                if (StringUtils.isNotBlank(walletUrl)) {
                    additionalInfo.put(WALLET_URL, walletUrl);
                }
                ExecutorResponse pending = new ExecutorResponse();
                pending.setResult(STATUS_EXTERNAL_REDIRECTION);
                pending.setRequiredData(Collections.singletonList(VP_TXN_ID));
                pending.setAdditionalInfo(additionalInfo);
                return pending;
        }
    }

    private String resolveSubjectClaimName(ExternalIdPConfig externalIdPConfig) {

        if (externalIdPConfig == null
                || externalIdPConfig.getIdentityProvider() == null
                || externalIdPConfig.getIdentityProvider().getClaimConfig() == null) {
            return null;
        }
        return externalIdPConfig.getIdentityProvider().getClaimConfig().getUserClaimURI();
    }

    private ExecutorResponse buildCompleteResponse(FlowExecutionContext context,
                                                   StandaloneVerificationSession session) {

        VerificationResult result = session.getVerificationResult();
        PresentationMetadata metadata = result != null ? result.getMetadata() : null;

        Map<String, Object> credentialClaims = (metadata != null && metadata.getCredentialClaims() != null)
                ? metadata.getCredentialClaims()
                : Collections.emptyMap();

        Map<String, Object> localClaims = mapToLocalClaims(credentialClaims, context.getExternalIdPConfig());

        String subjectClaimKey = resolveSubjectClaimName(context.getExternalIdPConfig());
        String username = resolveUsername(credentialClaims, subjectClaimKey, metadata);
        if (StringUtils.isNotBlank(username)) {
            localClaims.put(USERNAME_CLAIM_URI, username);
        }

        if (context.getExternalIdPConfig() != null && StringUtils.isNotBlank(username)) {
            context.getFlowUser().addFederatedAssociation(
                    context.getExternalIdPConfig().getIdPName(), username);
        }

        ExecutorResponse response = new ExecutorResponse(STATUS_COMPLETE);
        response.setUpdatedUserClaims(localClaims);
        return response;
    }

    private Map<String, Object> mapToLocalClaims(Map<String, Object> credentialClaims,
                                                  ExternalIdPConfig idpConfig) {

        Map<String, Object> localClaims = new HashMap<>();
        ClaimMapping[] claimMappings = (idpConfig != null) ? idpConfig.getClaimMappings() : null;

        for (Map.Entry<String, Object> entry : credentialClaims.entrySet()) {
            String remoteKey = entry.getKey();
            String localUri = findLocalUri(remoteKey, claimMappings);
            localClaims.put(localUri, entry.getValue());
        }
        return localClaims;
    }

    private String findLocalUri(String remoteKey, ClaimMapping[] claimMappings) {

        if (claimMappings != null) {
            for (ClaimMapping mapping : claimMappings) {
                if (remoteKey.equals(mapping.getRemoteClaim().getClaimUri())) {
                    return mapping.getLocalClaim().getClaimUri();
                }
            }
        }
        return CLAIM_URI_PREFIX + remoteKey;
    }

    private String resolveUsername(Map<String, Object> credentialClaims, String subjectClaimKey,
                                   PresentationMetadata metadata) {

        if (StringUtils.isNotBlank(subjectClaimKey)) {
            Object val = credentialClaims.get(subjectClaimKey);
            if (val != null && StringUtils.isNotBlank(val.toString())) {
                return val.toString();
            }
        }

        if (metadata != null && StringUtils.isNotBlank(metadata.getHolderDid())) {
            return metadata.getHolderDid();
        }

        if (!credentialClaims.isEmpty()) {
            Object first = credentialClaims.values().iterator().next();
            if (first != null && StringUtils.isNotBlank(first.toString())) {
                return first.toString();
            }
        }

        return null;
    }

    private ExecutorResponse userError(String message) {

        ExecutorResponse response = new ExecutorResponse();
        response.setResult(STATUS_USER_ERROR);
        response.setErrorMessage(message);
        return response;
    }
}
